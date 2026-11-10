"""
ThreatLens Detection Engine
- Campaign-based multi-stage tracking (no hard timeout)
- Time-decay weighting for historical correlation
- Rule library covering the MITRE ATT&CK kill chain
- Multi-rule detection: ALL matching rules fire, not just the first
- Successful Login After Brute Force (the most dangerous authentication signal)
"""
from __future__ import annotations

import ipaddress
import math
import re
from datetime import datetime
from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from models.db_models import AttackCampaign, IPState


# ========================
#  Helpers
# ========================
def _rx(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE)


def _raw(parsed: Dict) -> str:
    return parsed.get("raw") or ""


# RFC 5737 documentation ranges model "external internet hosts" in examples and demos.
_DOC_NETS = tuple(ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))


def _is_public(ip: Optional[str]) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
        if any(addr in net for net in _DOC_NETS):
            return True
        return not (addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_multicast or addr.is_link_local)
    except ValueError:
        return False


def _failed(parsed: Dict) -> bool:
    return parsed.get("status") == "Failed" or parsed.get("event_id") == "4625"


RX_POWERSHELL = _rx(r"\bpowershell(?:\.exe)?\b|\bpwsh\b")
RX_PS_SUSPICIOUS = _rx(
    r"-e(?:nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{8,}|encodedcommand|invoke-expression|\biex\b|downloadstring|"
    r"frombase64string|-(?:exec|executionpolicy)\s+bypass|-w(?:indowstyle)?\s+hidden|net\.webclient|"
    r"invoke-webrequest|invoke-mimikatz|add-mppreference|set-mppreference"
)
RX_CRED_DUMP = _rx(r"\b(?:lsass|mimikatz|procdump|sekurlsa|hashdump|ntds\.dit|comsvcs(?:\.dll)?|secretsdump|lazagne)\b")
RX_LOG_CLEARED = _rx(r"(?:audit|event|security)\s+log\s+(?:was\s+)?cleared|wevtutil(?:\.exe)?\s+cl\b|clear-eventlog|remove-eventlog")
RX_LATERAL = _rx(r"\b(?:psexe(?:c|svc)\w*|wmic|winrm|smbexec|wmiexec|dcomexec|invoke-command\s+-computername)\b")
RX_EXFIL_TOOL = _rx(r"\b(?:curl|wget|ftp|sftp|scp|rsync|rclone|megacmd)\b")
RX_EXFIL_VERB = _rx(r"\b(?:upload|exfil\w*|transfer|send|post|put)\b")
RX_PERSISTENCE = _rx(
    r"\bschtasks?\b|\bcrontab\b|currentversion\\run|\brun\s?key\b|startup\s+folder|\bautorun\b|"
    r"new-service|\bsc(?:\.exe)?\s+create\b|systemctl\s+enable|\.bashrc|authorized_keys"
)
RX_RECON = _rx(r"\b(?:nmap|masscan|zmap|enum4linux|nbtscan|nikto|gobuster|dirbuster|port\s*scan)\b")
RX_PRIVESC = _rx(r"\b(?:sudo|runas|privilege\s+escalat\w*|elevation|uac\s+bypass|setuid|pkexec)\b")
RX_C2 = _rx(r"\b(?:beacon\w*|c2|cobalt\s?strike|reverse\s+shell|meterpreter|callback|sliver|empire\s+agent)\b")
RX_SQLI = _rx(r"(?:'|%27)\s*(?:or|and)\s*(?:'|%27)?\s*\d+\s*(?:'|%27)?\s*=\s*(?:'|%27)?\s*\d+|union(?:\s|\+|%20)+select|sleep\(\d+\)|xp_cmdshell|information_schema")
RX_TRAVERSAL = _rx(r"\.\./\.\./|%2e%2e%2f|/etc/passwd|\.env\b|wp-config\.php")
RX_WEBSHELL = _rx(r"\bweb\s?shell\b|\b(?:shell|cmd|c99|r57|b374k)\.(?:php|aspx?|jsp)\b")

SENSITIVE_PORTS = {"21", "22", "23", "135", "139", "445", "1433", "3306", "3389", "4444", "5432", "5900", "6379"}
EXFIL_BYTES_THRESHOLD = 100 * 1024 * 1024  # 100 MB


def _large_outbound_transfer(parsed: Dict) -> bool:
    size = parsed.get("bytes")
    try:
        size = int(size) if size is not None else 0
    except (TypeError, ValueError):
        size = 0
    return size >= EXFIL_BYTES_THRESHOLD and _is_public(parsed.get("dest_ip"))


# ========================
#  Time-Decay Scoring
# ========================
def _time_decay_weight(event_time: Optional[datetime]) -> float:
    """
    Weight between 0.1 and 1.0 based on how recent the event is:
    1 hour → 1.0 · 1 day → ~0.93 · 1 week → ~0.6 · 1 month → ~0.1 (floor)
    """
    if not event_time:
        return 0.1
    hours_ago = max((datetime.utcnow() - event_time).total_seconds() / 3600, 0)
    return max(0.1, min(1.0, math.exp(-0.003 * hours_ago)))


# ========================
#  IP State Management
# ========================
def _get_or_create_ip_state(db: Session, ip: str, now: datetime) -> IPState:
    record = db.query(IPState).filter(IPState.ip_address == ip).first()
    if not record:
        record = IPState(ip_address=ip, failed_logins=0, stages_detected=[], first_seen=now, last_seen=now, total_events=0)
        db.add(record)
        db.flush()
    return record


def _update_ip_state(db: Session, record: IPState, stages: List[str], failed: bool, now: datetime) -> None:
    if not record.last_seen or now > record.last_seen:
        record.last_seen = now
    if record.first_seen and now < record.first_seen:
        record.first_seen = now
    record.total_events = (record.total_events or 0) + 1
    if failed:
        record.failed_logins = (record.failed_logins or 0) + 1

    current = list(record.stages_detected or [])
    new_stages = [s for s in stages if s and s not in current]
    if new_stages:
        record.stages_detected = current + new_stages
    db.flush()


# ========================
#  Campaign Management
# ========================
def _find_or_create_campaign(
    db: Session, ip: str, stages: List[str], user: Optional[str], mitre_ids: List[str], log_id: Optional[int] = None,
    now: Optional[datetime] = None,
) -> AttackCampaign:
    """Find an Active/Dormant campaign involving this IP, or create one. Campaigns never time out."""
    now = now or datetime.utcnow()
    campaigns = (
        db.query(AttackCampaign)
        .filter(AttackCampaign.status.in_(["Active", "Dormant"]))
        .order_by(AttackCampaign.last_seen.desc())
        .all()
    )
    for camp in campaigns:
        if ip not in (camp.source_ips or []):
            continue
        if camp.status == "Dormant":
            camp.status = "Active"
        camp.last_seen = max(camp.last_seen or now, now)
        camp.stages_progression = list(camp.stages_progression or []) + [
            {"stage": stage, "timestamp": now.isoformat(), "ip": ip, "log_id": log_id} for stage in stages
        ][-200:]
        users = list(camp.target_users or [])
        if user and user not in users:
            camp.target_users = users + [user]
        techniques = list(camp.mitre_techniques or [])
        additions = [m for m in mitre_ids if m and m not in techniques]
        if additions:
            camp.mitre_techniques = techniques + additions
        db.flush()
        return camp

    campaign = AttackCampaign(
        name=f"Campaign {ip} · {now.strftime('%Y-%m-%d')}",
        first_seen=now,
        last_seen=now,
        status="Active",
        source_ips=[ip],
        stages_progression=[{"stage": s, "timestamp": now.isoformat(), "ip": ip, "log_id": log_id} for s in stages],
        risk_score=0,
        risk_level="LOW",
        target_users=[user] if user else [],
        mitre_techniques=[m for m in mitre_ids if m],
    )
    db.add(campaign)
    db.flush()
    return campaign


# ========================
#  Detection Rules
# ========================
DETECTION_RULES = [
    {
        "name": "Successful Login After Brute Force",
        "check": lambda p, s: p.get("status") == "Success" and s is not None and (s.failed_logins or 0) >= 3,
        "impact": 25, "confidence": 0.95, "mitre": "T1110", "stage": "Initial Access", "severity_override": "CRITICAL",
    },
    {
        "name": "Brute Force Attack",
        "check": lambda p, s: _failed(p) and s is not None and (s.failed_logins or 0) >= 2,
        "impact": 15, "confidence": 0.85, "mitre": "T1110", "stage": "Initial Access",
    },
    {
        "name": "Suspicious PowerShell Execution",
        "check": lambda p, s: bool(RX_POWERSHELL.search(_raw(p))) and (
            bool(RX_PS_SUSPICIOUS.search(_raw(p))) or p.get("event_id") == "4104"
        ),
        "impact": 15, "confidence": 0.8, "mitre": "T1059", "stage": "Execution",
    },
    {
        "name": "Credential Dumping Attempt",
        "check": lambda p, s: bool(RX_CRED_DUMP.search(_raw(p))),
        "impact": 25, "confidence": 0.90, "mitre": "T1003", "stage": "Credential Access",
    },
    {
        "name": "Event Log Cleared",
        "check": lambda p, s: p.get("event_id") in ("1102", "104") or bool(RX_LOG_CLEARED.search(_raw(p))),
        "impact": 25, "confidence": 0.95, "mitre": "T1070", "stage": "Defense Evasion",
    },
    {
        "name": "Lateral Movement Detected",
        "check": lambda p, s: bool(RX_LATERAL.search(_raw(p))),
        "impact": 20, "confidence": 0.80, "mitre": "T1021", "stage": "Lateral Movement",
    },
    {
        "name": "Data Exfiltration Attempt",
        "check": lambda p, s: (
            bool(RX_EXFIL_TOOL.search(_raw(p))) and bool(RX_EXFIL_VERB.search(_raw(p)))
        ) or _large_outbound_transfer(p),
        "impact": 25, "confidence": 0.75, "mitre": "T1041", "stage": "Exfiltration",
    },
    {
        "name": "Persistence Mechanism Detected",
        "check": lambda p, s: bool(RX_PERSISTENCE.search(_raw(p))),
        "impact": 15, "confidence": 0.75, "mitre": "T1053", "stage": "Persistence",
    },
    {
        "name": "Reconnaissance Activity",
        "check": lambda p, s: bool(RX_RECON.search(_raw(p))),
        "impact": 5, "confidence": 0.65, "mitre": "T1046", "stage": "Reconnaissance",
    },
    {
        "name": "Privilege Escalation Attempt",
        "check": lambda p, s: bool(RX_PRIVESC.search(_raw(p))) and p.get("status") in ("Failed", "DENIED"),
        "impact": 15, "confidence": 0.70, "mitre": "T1068", "stage": "Privilege Escalation",
    },
    {
        "name": "Command and Control Communication",
        "check": lambda p, s: bool(RX_C2.search(_raw(p))),
        "impact": 25, "confidence": 0.90, "mitre": "T1071", "stage": "Command and Control",
    },
    {
        "name": "SQL Injection Attempt",
        "check": lambda p, s: bool(RX_SQLI.search(_raw(p))),
        "impact": 20, "confidence": 0.80, "mitre": "T1190", "stage": "Initial Access",
    },
    {
        "name": "Web Path Traversal / Sensitive File Probe",
        "check": lambda p, s: bool(RX_TRAVERSAL.search(_raw(p))),
        "impact": 5, "confidence": 0.65, "mitre": "T1595", "stage": "Reconnaissance",
    },
    {
        "name": "Web Shell Upload Attempt",
        "check": lambda p, s: bool(RX_WEBSHELL.search(_raw(p))),
        "impact": 25, "confidence": 0.85, "mitre": "T1505", "stage": "Persistence",
    },
    {
        "name": "Suspicious Inbound Scanning",
        "check": lambda p, s: p.get("status") in ("BLOCKED", "REJECTED", "DENIED") and (
            str(p.get("port")) in SENSITIVE_PORTS or str(p.get("source_port")) in {"4444", "1337", "31337"}
        ),
        "impact": 5, "confidence": 0.60, "mitre": "T1046", "stage": "Reconnaissance",
    },
    {
        "name": "Blocked Connection From External Host",
        "check": lambda p, s: p.get("status") in ("BLOCKED", "REJECTED", "DENIED") and _is_public(p.get("source_ip")),
        "impact": 0, "confidence": 0.35, "mitre": "T1595", "stage": "Reconnaissance",
    },
]

# Multi-stage correlation chains
ATTACK_CHAINS = [
    ({"Initial Access", "Execution"}, "Brute Force -> Code Execution"),
    ({"Execution", "Credential Access"}, "Execution -> Credential Theft"),
    ({"Initial Access", "Lateral Movement"}, "Breach -> Lateral Movement"),
    ({"Credential Access", "Lateral Movement"}, "Credential Theft -> Lateral Spread"),
    ({"Lateral Movement", "Exfiltration"}, "Lateral Movement -> Data Theft"),
    ({"Execution", "Defense Evasion"}, "Execution -> Evidence Tampering"),
    ({"Initial Access", "Persistence"}, "Breach -> Persistence Established"),
    ({"Reconnaissance", "Initial Access"}, "Recon -> Exploitation"),
    ({"Privilege Escalation", "Credential Access"}, "PrivEsc -> Credential Dump"),
    ({"Initial Access", "Execution", "Credential Access"}, "Full Kill Chain: Access -> Exec -> Creds"),
    ({"Initial Access", "Credential Access", "Lateral Movement"}, "Breach -> Credential Theft -> Lateral Spread"),
    ({"Initial Access", "Execution", "Lateral Movement", "Exfiltration"}, "Complete APT Chain Detected"),
    ({"Command and Control", "Exfiltration"}, "C2 Active -> Data Exfiltration"),
]


def evaluate_rules(parsed_log: Dict, ip_state: Optional[IPState] = None) -> List[Dict]:
    """Run every rule against a parsed log (pure function, used by tests)."""
    matched = []
    for rule in DETECTION_RULES:
        try:
            if rule["check"](parsed_log, ip_state):
                matched.append(rule)
        except Exception:
            continue
    # The specific "blocked external" rule only adds value when nothing richer fired.
    if len(matched) > 1:
        matched = [r for r in matched if r["name"] != "Blocked Connection From External Host"]
    return matched


# ========================
#  Main Detection Function
# ========================
def detect_threat(parsed_log: Dict, db: Session | None = None, log_id: Optional[int] = None,
                  event_time: Optional[datetime] = None) -> Dict:
    now = event_time or datetime.utcnow()
    ip = parsed_log.get("source_ip")
    user = parsed_log.get("user")
    is_failed = _failed(parsed_log)

    ip_state = _get_or_create_ip_state(db, ip, now) if ip and db is not None else None
    matched_rules = evaluate_rules(parsed_log, ip_state)

    primary = max(matched_rules, key=lambda r: r["confidence"]) if matched_rules else None
    threat_type = primary["name"] if primary else None
    confidence = primary["confidence"] if primary else 0
    mitre_candidate = primary["mitre"] if primary else None
    severity_override = primary.get("severity_override") if primary else None

    all_matched_stages = sorted({r["stage"] for r in matched_rules})
    all_matched_mitres = sorted({r["mitre"] for r in matched_rules})
    all_matched_threats = [r["name"] for r in matched_rules]

    if ip_state is not None and db is not None:
        _update_ip_state(db, ip_state, all_matched_stages, is_failed, now)

    decay_weight = _time_decay_weight(ip_state.first_seen) if ip_state is not None and ip_state.first_seen else 1.0

    campaign_info = None
    multi_stage_warning = None
    if ip and all_matched_stages and db is not None:
        campaign = _find_or_create_campaign(db, ip, all_matched_stages, user, all_matched_mitres, log_id, now)
        campaign_stages = {entry.get("stage") for entry in (campaign.stages_progression or []) if entry.get("stage")}

        best_chain, best_len = None, 0
        for required, message in ATTACK_CHAINS:
            if required.issubset(campaign_stages) and len(required) > best_len:
                best_chain, best_len = message, len(required)
        if best_chain:
            multi_stage_warning = best_chain
            confidence = min(confidence + 0.10 * best_len, 1.0)

        campaign.risk_score = max(campaign.risk_score or 0, round(confidence * 100 * decay_weight, 1))
        campaign.risk_level = (
            "CRITICAL" if campaign.risk_score >= 80
            else "HIGH" if campaign.risk_score >= 60
            else "MEDIUM" if campaign.risk_score >= 30
            else "LOW"
        )
        db.flush()

        campaign_info = {
            "campaign_id": campaign.id,
            "campaign_name": campaign.name,
            "stages_in_campaign": sorted(campaign_stages),
            "campaign_duration_hours": round(abs((campaign.last_seen - campaign.first_seen).total_seconds()) / 3600, 1),
            "campaign_risk": campaign.risk_level,
        }

    return {
        "threat_detected": threat_type,
        "all_threats_detected": all_matched_threats,
        "confidence": round(confidence, 2),
        "mitre_candidate": mitre_candidate,
        "all_mitre_techniques": all_matched_mitres,
        "current_stage": primary["stage"] if primary else None,
        "all_stages_this_log": all_matched_stages,
        "multi_stage_correlation": multi_stage_warning,
        "attack_stages_observed": list(ip_state.stages_detected or []) if ip_state is not None else [],
        "failed_attempts_from_ip": (ip_state.failed_logins or 0) if ip_state is not None else 0,
        "time_decay_weight": round(decay_weight, 2),
        "severity_override": severity_override,
        "impact": max((r.get("impact", 10) for r in matched_rules), default=0),
        "campaign": campaign_info,
    }
