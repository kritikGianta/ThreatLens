"""
ThreatLens hybrid log parser.

Regex extractors normalise any raw log line into a fixed set of fields. When the
regex pass cannot find either a source IP or an event ID (an unstructured format),
the Groq LLM is used as a fallback parser — if it is configured.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Dict, Optional

from core.llm import LLMUnavailable, chat_completion, extract_json, llm_enabled
from config import settings

_IPV4 = r"(?:\d{1,3}\.){3}\d{1,3}"


def _valid_ip(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def extract_ip(text: str) -> Optional[str]:
    explicit_patterns = [
        rf"\b(?:src_ip|source_ip|srcip|src_addr|SourceIP|ClientIP|client_ip|SRC|src|source|client)\s*[:=]\s*\"?({_IPV4})",
        rf"Source Network Address\s*[:=]\s*({_IPV4})",
        rf"\bfrom\s+({_IPV4})",
    ]
    for pattern in explicit_patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match and _valid_ip(match.group(1)):
            return match.group(1)

    for candidate in re.findall(_IPV4, text):
        if _valid_ip(candidate):
            return candidate
    return None


def extract_dest_ip(text: str, source_ip: Optional[str] = None) -> Optional[str]:
    match = re.search(
        rf"\b(?:dst_ip|dest_ip|dstip|DstIP|DestIP|destination|DST|dst|to)\s*[:=\s]\s*({_IPV4})",
        text,
        re.IGNORECASE,
    )
    if match and _valid_ip(match.group(1)):
        return match.group(1)
    for candidate in re.findall(_IPV4, text):
        if candidate != source_ip and _valid_ip(candidate):
            return candidate
    return None


def extract_event_id(text: str) -> Optional[str]:
    patterns = [
        r"(?<![A-Za-z])(?:EventID|Event[_ ]ID|EventCode|event_id|ID)\s*[:=]\s*(\d{2,6})\b",
        r"WinEventLog:[A-Za-z ]+:\s*(\d{3,5})\b",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def extract_user(text: str) -> Optional[str]:
    patterns = [
        r"\b(?:user|username|user_name|account|TargetUserName)\s*[:=]\s*\"?([A-Za-z0-9_.\\$@-]+)",
        r"\bfor\s+(?:invalid\s+user\s+)?([A-Za-z0-9_.\\-]+)\s+from\b",
        r"Account Name\s*[:=]\s*([A-Za-z0-9_.\\$-]+)",
        r"\bby\s+([A-Za-z0-9_.\\-]+)\s*:",
        r"\bSubject:\s*([A-Za-z0-9_.\\-]+)",
        r"\bsudo:\s+([A-Za-z0-9_.-]+)\s*:",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            value = match.group(1).strip("\"'.,;")
            if value and value.lower() not in {"-", "n/a", "null", "none"}:
                return value
    return None


def extract_status(text: str) -> Optional[str]:
    low = text.lower()
    if re.search(r"\bfail(?:ed|ure|_login)?\b|invalid password|authentication failure|logon failure|\bfailed_login\b", low):
        return "Failed"
    if re.search(r"\bsuccess(?:ful|_login)?\b|accepted (?:password|publickey)|login succeeded|logged on|\bsuccess_login\b", low):
        return "Success"
    if "blocked" in low or "[drop]" in low or re.search(r"\bdrop\b", low):
        return "BLOCKED"
    if "rejected" in low:
        return "REJECTED"
    if re.search(r"\bden(?:y|ied)\b", low):
        return "DENIED"
    if re.search(r"\b(allow|allowed|permit|permitted)\b", low):
        return "ALLOWED"
    return None


# Ordered: vendor-specific patterns come before generic ones. Flags are per-pattern
# so vendor keywords like Palo Alto's ",THREAT," are matched case-sensitively.
LOG_TYPE_PATTERNS = [
    (re.compile(r"WinEventLog|EventID|event_id\s*=\s*\d{4}|EventCode|Microsoft-Windows|Security\sLog|Windows\sEvent|PowerShell|\[REAL_LOG\]", re.I), "windows"),
    (re.compile(r"%(?:ASA|FWSM|PIX)-\d|\bCisco\b", re.I), "cisco"),
    (re.compile(r",TRAFFIC,|,THREAT,|PAN-OS|\bpaloalto\b"), "palo_alto"),
    (re.compile(r"\bsnort\b|\bsuricata\b|\[\*\*\].*\[\d+:\d+:\d+\]|\bET\s(?:POLICY|TROJAN|MALWARE|SCAN)\b", re.I), "ids_ips"),
    (re.compile(r"\bsshd\[|pam_unix|\bsudo\b|systemd\[|cron\[|kernel:|auditd|auth\.log", re.I), "linux"),
    (re.compile(r"iptables|netfilter|pf\.log|\bufw\b|DENY\sIN=|ACCEPT\sIN=|\bfirewall\b", re.I), "firewall"),
    (re.compile(r"CloudTrail|userIdentity|eventSource\"?\s*:\s*\"?[a-z0-9.-]+\.amazonaws\.com", re.I), "aws_cloudtrail"),
    (re.compile(r"\bAzure(?:AD)?\b|SignInLogs|AuditLogs|microsoft\.aad", re.I), "azure"),
    (re.compile(r"\bgcloud\b|projects/[^/\s]+/logs|google\.cloud", re.I), "gcp"),
    (re.compile(r"\b(?:GET|POST|PUT|DELETE|HEAD|PATCH) /|HTTP/\d\.\d|\bnginx\b|\bapache\b|\bsquid\b", re.I), "web_server"),
    (re.compile(r"query\[|NXDOMAIN|\bdns\b|named\[|dnsmasq", re.I), "dns"),
    (re.compile(r"^<\d+>|\bsyslog\b|rsyslog", re.I), "syslog"),
]


def detect_log_type(text: str) -> str:
    """Classify the log into one of 12+ formats using priority-ordered patterns."""
    for pattern, log_type in LOG_TYPE_PATTERNS:
        if pattern.search(text):
            return log_type
    return "unknown"


def extract_process(text: str) -> Optional[str]:
    match = re.search(r"\b(?:Process|process_name|Image|NewProcessName)\s*[:=]\s*\"?([^\s,;\"]+)", text, re.IGNORECASE)
    if match:
        return match.group(1)
    created = re.search(r'Process created(?: by [^:]+)?:\s*"([^"]+)"', text, re.IGNORECASE)
    if created:
        return created.group(1).split()[0]
    exe = re.search(r"([\w-]+\.exe)\b", text, re.IGNORECASE)
    return exe.group(1) if exe else None


def extract_port(text: str) -> Optional[str]:
    match = re.search(r"\b(?:dst_port|dport|DstPort|DPT|dest_port|port)\s*[:=\s]\s*(\d{1,5})\b", text, re.IGNORECASE)
    if match:
        return match.group(1)
    # Cisco style: "to 192.168.1.1/80"
    match = re.search(rf"\bto\s+(?:\w+:)?{_IPV4}/(\d{{1,5}})\b", text, re.IGNORECASE)
    return match.group(1) if match else None


def extract_source_port(text: str) -> Optional[str]:
    match = re.search(r"\b(?:src_port|sport|SPT)\s*[:=]\s*(\d{1,5})\b", text, re.IGNORECASE)
    if match:
        return match.group(1)
    match = re.search(rf"\bfrom\s+(?:\w+:)?{_IPV4}/(\d{{1,5}})\b", text, re.IGNORECASE)
    return match.group(1) if match else None


def extract_hostname(text: str) -> Optional[str]:
    match = re.search(r"\b(?:Host|Hostname|Computer|Workstation|MachineName)\s*[:=]\s*([^\s,;]+)", text, re.IGNORECASE)
    return match.group(1) if match else None


def extract_bytes(text: str) -> Optional[int]:
    match = re.search(r"\b(?:bytes|bytes_out|sent_bytes|bytes_sent)\s*[:=]\s*(\d+)\b", text, re.IGNORECASE)
    return int(match.group(1)) if match else None


def _llm_parse(raw_log: str) -> Optional[dict]:
    if not llm_enabled():
        return None
    prompt = (
        "Extract fields from this raw security log. Respond with a JSON object with keys "
        "event_id, user, source_ip, dest_ip, status (Success|Failed|null), log_type, process, port, hostname. "
        "Use null for anything not present. Do not invent values.\n\nRaw log:\n" + raw_log[:2000]
    )
    try:
        raw = chat_completion(
            [{"role": "user", "content": prompt}],
            model=settings.GROQ_FAST_MODEL,
            temperature=0,
            max_tokens=250,
            timeout=8,
            json_mode=True,
        )
    except LLMUnavailable:
        return None
    return extract_json(raw)


def parse_log(raw_log: str) -> Dict:
    source_ip = extract_ip(raw_log)
    parsed = {
        "event_id": extract_event_id(raw_log),
        "user": extract_user(raw_log),
        "source_ip": source_ip,
        "dest_ip": extract_dest_ip(raw_log, source_ip),
        "status": extract_status(raw_log),
        "log_type": detect_log_type(raw_log),
        "process": extract_process(raw_log),
        "port": extract_port(raw_log),
        "source_port": extract_source_port(raw_log),
        "hostname": extract_hostname(raw_log),
        "bytes": extract_bytes(raw_log),
        "parser": "regex",
        "raw": raw_log,
    }

    # Unstructured format — let the LLM fill the gaps (never overrides regex results).
    if not parsed["source_ip"] and not parsed["event_id"]:
        llm_parsed = _llm_parse(raw_log)
        if llm_parsed:
            filled = False
            for key, value in llm_parsed.items():
                if key in parsed and value not in (None, "", "null") and not parsed.get(key):
                    if key in ("source_ip", "dest_ip") and not _valid_ip(str(value)):
                        continue
                    parsed[key] = str(value)
                    filled = True
            if filled:
                parsed["parser"] = "regex+llm"

    return parsed
