"""
SOC summary generation.

Uses the Groq LLM when GROQ_API_KEY is configured; otherwise (or on any LLM failure)
builds a deterministic, analyst-grade summary from the pipeline data so the UI always
has meaningful content.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from core.llm import LLMUnavailable, chat_completion, extract_json, llm_enabled

logger = logging.getLogger("threatlens.summary")

SUMMARY_KEYS = ("executive_summary", "technical_analysis", "business_impact", "recommended_actions")

_STAGE_IMPACT = {
    "Initial Access": "An external actor may have obtained a foothold in the environment.",
    "Execution": "Attacker-controlled code may be running on an endpoint.",
    "Credential Access": "Credentials may be compromised, enabling impersonation and privilege abuse.",
    "Lateral Movement": "The intrusion may be spreading to additional hosts.",
    "Exfiltration": "Sensitive data may be leaving the organisation.",
    "Persistence": "The attacker may have established a mechanism to survive reboots and remediation.",
    "Defense Evasion": "Evidence may have been destroyed, hindering investigation.",
    "Command and Control": "A compromised host may be under remote attacker control.",
    "Privilege Escalation": "An actor attempted to gain elevated privileges.",
    "Reconnaissance": "An actor is mapping the attack surface ahead of a potential intrusion.",
    "Impact": "Systems or data may be destroyed or encrypted — business operations are directly at risk.",
}


def _flatten(value: Any) -> str:
    if value is None:
        return "Not available."
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "\n".join(f"• {item}" for item in value)
    if isinstance(value, dict):
        return "\n".join(f"{str(k).replace('_', ' ').title()}: {v}" for k, v in value.items())
    return str(value)


def build_fallback_summary(
    parsed: Dict, detection: Dict, mitre: Optional[Dict], cves: Optional[List], ip_intel: Optional[Dict], risk: Dict,
    threat_intel: Optional[List] = None, reason: str = "rule-engine",
) -> Dict[str, str]:
    threat = detection.get("threat_detected")
    level = risk.get("risk_level", "LOW")
    score = risk.get("risk_score", 0)
    ip = parsed.get("source_ip") or "an unknown source"
    user = parsed.get("user")
    stage = detection.get("current_stage")

    if not threat:
        return {
            "executive_summary": f"No malicious behaviour was detected in this {parsed.get('log_type', 'unknown')} event from {ip}. Risk is {level} ({score}/100).",
            "technical_analysis": "The event was parsed and evaluated against every detection rule, the blocklist and threat-intel IOCs; none matched.",
            "business_impact": "No direct impact identified. The event is retained for correlation with future activity.",
            "recommended_actions": "• No action required.\n• Continue monitoring this source as part of normal operations.",
            "generated_by": reason,
        }

    threats = detection.get("all_threats_detected") or [threat]
    mitre_text = f"{mitre['id']} ({mitre['name']})" if mitre else (detection.get("mitre_candidate") or "no specific technique")
    technical = [
        f"Detection rules fired: {', '.join(threats)} (confidence {int((detection.get('confidence') or 0) * 100)}%).",
        f"MITRE ATT&CK mapping: {mitre_text}; kill-chain stage: {stage or 'n/a'}.",
    ]
    if detection.get("failed_attempts_from_ip"):
        technical.append(f"{detection['failed_attempts_from_ip']} failed authentication attempts have been recorded from {ip}.")
    if detection.get("multi_stage_correlation"):
        technical.append(f"Multi-stage correlation: {detection['multi_stage_correlation']}.")
    if cves:
        top = sorted(cves, key=lambda c: c.get("cvss_score") or 0, reverse=True)[0]
        technical.append(f"Related vulnerability {top.get('cve_id')} (CVSS {top.get('cvss_score') or 'n/a'}).")
    if ip_intel:
        geo = ip_intel.get("geo") or {}
        rep = ip_intel.get("reputation") or {}
        technical.append(
            f"Source geolocation: {geo.get('city', 'Unknown')}, {geo.get('country', 'Unknown')}; "
            f"VirusTotal malicious verdicts: {rep.get('malicious', 0)}."
        )
    if threat_intel:
        technical.append(f"Threat intelligence context: {threat_intel[0].get('title')}.")

    impact = _STAGE_IMPACT.get(stage or "", "Suspicious activity that warrants analyst review.")
    if level in ("CRITICAL", "HIGH"):
        impact += " Given the risk level, treat this as a priority incident."

    actions = [f"Investigate all recent activity from {ip} in the Investigation Hub."]
    if user:
        actions.append(f"Review the account '{user}' for unauthorised access; reset credentials if compromise is suspected.")
    if stage in ("Credential Access", "Lateral Movement", "Execution", "Persistence", "Command and Control"):
        actions.append("Isolate the affected endpoint and collect volatile forensic evidence.")
    if stage == "Exfiltration":
        actions.append("Block the destination at the egress proxy/firewall and assess what data was transferred.")
    if level in ("CRITICAL", "HIGH") and parsed.get("source_ip"):
        actions.append(f"Consider adding {ip} to the blocklist via the SOAR page.")
    actions.append("Document findings on the incident record and update its workflow state.")

    return {
        "executive_summary": f"{threat} detected from {ip}{f' targeting {user}' if user else ''}. Risk is {level} ({score}/100).",
        "technical_analysis": "\n".join(technical),
        "business_impact": impact,
        "recommended_actions": "\n".join(f"• {a}" for a in actions),
        "generated_by": reason,
    }


def generate_soc_summary(parsed, detection, mitre, cves, ip_intel, risk, threat_intel=None) -> Dict[str, str]:
    """Generate an analyst summary. Never raises."""
    if not llm_enabled():
        return build_fallback_summary(parsed, detection, mitre, cves, ip_intel, risk, threat_intel, reason="rule-engine")

    event = {
        "parsed_log": {k: v for k, v in parsed.items() if k != "raw"},
        "raw_log": (parsed.get("raw") or "")[:1500],
        "detection": {k: v for k, v in detection.items() if k != "campaign"},
        "campaign": detection.get("campaign"),
        "mitre": mitre,
        "cves": cves,
        "ip_intelligence": ip_intel,
        "risk": risk,
        "threat_intel_context": threat_intel or [],
    }
    prompt = (
        "Analyse the following security event. Only reference facts present in the data — do not invent "
        "products, IPs or vulnerabilities. Respond with a JSON object with exactly these string keys: "
        "executive_summary (1-2 sentences), technical_analysis, business_impact, recommended_actions "
        "(bullet points separated by newlines, each starting with '• ').\n\nEvent data:\n"
        + json.dumps(event, default=str)[:12000]
    )
    try:
        raw = chat_completion(
            [
                {"role": "system", "content": "You are a senior SOC analyst writing concise, factual incident summaries."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
            max_tokens=700,
            json_mode=True,
        )
        data = extract_json(raw) or {}
        if not any(data.get(k) for k in SUMMARY_KEYS):
            raise LLMUnavailable("LLM returned no summary fields")
        summary = {key: _flatten(data.get(key)) for key in SUMMARY_KEYS}
        summary["generated_by"] = "llm"
        return summary
    except LLMUnavailable as exc:
        logger.warning("SOC summary falling back to rule engine: %s", exc)
        return build_fallback_summary(parsed, detection, mitre, cves, ip_intel, risk, threat_intel, reason=f"rule-engine ({exc})")
