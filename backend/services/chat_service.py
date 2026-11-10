"""
ThreatLens AI SOC Copilot.

Answers analyst questions grounded in the live security database. Context is
gathered from the question (IPs, users, incidents, campaigns, blocklist, MITRE),
combined with the user's own conversation history, and sent to the Groq LLM.
Without an LLM key (or on failure) a deterministic briefing is produced from the
same context, so the Copilot is always useful.
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from core.llm import LLMUnavailable, chat_completion, llm_enabled
from models.db_models import AttackCampaign, Blocklist, ChatMessage, Incident, IPState, LogEntry, ThreatIntelEntry
from services.rag_service import check_ioc_match

logger = logging.getLogger("threatlens.copilot")

MAX_MEMORY_MESSAGES = 10
_IP_RX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_MITRE_RX = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

SYSTEM_PROMPT = """You are ThreatLens Copilot, a senior SOC analyst assistant.
Answer ONLY from the DATABASE CONTEXT below and the conversation history. If the
context does not contain the answer, say so and suggest which ThreatLens page or
query would find it. Be concise and actionable: lead with the answer, then use
short bullet points for evidence and recommended actions. Quote IPs, incident IDs
and MITRE technique IDs exactly as they appear.

=== DATABASE CONTEXT (generated {now} UTC) ===
{context}
=== END CONTEXT ==="""


def chat(user_message: str, db: Session, session_id: Optional[str] = None, user_id: Optional[int] = None) -> Dict:
    context = gather_context(user_message, db)
    history = _load_history(db, session_id, user_id)

    if not llm_enabled():
        return {"response": _fallback_answer(user_message, context), "context_used": context, "generated_by": "rule-engine"}

    messages = [{"role": "system", "content": SYSTEM_PROMPT.format(
        now=datetime.utcnow().strftime("%Y-%m-%d %H:%M"),
        context=json.dumps(context, indent=1, default=str)[:14000],
    )}]
    messages += history
    messages.append({"role": "user", "content": user_message})

    try:
        answer = chat_completion(messages, temperature=0.3, max_tokens=900)
        return {"response": answer, "context_used": context, "generated_by": "llm"}
    except LLMUnavailable as exc:
        logger.warning("Copilot LLM unavailable: %s", exc)
        note = f"_AI model unavailable ({exc}); showing a briefing generated directly from your data._\n\n"
        return {"response": note + _fallback_answer(user_message, context), "context_used": context, "generated_by": "rule-engine"}


def _load_history(db: Session, session_id: Optional[str], user_id: Optional[int]) -> List[Dict]:
    if not session_id:
        return []
    query = db.query(ChatMessage).filter(ChatMessage.session_id == session_id)
    if user_id is not None:
        query = query.filter(ChatMessage.user_id == user_id)
    recent = query.order_by(ChatMessage.timestamp.desc(), ChatMessage.id.desc()).limit(MAX_MEMORY_MESSAGES).all()
    return [{"role": m.role, "content": (m.content or "")[:800]} for m in reversed(recent) if m.role in ("user", "assistant")]


def _incident_row(i: Incident) -> Dict:
    return {
        "id": i.id, "threat": i.threat_type, "risk_level": i.risk_level, "risk_score": i.risk_score,
        "source_ip": i.source_ip, "status": i.status, "workflow_state": i.workflow_state, "owner": i.owner,
        "mitre": i.mitre_technique, "last_seen": i.last_seen.isoformat() if i.last_seen else None,
    }


def gather_context(question: str, db: Session) -> Dict:
    q = question.lower()
    since_24h = datetime.utcnow() - timedelta(hours=24)
    since_7d = datetime.utcnow() - timedelta(days=7)

    context: Dict = {
        "summary": {
            "total_incidents": db.query(func.count(Incident.id)).scalar() or 0,
            "open_incidents": db.query(func.count(Incident.id)).filter(Incident.status.in_(["Open", "Investigating"])).scalar() or 0,
            "critical_open": db.query(func.count(Incident.id)).filter(Incident.status.in_(["Open", "Investigating"]), Incident.risk_level == "CRITICAL").scalar() or 0,
            "incidents_last_24h": db.query(func.count(Incident.id)).filter(Incident.last_seen >= since_24h).scalar() or 0,
            "total_logs": db.query(func.count(LogEntry.id)).scalar() or 0,
            "active_campaigns": db.query(func.count(AttackCampaign.id)).filter(AttackCampaign.status == "Active").scalar() or 0,
            "blocked_ips": db.query(func.count(Blocklist.id)).scalar() or 0,
            "threat_intel_iocs": db.query(func.count(ThreatIntelEntry.id)).scalar() or 0,
        }
    }

    # Always give the model the highest-priority open work.
    context["top_open_incidents"] = [
        _incident_row(i)
        for i in db.query(Incident)
        .filter(Incident.status.in_(["Open", "Investigating"]))
        .order_by(desc(Incident.risk_score), desc(Incident.last_seen))
        .limit(8)
        .all()
    ]

    for ip in dict.fromkeys(_IP_RX.findall(question)):
        state = db.query(IPState).filter(IPState.ip_address == ip).first()
        incidents = db.query(Incident).filter(Incident.source_ip == ip).order_by(desc(Incident.last_seen)).limit(10).all()
        blocked = db.query(Blocklist).filter(Blocklist.ip_address == ip).first()
        context.setdefault("ip_investigations", []).append({
            "ip": ip,
            "failed_logins": state.failed_logins if state else 0,
            "attack_stages": state.stages_detected if state else [],
            "first_seen": state.first_seen.isoformat() if state and state.first_seen else None,
            "last_seen": state.last_seen.isoformat() if state and state.last_seen else None,
            "total_events": state.total_events if state else 0,
            "blocked": bool(blocked),
            "block_reason": blocked.reason if blocked else None,
            "threat_intel_matches": [m["title"] for m in check_ioc_match(ip, db)],
            "incidents": [_incident_row(i) for i in incidents],
        })

    for technique in dict.fromkeys(t.upper() for t in _MITRE_RX.findall(question)):
        rows = db.query(Incident).filter(Incident.mitre_technique == technique).order_by(desc(Incident.last_seen)).limit(10).all()
        context.setdefault("mitre_lookups", []).append({"technique": technique, "incidents": [_incident_row(i) for i in rows]})

    if any(k in q for k in ("critical", "high", "incident", "attack", "threat", "alert", "last 24", "today", "week", "brute", "happen")):
        rows = db.query(Incident).filter(Incident.last_seen >= since_7d).order_by(desc(Incident.last_seen)).limit(15).all()
        context["recent_incidents_7d"] = [_incident_row(i) for i in rows]

    if any(k in q for k in ("campaign", "multi-stage", "multi stage", "apt", "kill chain", "stage")):
        campaigns = (
            db.query(AttackCampaign).filter(AttackCampaign.status.in_(["Active", "Dormant"]))
            .order_by(desc(AttackCampaign.risk_score), desc(AttackCampaign.last_seen)).limit(8).all()
        )
        context["campaigns"] = [
            {
                "id": c.id, "name": c.name, "status": c.status, "risk_level": c.risk_level, "risk_score": c.risk_score,
                "stages": list(dict.fromkeys(s.get("stage") for s in (c.stages_progression or []))),
                "source_ips": c.source_ips, "target_users": c.target_users, "mitre": c.mitre_techniques,
                "first_seen": c.first_seen.isoformat() if c.first_seen else None,
                "last_seen": c.last_seen.isoformat() if c.last_seen else None,
            }
            for c in campaigns
        ]

    if any(k in q for k in ("user", "admin", "root", "account", "login", "credential")):
        rows = (
            db.query(LogEntry.user, LogEntry.status, func.count(LogEntry.id).label("count"))
            .filter(LogEntry.user.isnot(None), LogEntry.timestamp >= since_7d)
            .group_by(LogEntry.user, LogEntry.status).order_by(desc("count")).limit(15).all()
        )
        context["user_activity_7d"] = [{"user": u, "status": s, "count": c} for u, s, c in rows]

    if any(k in q for k in ("top", "most", "worst", "frequent", "common", "mitre", "technique", "type")):
        context["top_offending_ips"] = [
            {"ip": ip, "incidents": c}
            for ip, c in db.query(Incident.source_ip, func.count(Incident.id).label("c"))
            .filter(Incident.source_ip.isnot(None)).group_by(Incident.source_ip).order_by(desc("c")).limit(10).all()
        ]
        context["top_threat_types"] = [
            {"threat": t, "count": c}
            for t, c in db.query(Incident.threat_type, func.count(Incident.id).label("c"))
            .group_by(Incident.threat_type).order_by(desc("c")).limit(10).all()
        ]
        context["mitre_distribution"] = [
            {"technique": t, "count": c}
            for t, c in db.query(Incident.mitre_technique, func.count(Incident.id).label("c"))
            .filter(Incident.mitre_technique.isnot(None)).group_by(Incident.mitre_technique).order_by(desc("c")).limit(10).all()
        ]

    if any(k in q for k in ("block", "ban", "firewall", "deny")):
        context["blocklist"] = [
            {"ip": b.ip_address, "reason": b.reason, "auto_blocked": b.auto_blocked,
             "blocked_at": b.blocked_at.isoformat() if b.blocked_at else None}
            for b in db.query(Blocklist).order_by(desc(Blocklist.blocked_at)).limit(25).all()
        ]

    return context


def _fmt_incident(i: Dict) -> str:
    ip = f" from `{i['source_ip']}`" if i.get("source_ip") else ""
    return f"**#{i['id']} {i['threat']}**{ip} — {i['risk_level']} ({i['risk_score']}), {i['status']}"


def _fallback_answer(question: str, ctx: Dict) -> str:
    """Deterministic briefing assembled from the gathered context."""
    s = ctx["summary"]
    lines = [
        f"**Security posture:** {s['open_incidents']} open incidents ({s['critical_open']} critical), "
        f"{s['incidents_last_24h']} active in the last 24h, {s['active_campaigns']} active campaigns, "
        f"{s['blocked_ips']} blocked IPs, {s['threat_intel_iocs']} threat-intel IOCs."
    ]

    for inv in ctx.get("ip_investigations", []):
        lines.append(f"\n**IP `{inv['ip']}`:** {inv['total_events']} events, {inv['failed_logins']} failed logins, "
                     f"{len(inv['incidents'])} incidents{', BLOCKED' if inv['blocked'] else ''}.")
        if inv["attack_stages"]:
            lines.append(f"• Kill-chain stages observed: {', '.join(inv['attack_stages'])}")
        if inv["threat_intel_matches"]:
            lines.append(f"• Threat-intel matches: {'; '.join(inv['threat_intel_matches'][:3])}")
        lines += [f"• {_fmt_incident(i)}" for i in inv["incidents"][:5]]
        if not inv["incidents"] and not inv["total_events"]:
            lines.append("• No activity recorded for this IP.")

    for lookup in ctx.get("mitre_lookups", []):
        lines.append(f"\n**{lookup['technique']}:** {len(lookup['incidents'])} related incidents.")
        lines += [f"• {_fmt_incident(i)}" for i in lookup["incidents"][:5]]

    if ctx.get("campaigns"):
        lines.append("\n**Attack campaigns:**")
        for c in ctx["campaigns"][:5]:
            lines.append(f"• **{c['name']}** ({c['status']}, {c['risk_level']}) — stages: {' → '.join(c['stages']) or 'n/a'}")

    if ctx.get("blocklist") is not None:
        lines.append(f"\n**Blocklist ({len(ctx['blocklist'])} shown):**")
        lines += [f"• `{b['ip']}` — {b['reason']}{' (auto)' if b['auto_blocked'] else ''}" for b in ctx["blocklist"][:10]]

    if ctx.get("top_threat_types"):
        lines.append("\n**Top threat types:** " + ", ".join(f"{t['threat']} ({t['count']})" for t in ctx["top_threat_types"][:5]))
    if ctx.get("mitre_distribution"):
        lines.append("**Top MITRE techniques:** " + ", ".join(f"{t['technique']} ({t['count']})" for t in ctx["mitre_distribution"][:5]))
    if ctx.get("top_offending_ips"):
        lines.append("**Top offending IPs:** " + ", ".join(f"`{t['ip']}` ({t['incidents']})" for t in ctx["top_offending_ips"][:5]))

    if ctx.get("user_activity_7d"):
        failed = [u for u in ctx["user_activity_7d"] if u["status"] == "Failed"]
        if failed:
            lines.append("**Accounts with failed logins (7d):** " + ", ".join(f"{u['user']} ({u['count']})" for u in failed[:6]))

    if not any(k in ctx for k in ("ip_investigations", "mitre_lookups", "campaigns", "blocklist")) and ctx["top_open_incidents"]:
        lines.append("\n**Highest-priority open incidents:**")
        lines += [f"• {_fmt_incident(i)}" for i in ctx["top_open_incidents"][:6]]

    lines.append("\n_Set GROQ_API_KEY to enable conversational AI answers._")
    return "\n".join(lines)
