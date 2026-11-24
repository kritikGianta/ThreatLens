"""
ThreatLens Alert & SOAR Service v2.1
- Webhook notifications with auth headers (async via threading)
- Auto-block IPs
- Auto-escalate incidents
- Email notifications via SMTP (async via threading)
"""
import logging
import smtplib
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from sqlalchemy.orm import Session
from models.db_models import AlertRule, Blocklist, Incident
from config import settings
from core.events import queue_event
from core.http import http_client

CONDITION_TYPES = ("risk_level", "risk_level_min", "threat_type", "multi_stage")
ACTION_TYPES = ("webhook", "slack", "email", "block_ip", "escalate")

logger = logging.getLogger("threatlens.alerts")


def evaluate_alert_rules(db: Session, incident: Incident):
    rules = db.query(AlertRule).filter(AlertRule.enabled.is_(True)).all()
    already_fired = {a.get("rule") for a in (incident.soc_summary or {}).get("soar_actions") or []}
    triggered = []
    for rule in rules:
        if rule.name in already_fired:
            continue
        should_fire = False
        if rule.condition_type == "risk_level":
            should_fire = incident.risk_level == rule.condition_value
        elif rule.condition_type == "risk_level_min":
            order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
            should_fire = order.get(incident.risk_level, 0) >= order.get(rule.condition_value, 0)
        elif rule.condition_type == "threat_type":
            should_fire = incident.threat_type and rule.condition_value.lower() in incident.threat_type.lower()
        elif rule.condition_type == "multi_stage":
            soc = incident.soc_summary or {}
            should_fire = isinstance(soc, dict) and soc.get("multi_stage_correlation") is not None
        if should_fire:
            detail = _execute_action(db, rule, incident)
            rule.times_triggered = (rule.times_triggered or 0) + 1
            rule.last_triggered = datetime.utcnow()
            triggered.append({"rule": rule.name, "action": rule.action_type, "status": "success", "detail": detail})
    if triggered:
        summary = dict(incident.soc_summary or {})
        summary["soar_actions"] = (summary.get("soar_actions") or []) + triggered
        incident.soc_summary = summary
        incident.tags = sorted(set((incident.tags or []) + [f"soar:{t['action']}" for t in triggered]))
        db.flush()
        for action in triggered:
            queue_event(db, "soar", {"incident_id": incident.id, "threat_type": incident.threat_type,
                                     "source_ip": incident.source_ip, **action})
        logger.info(f"[Alerts] Triggered for incident #{incident.id}: {[t['rule'] for t in triggered]}")
    return triggered


def _execute_action(db, rule, incident) -> str:
    """Run the rule's action and return a short human-readable description."""
    config = rule.action_config or {}
    if rule.action_type in ("webhook", "slack"):
        if not (config.get("webhook_url") or config.get("url")):
            return "Skipped — no webhook URL configured"
        threading.Thread(target=_send_webhook, args=(config, incident), daemon=True).start()
        return "Webhook notification dispatched"
    if rule.action_type == "block_ip":
        return _auto_block_ip(db, incident)
    if rule.action_type == "escalate":
        incident.status = "Investigating"
        incident.workflow_state = "Investigate"
        return "Incident escalated to Investigating"
    if rule.action_type == "email":
        if not (config.get("email") or config.get("to")):
            return "Skipped — no recipient configured"
        threading.Thread(target=_send_email, args=(config, incident), daemon=True).start()
        return f"Email alert queued to {config.get('email') or config.get('to')}"
    return "Unknown action"


def _send_webhook(config, incident):
    url = config.get("webhook_url") or config.get("url")
    if not url:
        return
    payload = {
        "text": f"[ThreatLens] {incident.risk_level} - {incident.threat_type} | IP: {incident.source_ip or 'N/A'} | Score: {incident.risk_score} | #{incident.id}",
        "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": f"*ThreatLens Alert*\n*Threat:* {incident.threat_type}\n*Severity:* `{incident.risk_level}` ({incident.risk_score})\n*IP:* `{incident.source_ip or 'N/A'}`\n*MITRE:* {incident.mitre_technique or 'N/A'}"}}],
    }
    headers = {"Content-Type": "application/json"}
    auth = config.get("auth_headers", {})
    if isinstance(auth, dict):
        headers.update(auth)
    if config.get("bearer_token"):
        headers["Authorization"] = f"Bearer {config['bearer_token']}"
    try:
        resp = http_client.post(url, json=payload, headers=headers, timeout=10)
        logger.info(f"[Webhook] Sent to {url[:50]}... Status: {resp.status_code}")
    except Exception as e:
        logger.error(f"[Webhook] Failed: {e}")


def _send_email(config, incident):
    to_email = config.get("email") or config.get("to")
    if not to_email:
        logger.warning("[Email] No recipient configured")
        return
    host = config.get("smtp_host") or settings.SMTP_HOST
    port = config.get("smtp_port") or settings.SMTP_PORT
    user = config.get("smtp_user") or settings.SMTP_USER
    pwd = config.get("smtp_password") or settings.SMTP_PASSWORD
    sender = config.get("from_email") or settings.SMTP_FROM or user
    if not user or not pwd:
        logger.warning("[Email] SMTP credentials not configured")
        return
    color = "#ff4444" if incident.risk_level == "CRITICAL" else "#ff8c00" if incident.risk_level == "HIGH" else "#ffd700"
    body = f"""<html><body style="font-family:Arial;background:#1a1a2e;color:#e0e0e0;padding:20px;">
    <div style="max-width:600px;margin:0 auto;background:#16213e;border-radius:8px;padding:24px;border-left:4px solid {color};">
    <h2 style="color:#e94560;">ThreatLens Security Alert</h2>
    <p><b>Threat:</b> {incident.threat_type}</p>
    <p><b>Severity:</b> <span style="color:{color}">{incident.risk_level}</span> (Score: {incident.risk_score})</p>
    <p><b>Source IP:</b> {incident.source_ip or 'N/A'}</p>
    <p><b>MITRE:</b> {incident.mitre_technique or 'N/A'}</p>
    <p><b>Incident:</b> #{incident.id}</p>
    <hr style="border-color:#333;"><p style="color:#aaa;font-size:12px;">Auto-generated by ThreatLens SOAR</p>
    </div></body></html>"""
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[ThreatLens] {incident.risk_level}: {incident.threat_type}"
    msg["From"] = sender
    msg["To"] = to_email
    msg.attach(MIMEText(body, "html"))
    try:
        port = int(port)
        if port == 465:
            server_ctx = smtplib.SMTP_SSL(host, port, timeout=15)
        else:
            server_ctx = smtplib.SMTP(host, port, timeout=15)
        with server_ctx as server:
            server.ehlo()
            if port != 465:
                server.starttls()
                server.ehlo()
            server.login(user, pwd)
            server.sendmail(sender, [to_email], msg.as_string())
        logger.info(f"[Email] Sent to {to_email}")
    except Exception as e:
        logger.error(f"[Email] Failed: {e}")


def _auto_block_ip(db, incident) -> str:
    if not incident.source_ip:
        return "Skipped — incident has no source IP"
    if db.query(Blocklist).filter(Blocklist.ip_address == incident.source_ip).first():
        return f"{incident.source_ip} already on blocklist"
    db.add(Blocklist(ip_address=incident.source_ip, reason=f"Auto-blocked by SOAR: {incident.threat_type} (#{incident.id})", auto_blocked=True))
    db.flush()
    logger.info(f"[SOAR] Auto-blocked IP: {incident.source_ip}")
    return f"{incident.source_ip} added to blocklist"


def create_default_rules(db):
    if db.query(AlertRule).count() > 0:
        return
    defaults = [
        AlertRule(name="Critical Incident Alert", description="Escalate CRITICAL incidents", condition_type="risk_level", condition_value="CRITICAL", action_type="escalate", action_config={}, enabled=True),
        AlertRule(name="High Severity Webhook", description="Webhook for HIGH+", condition_type="risk_level_min", condition_value="HIGH", action_type="webhook", action_config={"webhook_url": ""}, enabled=False),
        AlertRule(name="Brute Force Auto-Block", description="Auto-block brute force IPs", condition_type="threat_type", condition_value="brute force", action_type="block_ip", action_config={}, enabled=True),
        AlertRule(name="Critical Email Alert", description="Email on CRITICAL (set SMTP in .env)", condition_type="risk_level", condition_value="CRITICAL", action_type="email", action_config={"email": ""}, enabled=False),
    ]
    for r in defaults:
        db.add(r)
    db.commit()
    logger.info("[Alerts] Default rules created")
