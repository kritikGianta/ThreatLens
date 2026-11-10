"""
SOAR automation (alert rules), blocklist management and threat-intelligence endpoints.
"""

import csv
import io
import ipaddress
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import desc, or_
from sqlalchemy.orm import Session

from dependencies.auth import require_writer
from models.database import get_db
from models.db_models import AlertRule, Blocklist, ThreatIntelEntry, User
from services.alert_service import ACTION_TYPES, CONDITION_TYPES
from services.audit import record_audit
from services.threat_intel_ingestion import get_intel_stats, ingest_all

router = APIRouter()

RISK_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


# ========================
#  Alert Rules
# ========================
class AlertRuleCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=255)
    description: str = Field(default="", max_length=2000)
    condition_type: str
    condition_value: str = Field(default="", max_length=255)
    action_type: str
    action_config: dict = Field(default_factory=dict)
    enabled: bool = True

    @field_validator("condition_type")
    @classmethod
    def valid_condition(cls, v):
        if v not in CONDITION_TYPES:
            raise ValueError(f"condition_type must be one of: {', '.join(CONDITION_TYPES)}")
        return v

    @field_validator("action_type")
    @classmethod
    def valid_action(cls, v):
        if v not in ACTION_TYPES:
            raise ValueError(f"action_type must be one of: {', '.join(ACTION_TYPES)}")
        return v

    @model_validator(mode="after")
    def check_consistency(self):
        if self.condition_type in ("risk_level", "risk_level_min"):
            self.condition_value = self.condition_value.upper()
            if self.condition_value not in RISK_LEVELS:
                raise ValueError(f"condition_value must be one of: {', '.join(RISK_LEVELS)}")
        elif self.condition_type == "threat_type" and not self.condition_value.strip():
            raise ValueError("condition_value (threat type substring) is required")
        if self.action_type in ("webhook", "slack"):
            url = self.action_config.get("webhook_url") or self.action_config.get("url") or ""
            if url and not url.startswith(("https://", "http://")):
                raise ValueError("webhook_url must be an http(s) URL")
        if self.action_type == "email":
            email = self.action_config.get("email") or self.action_config.get("to") or ""
            if email and "@" not in email:
                raise ValueError("action_config.email must be a valid email address")
        return self


def _serialize_rule(r: AlertRule) -> dict:
    config = dict(r.action_config or {})
    for secret in ("bearer_token", "smtp_password"):
        if config.get(secret):
            config[secret] = "••••••"
    return {
        "id": r.id, "name": r.name, "description": r.description,
        "condition_type": r.condition_type, "condition_value": r.condition_value,
        "action_type": r.action_type, "action_config": config, "enabled": r.enabled,
        "times_triggered": r.times_triggered or 0,
        "last_triggered": r.last_triggered.isoformat() if r.last_triggered else None,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }


def _rule_or_404(db: Session, rule_id: int) -> AlertRule:
    rule = db.get(AlertRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


@router.get("/rules")
def list_alert_rules(db: Session = Depends(get_db)):
    rules = db.query(AlertRule).order_by(AlertRule.id).all()
    return {
        "rules": [_serialize_rule(r) for r in rules],
        "condition_types": list(CONDITION_TYPES),
        "action_types": list(ACTION_TYPES),
    }


@router.post("/rules", status_code=201)
def create_alert_rule(request: Request, data: AlertRuleCreate, db: Session = Depends(get_db), user: User = Depends(require_writer)):
    rule = AlertRule(**data.model_dump())
    db.add(rule)
    db.flush()
    record_audit(db, "soar.rule_create", actor=user, target_type="alert_rule", target_id=rule.id,
                 details={"name": rule.name, "condition": f"{rule.condition_type}={rule.condition_value}", "action": rule.action_type},
                 request=request)
    db.commit()
    return {"message": f"Alert rule '{rule.name}' created", "id": rule.id, "rule": _serialize_rule(rule)}


@router.put("/rules/{rule_id}/toggle")
def toggle_alert_rule(request: Request, rule_id: int, db: Session = Depends(get_db), user: User = Depends(require_writer)):
    rule = _rule_or_404(db, rule_id)
    rule.enabled = not rule.enabled
    record_audit(db, "soar.rule_toggle", actor=user, target_type="alert_rule", target_id=rule.id,
                 details={"enabled": rule.enabled}, request=request)
    db.commit()
    return {"message": f"Rule '{rule.name}' {'enabled' if rule.enabled else 'disabled'}", "rule": _serialize_rule(rule)}


@router.delete("/rules/{rule_id}")
def delete_alert_rule(request: Request, rule_id: int, db: Session = Depends(get_db), user: User = Depends(require_writer)):
    rule = _rule_or_404(db, rule_id)
    name = rule.name
    db.delete(rule)
    record_audit(db, "soar.rule_delete", actor=user, target_type="alert_rule", target_id=rule_id, details={"name": name}, request=request)
    db.commit()
    return {"message": f"Rule '{name}' deleted"}


# ========================
#  Blocklist
# ========================
class BlockIPInput(BaseModel):
    ip_address: str
    reason: str = Field(default="Manually blocked by analyst", max_length=1000)

    @field_validator("ip_address")
    @classmethod
    def valid_ip(cls, v):
        try:
            return str(ipaddress.ip_address(v.strip()))
        except ValueError:
            raise ValueError("ip_address must be a valid IPv4 or IPv6 address")


def _serialize_block(b: Blocklist) -> dict:
    return {
        "id": b.id, "ip_address": b.ip_address, "reason": b.reason,
        "blocked_at": b.blocked_at.isoformat() if b.blocked_at else None,
        "auto_blocked": b.auto_blocked,
    }


@router.get("/blocklist")
def get_blocklist(db: Session = Depends(get_db)):
    blocked = db.query(Blocklist).order_by(desc(Blocklist.blocked_at)).all()
    return {"total": len(blocked), "blocked_ips": [_serialize_block(b) for b in blocked]}


@router.get("/blocklist/export", response_class=PlainTextResponse)
def export_blocklist(fmt: str = Query("txt", pattern="^(txt|csv)$"), db: Session = Depends(get_db)):
    """Firewall-ready export of the blocklist (plain text or CSV)."""
    rows = db.query(Blocklist).order_by(Blocklist.ip_address).all()
    if fmt == "txt":
        return "\n".join(b.ip_address for b in rows) + "\n"
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["ip_address", "reason", "blocked_at", "auto_blocked"])
    for b in rows:
        writer.writerow([b.ip_address, b.reason, b.blocked_at.isoformat() if b.blocked_at else "", b.auto_blocked])
    return buffer.getvalue()


@router.post("/blocklist", status_code=201)
def block_ip(request: Request, data: BlockIPInput, db: Session = Depends(get_db), user: User = Depends(require_writer)):
    if db.query(Blocklist).filter(Blocklist.ip_address == data.ip_address).first():
        raise HTTPException(status_code=409, detail=f"IP {data.ip_address} is already blocked")
    block = Blocklist(ip_address=data.ip_address, reason=data.reason, auto_blocked=False)
    db.add(block)
    db.flush()
    record_audit(db, "blocklist.add", actor=user, target_type="ip", target_id=data.ip_address, details={"reason": data.reason}, request=request)
    db.commit()
    return {"message": f"IP {data.ip_address} blocked", "id": block.id, "entry": _serialize_block(block)}


@router.delete("/blocklist/{block_id}")
def unblock_ip(request: Request, block_id: int, db: Session = Depends(get_db), user: User = Depends(require_writer)):
    block = db.get(Blocklist, block_id)
    if not block:
        raise HTTPException(status_code=404, detail="Blocklist entry not found")
    ip = block.ip_address
    db.delete(block)
    record_audit(db, "blocklist.remove", actor=user, target_type="ip", target_id=ip, request=request)
    db.commit()
    return {"message": f"IP {ip} unblocked"}


# ========================
#  Threat Intelligence
# ========================
@router.post("/intel/ingest")
def trigger_intel_ingestion(request: Request, db: Session = Depends(get_db), user: User = Depends(require_writer)):
    """Pull the latest indicators from every configured feed (takes 10-60s)."""
    results = ingest_all()
    record_audit(db, "intel.ingest", actor=user, details={k: v.get("status") for k, v in (results.get("feeds") or {}).items()},
                 request=request, commit=True)
    return {"message": "Ingestion complete", "results": results, "stats": get_intel_stats(db)}


@router.get("/intel/stats")
def intel_statistics(db: Session = Depends(get_db)):
    return get_intel_stats(db)


@router.get("/intel/iocs")
def get_intel_iocs(
    search: Optional[str] = Query(None, max_length=200),
    source: Optional[str] = Query(None),
    ioc_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    query = db.query(ThreatIntelEntry)
    if source:
        query = query.filter(ThreatIntelEntry.source == source)
    if ioc_type:
        query = query.filter(ThreatIntelEntry.ioc_type == ioc_type)
    if severity:
        query = query.filter(ThreatIntelEntry.severity == severity.upper())
    if search:
        term = f"%{search.strip()}%"
        query = query.filter(or_(ThreatIntelEntry.ioc_value.ilike(term), ThreatIntelEntry.title.ilike(term),
                                 ThreatIntelEntry.description.ilike(term)))
    total = query.count()
    rows = query.order_by(desc(ThreatIntelEntry.ingested_at), desc(ThreatIntelEntry.id)).offset(offset).limit(limit).all()
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "iocs": [
            {
                "id": i.id, "source": i.source, "threat_name": i.title, "description": i.description,
                "ioc_type": i.ioc_type, "ioc_value": i.ioc_value, "severity": i.severity, "tags": i.tags or [],
                "ingested_at": i.ingested_at.isoformat() if i.ingested_at else None,
            }
            for i in rows
        ],
    }
