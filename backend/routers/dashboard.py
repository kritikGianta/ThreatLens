"""
Dashboard, incident case management, investigation, campaigns, settings and audit endpoints.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import desc, func, or_
from sqlalchemy.orm import Session

from dependencies.auth import require_admin, require_writer
from models.database import get_db
from models.db_models import (
    AttackCampaign, AuditLog, Blocklist, ChatMessage, Incident, IPState, LogEntry, MonitoredAsset,
    SourceHealth, ThreatIntelEntry, User,
)
from services.app_settings import get_app_settings, update_app_settings
from services.audit import record_audit, serialize_audit
from services.incident_ops import run_incident_lifecycle_sweep
from services.log_collector import get_collector_status

router = APIRouter()

INCIDENT_STATUSES = ("Open", "Investigating", "Resolved", "Closed", "False Positive")
WORKFLOW_STATES = ("New", "Triage", "Investigate", "Contain", "Resolve")
ACTIVE_STATUSES = ("Open", "Investigating")


def _get_or_404(db: Session, model, object_id, label: str):
    obj = db.get(model, object_id)
    if obj is None:
        raise HTTPException(status_code=404, detail=f"{label} not found")
    return obj


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value else None


def _serialize_incident(incident: Incident) -> Dict[str, Any]:
    sla_remaining_minutes = None
    sla_breached = False
    if incident.sla_due_at:
        delta = incident.sla_due_at - datetime.utcnow()
        sla_remaining_minutes = int(delta.total_seconds() // 60)
        sla_breached = delta.total_seconds() < 0 and incident.status in ACTIVE_STATUSES

    summary = incident.soc_summary or {}
    return {
        "id": incident.id,
        "timestamp": _iso(incident.timestamp),
        "first_seen": _iso(incident.first_seen),
        "last_seen": _iso(incident.last_seen),
        "opened_at": _iso(incident.opened_at),
        "resolved_at": _iso(incident.resolved_at),
        "sla_due_at": _iso(incident.sla_due_at),
        "sla_remaining_minutes": sla_remaining_minutes,
        "sla_breached": sla_breached,
        "threat_type": incident.threat_type,
        "risk_level": incident.risk_level,
        "risk_score": incident.risk_score,
        "source_ip": incident.source_ip,
        "mitre_technique": incident.mitre_technique,
        "status": incident.status,
        "workflow_state": incident.workflow_state or "New",
        "campaign_id": incident.campaign_id,
        "source": incident.source or summary.get("source") or "other",
        "asset_id": incident.asset_id,
        "asset": {
            "id": incident.asset_id,
            "name": summary.get("asset_name"),
            "target": summary.get("asset_target"),
            "type": summary.get("asset_type"),
            "type_label": summary.get("asset_type_label"),
        } if incident.asset_id else None,
        "owner": incident.owner or "Unassigned",
        "alert_count": incident.alert_count or 1,
        "analyst_notes": incident.analyst_notes,
        "status_history": incident.status_history or [],
        "evidence": incident.evidence or [],
        "explanation": incident.explanation or {},
        "recommended_actions": incident.recommended_actions or [],
        "tags": incident.tags or [],
        "soc_summary": summary,
    }


def _build_query(
    db: Session,
    *,
    status: Optional[str] = None,
    workflow_state: Optional[str] = None,
    risk_level: Optional[str] = None,
    source: Optional[str] = None,
    owner: Optional[str] = None,
    mitre_technique: Optional[str] = None,
    search: Optional[str] = None,
    hours: Optional[int] = None,
):
    query = db.query(Incident)
    if status:
        query = query.filter(Incident.status == status)
    if workflow_state:
        query = query.filter(Incident.workflow_state == workflow_state)
    if risk_level:
        query = query.filter(Incident.risk_level == risk_level.upper())
    if source:
        query = query.filter(Incident.source == source)
    if owner:
        query = query.filter(Incident.owner == owner)
    if mitre_technique:
        query = query.filter(Incident.mitre_technique == mitre_technique.upper())
    if search:
        term = f"%{search.strip()}%"
        query = query.filter(or_(
            Incident.threat_type.ilike(term), Incident.source_ip.ilike(term),
            Incident.owner.ilike(term), Incident.mitre_technique.ilike(term),
        ))
    if hours:
        query = query.filter(Incident.last_seen >= datetime.utcnow() - timedelta(hours=hours))
    return query


# ========================
#  Dashboard statistics
# ========================
@router.get("/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    now = datetime.utcnow()
    since_24h = now - timedelta(hours=24)
    count = func.count(Incident.id)

    total_logs = db.query(func.count(LogEntry.id)).scalar() or 0
    total_incidents = db.query(count).scalar() or 0
    status_counts = dict(db.query(Incident.status, count).group_by(Incident.status).all())
    workflow_counts = dict(
        db.query(Incident.workflow_state, count).filter(Incident.status.in_(ACTIVE_STATUSES)).group_by(Incident.workflow_state).all()
    )
    severity = dict(db.query(Incident.risk_level, count).group_by(Incident.risk_level).all())
    open_severity = dict(
        db.query(Incident.risk_level, count).filter(Incident.status.in_(ACTIVE_STATUSES)).group_by(Incident.risk_level).all()
    )
    breached_slas = db.query(count).filter(
        Incident.sla_due_at.isnot(None), Incident.sla_due_at < now, Incident.status.in_(ACTIVE_STATUSES)
    ).scalar() or 0

    top_ips = (
        db.query(Incident.source_ip, count.label("c")).filter(Incident.source_ip.isnot(None))
        .group_by(Incident.source_ip).order_by(desc("c")).limit(5).all()
    )
    top_threats = (
        db.query(Incident.threat_type, count.label("c")).filter(Incident.threat_type.isnot(None))
        .group_by(Incident.threat_type).order_by(desc("c")).limit(5).all()
    )
    mitre_dist = (
        db.query(Incident.mitre_technique, count.label("c")).filter(Incident.mitre_technique.isnot(None))
        .group_by(Incident.mitre_technique).order_by(desc("c")).limit(10).all()
    )

    incident_sources = {(s or "other"): c for s, c in db.query(Incident.source, count).group_by(Incident.source).all()}
    log_sources = {
        (s or "other"): c for s, c in db.query(LogEntry.source, func.count(LogEntry.id)).group_by(LogEntry.source).all()
    }

    # Real activity series (by incident last-seen time), split by severity.
    levels = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    since_7d = now - timedelta(days=7)
    hourly: Dict[str, Dict[str, int]] = {}
    daily: Dict[str, Dict[str, int]] = {}
    for ts, level in db.query(Incident.last_seen, Incident.risk_level).filter(Incident.last_seen >= since_7d).all():
        if not ts:
            continue
        level = level if level in levels else "LOW"
        day_key = ts.date().isoformat()
        daily.setdefault(day_key, {}).setdefault(level, 0)
        daily[day_key][level] += 1
        if ts >= since_24h:
            hour_key = ts.replace(minute=0, second=0, microsecond=0).isoformat()
            hourly.setdefault(hour_key, {}).setdefault(level, 0)
            hourly[hour_key][level] += 1

    def _point(key: str, bucket: Dict[str, int], label_key: str) -> Dict[str, Any]:
        return {label_key: key, "incidents": sum(bucket.values()), **{lvl.lower(): bucket.get(lvl, 0) for lvl in levels}}

    now_hour = now.replace(minute=0, second=0, microsecond=0)
    activity_24h = [
        _point((now_hour - timedelta(hours=o)).isoformat(), hourly.get((now_hour - timedelta(hours=o)).isoformat(), {}), "hour")
        for o in range(23, -1, -1)
    ]
    activity_7d = [
        _point((now.date() - timedelta(days=o)).isoformat(), daily.get((now.date() - timedelta(days=o)).isoformat(), {}), "day")
        for o in range(6, -1, -1)
    ]

    return {
        "total_logs_ingested": total_logs,
        "total_incidents": total_incidents,
        "open_incidents": status_counts.get("Open", 0),
        "investigating_incidents": status_counts.get("Investigating", 0),
        "resolved_incidents": status_counts.get("Resolved", 0) + status_counts.get("Closed", 0),
        "status_breakdown": status_counts,
        "new_cases": workflow_counts.get("New", 0),
        "triage_cases": workflow_counts.get("Triage", 0),
        "workflow_breakdown": workflow_counts,
        "sla_breaches": breached_slas,
        "incidents_last_24h": db.query(count).filter(Incident.last_seen >= since_24h).scalar() or 0,
        "active_campaigns": db.query(func.count(AttackCampaign.id)).filter(AttackCampaign.status == "Active").scalar() or 0,
        "blocked_ips": db.query(func.count(Blocklist.id)).scalar() or 0,
        "unique_attackers": db.query(func.count(func.distinct(Incident.source_ip))).filter(Incident.source_ip.isnot(None)).scalar() or 0,
        "threat_intel_iocs": db.query(func.count(ThreatIntelEntry.id)).scalar() or 0,
        "monitored_assets": db.query(func.count(MonitoredAsset.id)).filter(MonitoredAsset.status == "Active").scalar() or 0,
        "severity_breakdown": {lvl: severity.get(lvl, 0) for lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
        "open_severity_breakdown": {lvl: open_severity.get(lvl, 0) for lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
        "top_source_ips": [{"ip": ip, "incident_count": c} for ip, c in top_ips],
        "top_threat_types": [{"threat": t, "count": c} for t, c in top_threats],
        "mitre_technique_distribution": [{"technique": t, "count": c} for t, c in mitre_dist],
        "incident_sources": incident_sources,
        "log_sources": log_sources,
        "activity_24h": activity_24h,
        "activity_7d": activity_7d,
        "generated_at": now.isoformat(),
    }


# ========================
#  Incidents (case management)
# ========================
@router.get("/incidents")
def list_incidents(
    status: Optional[str] = Query(None),
    workflow_state: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    owner: Optional[str] = Query(None),
    mitre_technique: Optional[str] = Query(None),
    search: Optional[str] = Query(None, max_length=200),
    hours: Optional[int] = Query(None, ge=1, le=8760),
    saved_view: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    if saved_view == "high_priority":
        query = _build_query(db, hours=72).filter(
            Incident.status.in_(ACTIVE_STATUSES), Incident.risk_level.in_(["CRITICAL", "HIGH"])
        )
    elif saved_view == "sla_watch":
        query = db.query(Incident).filter(
            Incident.status.in_(ACTIVE_STATUSES),
            Incident.sla_due_at.isnot(None),
            Incident.sla_due_at < datetime.utcnow() + timedelta(minutes=30),
        )
    elif saved_view == "unassigned":
        query = db.query(Incident).filter(Incident.status.in_(ACTIVE_STATUSES), Incident.owner == "Unassigned")
    elif saved_view == "real_telemetry":
        query = _build_query(db, source="real_windows_event_log", hours=72)
    else:
        query = _build_query(
            db, status=status, workflow_state=workflow_state, risk_level=risk_level, source=source,
            owner=owner, mitre_technique=mitre_technique, search=search, hours=hours,
        )

    total = query.count()
    incidents = query.order_by(desc(Incident.last_seen), desc(Incident.risk_score)).offset(offset).limit(limit).all()
    return {"total": total, "limit": limit, "offset": offset, "incidents": [_serialize_incident(i) for i in incidents]}


@router.get("/incidents/views")
def incident_saved_views():
    return {
        "views": [
            {"id": "high_priority", "label": "High Priority Queue", "description": "Open CRITICAL/HIGH cases from the last 72 hours."},
            {"id": "sla_watch", "label": "SLA Watch", "description": "Open cases that are nearing or breaching analyst SLA."},
            {"id": "unassigned", "label": "Unassigned", "description": "Open cases with no owner."},
            {"id": "real_telemetry", "label": "Real Telemetry", "description": "Cases generated from local Windows event log collection."},
        ]
    }


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: int, db: Session = Depends(get_db)):
    return _serialize_incident(_get_or_404(db, Incident, incident_id, "Incident"))


@router.get("/incidents/{incident_id}/detail")
def get_incident_detail(incident_id: int, db: Session = Depends(get_db)):
    incident = _get_or_404(db, Incident, incident_id, "Incident")

    log_ids = [e.get("log_id") for e in (incident.evidence or []) if e.get("log_id")]
    log_query = db.query(LogEntry)
    if incident.source_ip:
        log_query = log_query.filter(or_(LogEntry.source_ip == incident.source_ip, LogEntry.id.in_(log_ids or [-1])))
    elif log_ids:
        log_query = log_query.filter(LogEntry.id.in_(log_ids))
    else:
        log_query = log_query.filter(False)
    related_logs = log_query.order_by(desc(LogEntry.timestamp)).limit(25).all()

    related_incidents = []
    if incident.source_ip:
        related_incidents = (
            db.query(Incident)
            .filter(Incident.source_ip == incident.source_ip, Incident.id != incident.id)
            .order_by(desc(Incident.last_seen)).limit(10).all()
        )
    campaign = db.get(AttackCampaign, incident.campaign_id) if incident.campaign_id else None

    detail = _serialize_incident(incident)
    detail.update({
        "related_logs": [
            {
                "id": log.id, "timestamp": _iso(log.timestamp), "event_id": log.event_id, "user": log.user,
                "status": log.status, "log_type": log.log_type, "source": log.source,
                "source_ip": log.source_ip, "raw_log": (log.raw_log or "")[:500],
            }
            for log in related_logs
        ],
        "related_incidents": [_serialize_incident(item) for item in related_incidents],
        "campaign": {
            "id": campaign.id, "name": campaign.name, "status": campaign.status,
            "risk_level": campaign.risk_level, "risk_score": campaign.risk_score, "summary": campaign.summary,
            "stages": list(dict.fromkeys(stage.get("stage") for stage in (campaign.stages_progression or []))),
        } if campaign else None,
    })
    return detail


class IncidentUpdate(BaseModel):
    status: Optional[str] = None
    workflow_state: Optional[str] = None
    owner: Optional[str] = Field(default=None, max_length=100)
    analyst_notes: Optional[str] = Field(default=None, max_length=20000)

    @field_validator("status")
    @classmethod
    def valid_status(cls, v):
        if v is not None and v not in INCIDENT_STATUSES:
            raise ValueError(f"status must be one of: {', '.join(INCIDENT_STATUSES)}")
        return v

    @field_validator("workflow_state")
    @classmethod
    def valid_workflow(cls, v):
        if v is not None and v not in WORKFLOW_STATES:
            raise ValueError(f"workflow_state must be one of: {', '.join(WORKFLOW_STATES)}")
        return v


@router.put("/incidents/{incident_id}")
def update_incident(
    request: Request, incident_id: int, update: IncidentUpdate,
    db: Session = Depends(get_db), user: User = Depends(require_writer),
):
    incident = _get_or_404(db, Incident, incident_id, "Incident")
    before = {"status": incident.status, "workflow_state": incident.workflow_state, "owner": incident.owner}

    if update.status:
        incident.status = update.status
        if update.status in ("Resolved", "Closed", "False Positive"):
            incident.resolved_at = datetime.utcnow()
            if not update.workflow_state:
                incident.workflow_state = "Resolve"
        elif update.status == "Investigating" and not update.workflow_state:
            incident.workflow_state = "Investigate"
        elif update.status == "Open":
            incident.resolved_at = None
    if update.workflow_state:
        incident.workflow_state = update.workflow_state
    if update.owner is not None:
        incident.owner = update.owner.strip() or "Unassigned"
    if update.analyst_notes is not None:
        incident.analyst_notes = update.analyst_notes

    history = list(incident.status_history or [])
    history.append({
        "timestamp": datetime.utcnow().isoformat(),
        "workflow_state": incident.workflow_state,
        "status": incident.status,
        "owner": user.username,
        "note": "Case updated by analyst." + (" Notes edited." if update.analyst_notes is not None else ""),
    })
    incident.status_history = history[-50:]
    record_audit(
        db, "incident.update", actor=user, target_type="incident", target_id=incident.id, request=request,
        details={"before": before, "after": {"status": incident.status, "workflow_state": incident.workflow_state, "owner": incident.owner}},
    )
    db.commit()
    db.refresh(incident)
    return {"message": "Incident updated", "incident": _serialize_incident(incident)}


# ========================
#  Logs & investigation
# ========================
@router.get("/logs")
def list_logs(
    source_ip: Optional[str] = Query(None),
    log_type: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    query = db.query(LogEntry)
    if source_ip:
        query = query.filter(LogEntry.source_ip == source_ip)
    if log_type:
        query = query.filter(LogEntry.log_type == log_type)
    if source:
        query = query.filter(LogEntry.source == source)
    total = query.count()
    logs = query.order_by(desc(LogEntry.timestamp)).offset(offset).limit(limit).all()
    return {
        "total": total,
        "logs": [
            {
                "id": log.id, "timestamp": _iso(log.timestamp), "source_ip": log.source_ip, "event_id": log.event_id,
                "user": log.user, "status": log.status, "log_type": log.log_type, "source": log.source,
                "raw_log": (log.raw_log or "")[:300] or None,
            }
            for log in logs
        ],
    }


def _campaigns_for_ip(db: Session, ip: str, active_only: bool = True):
    query = db.query(AttackCampaign)
    if active_only:
        query = query.filter(AttackCampaign.status.in_(["Active", "Dormant"]))
    return [c for c in query.order_by(desc(AttackCampaign.last_seen)).all() if ip in (c.source_ips or [])]


@router.get("/investigate/{ip_address}")
def investigate_ip(ip_address: str, db: Session = Depends(get_db)):
    ip_state = db.query(IPState).filter(IPState.ip_address == ip_address).first()
    incident_q = db.query(Incident).filter(Incident.source_ip == ip_address)
    log_q = db.query(LogEntry).filter(LogEntry.source_ip == ip_address)
    related_incidents = incident_q.order_by(desc(Incident.last_seen)).limit(20).all()
    related_logs = log_q.order_by(desc(LogEntry.timestamp)).limit(10).all()
    blocked = db.query(Blocklist).filter(Blocklist.ip_address == ip_address).first()
    intel = db.query(ThreatIntelEntry).filter(ThreatIntelEntry.ioc_value == ip_address).limit(5).all()

    return {
        "ip_address": ip_address,
        "state": {
            "failed_logins": ip_state.failed_logins if ip_state else 0,
            "attack_stages": ip_state.stages_detected if ip_state else [],
            "first_seen": _iso(ip_state.first_seen) if ip_state else None,
            "last_seen": _iso(ip_state.last_seen) if ip_state else None,
            "total_events": ip_state.total_events if ip_state else 0,
        },
        "blocked": bool(blocked),
        "block_reason": blocked.reason if blocked else None,
        "threat_intel": [{"source": i.source, "title": i.title, "severity": i.severity} for i in intel],
        "campaigns": [
            {
                "id": c.id, "name": c.name, "status": c.status, "risk_level": c.risk_level,
                "stages": list(dict.fromkeys(stage.get("stage") for stage in (c.stages_progression or []))),
            }
            for c in _campaigns_for_ip(db, ip_address)
        ],
        "incident_count": incident_q.count(),
        "incidents": [_serialize_incident(i) for i in related_incidents],
        "log_count": log_q.count(),
        "recent_logs": [
            {"id": log.id, "timestamp": _iso(log.timestamp), "event_id": log.event_id, "status": log.status,
             "raw_log": (log.raw_log or "")[:200] or None}
            for log in related_logs
        ],
    }


@router.get("/timeline/{ip_address}")
def get_attack_timeline(ip_address: str, limit: int = Query(500, ge=1, le=2000), db: Session = Depends(get_db)):
    logs = db.query(LogEntry).filter(LogEntry.source_ip == ip_address).order_by(desc(LogEntry.timestamp)).limit(limit).all()
    incidents = db.query(Incident).filter(Incident.source_ip == ip_address).order_by(desc(Incident.first_seen)).limit(limit).all()
    timeline = [
        {
            "type": "log", "timestamp": _iso(log.timestamp), "event_id": log.event_id, "user": log.user,
            "status": log.status, "description": (log.raw_log or "Unknown event")[:160],
        }
        for log in logs
    ] + [
        {
            "type": "incident", "id": i.id, "timestamp": _iso(i.first_seen or i.timestamp), "threat_type": i.threat_type,
            "risk_level": i.risk_level, "mitre_technique": i.mitre_technique,
            "description": f"[{i.risk_level}] {i.threat_type}", "workflow_state": i.workflow_state,
        }
        for i in incidents
    ]
    timeline.sort(key=lambda item: item.get("timestamp") or "")

    campaign_info = None
    campaigns = _campaigns_for_ip(db, ip_address, active_only=False)
    if campaigns:
        c = campaigns[0]
        campaign_info = {
            "campaign_id": c.id, "campaign_name": c.name, "risk_level": c.risk_level,
            "stages_progression": list(dict.fromkeys(stage.get("stage") for stage in (c.stages_progression or []))),
            "duration_hours": round(abs((c.last_seen - c.first_seen).total_seconds()) / 3600, 1) if c.last_seen and c.first_seen else 0,
        }
    return {"ip_address": ip_address, "total_events": len(timeline), "campaign": campaign_info, "timeline": timeline}


# ========================
#  Campaigns
# ========================
def _serialize_campaign(c: AttackCampaign) -> Dict[str, Any]:
    return {
        "id": c.id, "name": c.name, "status": c.status, "risk_level": c.risk_level, "risk_score": c.risk_score,
        "source_ips": c.source_ips or [], "target_users": c.target_users or [], "mitre_techniques": c.mitre_techniques or [],
        "stages": list(dict.fromkeys(stage.get("stage") for stage in (c.stages_progression or []))),
        "event_count": len(c.stages_progression or []),
        "first_seen": _iso(c.first_seen), "last_seen": _iso(c.last_seen),
        "duration_hours": round(abs((c.last_seen - c.first_seen).total_seconds()) / 3600, 1) if c.last_seen and c.first_seen else 0,
    }


@router.get("/campaigns")
def list_campaigns(status: Optional[str] = Query(None), db: Session = Depends(get_db)):
    query = db.query(AttackCampaign)
    if status:
        query = query.filter(AttackCampaign.status == status)
    campaigns = query.order_by(desc(AttackCampaign.last_seen)).all()
    return {"total": len(campaigns), "campaigns": [_serialize_campaign(c) for c in campaigns]}


@router.get("/campaigns/{campaign_id}")
def get_campaign(campaign_id: int, db: Session = Depends(get_db)):
    campaign = _get_or_404(db, AttackCampaign, campaign_id, "Campaign")
    related = db.query(Incident).filter(Incident.campaign_id == campaign_id).order_by(Incident.first_seen).all()
    return {
        **_serialize_campaign(campaign),
        "stages_progression": campaign.stages_progression or [],
        "summary": campaign.summary,
        "incidents": [_serialize_incident(i) for i in related],
    }


@router.put("/campaigns/{campaign_id}/close")
def close_campaign(request: Request, campaign_id: int, db: Session = Depends(get_db), user: User = Depends(require_writer)):
    campaign = _get_or_404(db, AttackCampaign, campaign_id, "Campaign")
    campaign.status = "Closed"
    record_audit(db, "campaign.close", actor=user, target_type="campaign", target_id=campaign.id, request=request)
    db.commit()
    return {"message": f"Campaign '{campaign.name}' closed"}


# ========================
#  Operations: ingestion health, settings, maintenance, audit
# ========================
@router.get("/ingestion-health")
def get_ingestion_health(db: Session = Depends(get_db)):
    sources = db.query(SourceHealth).order_by(SourceHealth.source_key).all()
    return {
        "collector": get_collector_status(),
        "sources": [
            {
                "source_key": s.source_key, "display_name": s.display_name,
                "last_event_at": _iso(s.last_event_at), "last_success_at": _iso(s.last_success_at),
                "last_error_at": _iso(s.last_error_at), "last_error": s.last_error,
                "events_ingested": s.events_ingested or 0, "incidents_created": s.incidents_created or 0,
                "parse_failures": s.parse_failures or 0, "dropped_events": s.dropped_events or 0,
                "collector_interval_seconds": s.collector_interval_seconds, "last_lag_seconds": s.last_lag_seconds,
            }
            for s in sources
        ],
    }


@router.get("/settings")
def settings_view():
    return get_app_settings(force_reload=True)


class SettingsUpdate(BaseModel):
    demo_mode: Optional[bool] = None
    collector: Optional[dict] = None
    retention: Optional[dict] = None
    feeds: Optional[dict] = None
    detection: Optional[dict] = None


@router.put("/settings")
def settings_update(request: Request, payload: SettingsUpdate, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    changes = payload.model_dump(exclude_none=True)
    try:
        updated = update_app_settings(changes, updated_by=user.username, db=db)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    record_audit(db, "settings.update", actor=user, target_type="settings", details=changes, request=request)
    db.commit()
    return updated


@router.post("/lifecycle/sweep", dependencies=[Depends(require_writer)])
def lifecycle_sweep(db: Session = Depends(get_db)):
    return run_incident_lifecycle_sweep(db)


@router.post("/correlate", dependencies=[Depends(require_writer)])
def trigger_correlation():
    from services.correlation_engine import run_correlation_sweep

    findings = run_correlation_sweep()
    return {"findings": findings, "total": len(findings)}


@router.post("/reset")
def reset_dashboard(request: Request, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    """Admin only: wipe operational data and replay the demo scenario."""
    from services.log_seed import seed_demo_attacks

    try:
        db.query(Incident).delete(synchronize_session=False)
        db.query(LogEntry).delete(synchronize_session=False)
        db.query(AttackCampaign).delete(synchronize_session=False)
        db.query(IPState).delete(synchronize_session=False)
        db.query(SourceHealth).delete(synchronize_session=False)
        db.query(Blocklist).filter(Blocklist.auto_blocked.is_(True)).delete(synchronize_session=False)
        db.query(ChatMessage).delete(synchronize_session=False)
        record_audit(db, "platform.reset", actor=user, request=request)
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Reset failed: {exc}")
    seed = seed_demo_attacks(db, force=True)
    return {"message": "Operational data reset and demo scenario replayed.", "seed": seed}


@router.get("/audit-logs", dependencies=[Depends(require_admin)])
def list_audit_logs(
    action: Optional[str] = Query(None),
    actor: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    query = db.query(AuditLog)
    if action:
        query = query.filter(AuditLog.action.ilike(f"%{action}%"))
    if actor:
        query = query.filter(AuditLog.actor == actor)
    total = query.count()
    rows = query.order_by(desc(AuditLog.timestamp), desc(AuditLog.id)).offset(offset).limit(limit).all()
    return {"total": total, "entries": [serialize_audit(r) for r in rows]}
