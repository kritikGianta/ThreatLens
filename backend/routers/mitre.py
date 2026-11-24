"""MITRE ATT&CK knowledge-base endpoints."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from models.database import get_db
from models.db_models import Incident
from services.mitre_service import get_technique_by_id, list_tactics, search_techniques, technique_count

router = APIRouter()


@router.get("/technique/{technique_id}")
def get_technique(technique_id: str, db: Session = Depends(get_db)):
    """Look up a technique by ID (e.g. T1110 or T1110.004), with local detection statistics."""
    result = get_technique_by_id(technique_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Technique '{technique_id}' not found")
    tid = result["id"]
    incidents = db.query(Incident).filter(Incident.mitre_technique.like(f"{tid}%"))
    sub_techniques = [t for t in search_techniques(f"{tid}.", limit=50) if t["id"].startswith(f"{tid}.")]
    return {
        **result,
        "sub_techniques": sub_techniques,
        "observed_incidents": incidents.count(),
        "recent_incidents": [
            {"id": i.id, "threat_type": i.threat_type, "risk_level": i.risk_level, "source_ip": i.source_ip,
             "last_seen": i.last_seen.isoformat() if i.last_seen else None}
            for i in incidents.order_by(desc(Incident.last_seen)).limit(5).all()
        ],
    }


@router.get("/search")
def search_mitre(q: str = Query("", max_length=100), tactic: Optional[str] = Query(None), limit: int = Query(25, ge=1, le=100)):
    """Search techniques by ID, name or description; optionally filter by tactic."""
    results = search_techniques(q, limit=limit, tactic=tactic)
    return {"query": q, "results": results, "total": len(results)}


@router.get("/tactics")
def tactics():
    return {"tactics": list_tactics(), "technique_count": technique_count()}


@router.get("/coverage")
def coverage(db: Session = Depends(get_db)):
    """Techniques observed in this environment, mapped to tactics (for heatmaps)."""
    rows = (
        db.query(Incident.mitre_technique, func.count(Incident.id))
        .filter(Incident.mitre_technique.isnot(None))
        .group_by(Incident.mitre_technique)
        .all()
    )
    observed = []
    for tid, count in rows:
        tech = get_technique_by_id(tid)
        observed.append({
            "id": tid, "name": tech["name"] if tech else tid, "tactics": tech.get("tactics", []) if tech else [], "incidents": count,
        })
    return {"observed": sorted(observed, key=lambda t: -t["incidents"])}


@router.get("/matrix")
def coverage_matrix(db: Session = Depends(get_db)):
    """ATT&CK heatmap: techniques the rule set can detect, grouped by tactic, with observed incident counts."""
    from services.detector import DETECTION_RULES
    from services.mitre_service import list_tactics

    detectable: dict = {}
    for rule in DETECTION_RULES:
        detectable.setdefault(rule["mitre"], []).append(rule["name"])
    detectable.setdefault("T1110.004", []).append("Distributed Brute Force (correlation engine)")
    detectable.setdefault("T1110", []).append("Slow Brute Force (correlation engine)")

    observed = dict(
        db.query(Incident.mitre_technique, func.count(Incident.id))
        .filter(Incident.mitre_technique.isnot(None))
        .group_by(Incident.mitre_technique)
        .all()
    )
    technique_ids = set(detectable) | set(observed)
    columns: dict = {}
    for tid in sorted(technique_ids):
        tech = get_technique_by_id(tid)
        tactics = (tech or {}).get("tactics") or ["Unmapped"]
        for tactic in tactics:
            columns.setdefault(tactic, []).append({
                "id": tid,
                "name": tech["name"] if tech else tid,
                "detectable": tid in detectable,
                "rules": detectable.get(tid, []),
                "observed": observed.get(tid, 0),
            })
    order = [t["name"] for t in list_tactics()]
    matrix = [{"tactic": tactic, "techniques": columns[tactic]} for tactic in order if tactic in columns]
    matrix += [{"tactic": tactic, "techniques": techs} for tactic, techs in columns.items() if tactic not in order]
    return {
        "matrix": matrix,
        "detectable_techniques": len(detectable),
        "observed_techniques": len([t for t in observed if observed[t]]),
        "tactics_covered": len(matrix),
        "rules": len(DETECTION_RULES),
    }
