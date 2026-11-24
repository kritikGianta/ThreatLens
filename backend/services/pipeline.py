"""
The ThreatLens analysis pipeline — the single code path used by every ingestion
channel (interactive analysis, bulk jobs, webhooks, the Windows collector and the
demo seeder):

  parse → detect → blocklist → IOC cross-reference → (enrichment) → risk
        → (SOC summary) → persist log → incident create/update → SOAR rules
"""
from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from core import telemetry
from core.events import queue_event
from models.db_models import Blocklist, LogEntry
from services.alert_service import evaluate_alert_rules
from services.cve_service import search_cves
from services.detector import detect_threat
from services.incident_ops import create_or_update_incident
from services.ip_intel_service import enrich_ip
from services.llm_service import generate_soc_summary
from services.mitre_service import get_technique_by_id
from services.parser import parse_log
from services.rag_service import check_ioc_match, retrieve_threat_intel
from services.risk_engine import calculate_risk
from services.source_health import record_source_health

logger = logging.getLogger("threatlens.pipeline")

# Network enrichment (NVD, ip-api, VirusTotal) runs concurrently.
_enrichment_pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="enrich")


def _apply_ioc_detection(detection: Dict, ioc_matches: list) -> None:
    """A known-bad indicator is itself a detection, even if no rule fired."""
    if not ioc_matches or detection.get("threat_detected"):
        return
    first = ioc_matches[0]
    is_c2 = first.get("source") in ("FEODO_TRACKER", "THREATFOX")
    detection.update({
        "threat_detected": f"Known Malicious Indicator ({first.get('source')})",
        "all_threats_detected": [f"Known Malicious Indicator ({first.get('source')})"],
        "confidence": 0.85,
        "mitre_candidate": "T1071" if is_c2 else "T1595",
        "all_mitre_techniques": ["T1071" if is_c2 else "T1595"],
        "current_stage": "Command and Control" if is_c2 else "Reconnaissance",
    })


def _apply_overrides(risk: Dict, detection: Dict, blocklist_hit: bool, ioc_matches: list) -> None:
    if detection.get("severity_override"):
        risk["risk_level"] = detection["severity_override"]
        risk["risk_score"] = max(risk["risk_score"], 90)
        risk["risk_factors"].append(f"Severity override: {detection['severity_override']}")
    if blocklist_hit:
        risk["risk_level"] = "CRITICAL"
        risk["risk_score"] = max(risk["risk_score"], 95)
        risk["risk_factors"].append("Source IP is on the active blocklist")
    if ioc_matches and risk["risk_level"] not in ("CRITICAL", "HIGH"):
        risk["risk_level"] = "HIGH"
        risk["risk_score"] = max(risk["risk_score"], 75)
        risk["risk_factors"].append("Indicator matched threat-intelligence feed (minimum HIGH)")


def process_log(
    db: Session,
    raw_log: str,
    *,
    source: str,
    enrich: bool = False,
    event_time: Optional[datetime] = None,
    summary_extra: Optional[Dict[str, Any]] = None,
    asset_id: Optional[int] = None,
    detection_hook=None,
) -> Dict[str, Any]:
    """
    Run one raw log line through the full pipeline. The caller owns the transaction
    (this function only flushes). `enrich=True` adds MITRE/CVE/IP intel, RAG context
    and a SOC summary — used for interactive analysis.
    """
    started = time.perf_counter()
    parsed = parse_log(raw_log)
    source_ip = parsed.get("source_ip")

    detection = detect_threat(parsed, db=db, event_time=event_time)
    if detection_hook:
        detection_hook(parsed, detection)

    blocklist_hit = bool(source_ip and db.query(Blocklist.id).filter(Blocklist.ip_address == source_ip).first())
    ioc_matches = check_ioc_match(source_ip, db) if source_ip else []
    _apply_ioc_detection(detection, ioc_matches)

    mitre_details = cve_results = ip_intel = None
    threat_intel: list = []
    if enrich:
        mitre_details = get_technique_by_id(detection.get("mitre_candidate")) if detection.get("mitre_candidate") else None
        cve_future = _enrichment_pool.submit(search_cves, mitre_details["name"]) if mitre_details else None
        ip_future = _enrichment_pool.submit(enrich_ip, source_ip) if source_ip else None
        if detection.get("threat_detected"):
            threat_intel = retrieve_threat_intel(
                f"{detection['threat_detected']} {' '.join(detection.get('all_threats_detected') or [])}",
                db,
                top_k=3,
                indicators=[source_ip] if source_ip else [],
            )
        cve_results = cve_future.result() if cve_future else []
        ip_intel = ip_future.result() if ip_future else None

    risk = calculate_risk(
        detection, cve_results, ip_intel, db=db, source_ip=source_ip,
        threat_intel_matches=ioc_matches or threat_intel,
    )
    _apply_overrides(risk, detection, blocklist_hit, ioc_matches)

    soc_summary = None
    if enrich:
        soc_summary = generate_soc_summary(parsed, detection, mitre_details, cve_results, ip_intel, risk, threat_intel)

    log_entry = LogEntry(
        timestamp=event_time or datetime.utcnow(),
        source_ip=source_ip,
        event_id=parsed.get("event_id"),
        user=(parsed.get("user") or None) and str(parsed.get("user"))[:100],
        status=parsed.get("status"),
        log_type=parsed.get("log_type"),
        source=source,
        raw_log=raw_log,
    )
    db.add(log_entry)
    db.flush()
    record_source_health(db, source, event_timestamp=log_entry.timestamp, ingested=1)

    incident = None
    created = reopened = False
    soar_actions: list = []
    if detection.get("threat_detected"):
        campaign = detection.get("campaign")
        extra = {"blocklist_hit": blocklist_hit, "ioc_matches": len(ioc_matches)}
        if soc_summary:
            extra["llm_summary"] = soc_summary
        if summary_extra:
            extra.update(summary_extra)
        incident, created, reopened = create_or_update_incident(
            db,
            source=source,
            detection=detection,
            risk=risk,
            source_ip=source_ip,
            parsed=parsed,
            raw_log=raw_log,
            log_id=log_entry.id,
            event_timestamp=log_entry.timestamp,
            ioc_matches=ioc_matches,
            blocklist_hit=blocklist_hit,
            campaign_id=campaign.get("campaign_id") if campaign else None,
            asset_id=asset_id,
            summary_extra=extra,
        )
        if incident is not None and (created or getattr(incident, "_escalated", False)):
            soar_actions = evaluate_alert_rules(db, incident)
            record_source_health(db, source, event_timestamp=log_entry.timestamp, incidents_created=1)

    duration_ms = (time.perf_counter() - started) * 1000
    if not enrich:  # interactive enrichment waits on third-party APIs; measure the core pipeline only
        telemetry.record_processed(duration_ms)

    queue_event(db, "log", {
        "id": log_entry.id,
        "timestamp": log_entry.timestamp.isoformat(),
        "source": source,
        "source_ip": source_ip,
        "log_type": parsed.get("log_type"),
        "threat": detection.get("threat_detected"),
        "risk_level": risk["risk_level"] if detection.get("threat_detected") else None,
        "excerpt": raw_log[:160],
    })
    if incident is not None:
        queue_event(db, "incident", {
            "id": incident.id,
            "created": created,
            "reopened": reopened,
            "threat_type": incident.threat_type,
            "risk_level": incident.risk_level,
            "risk_score": incident.risk_score,
            "source_ip": incident.source_ip,
            "mitre_technique": incident.mitre_technique,
            "status": incident.status,
            "alert_count": incident.alert_count or 1,
            "campaign_id": incident.campaign_id,
            "multi_stage": detection.get("multi_stage_correlation"),
            "source": source,
        })

    return {
        "processing_ms": round(duration_ms, 1),
        "log_id": log_entry.id,
        "incident_id": incident.id if incident is not None else None,
        "parsed_log": parsed,
        "detection_result": detection,
        "blocklist_hit": blocklist_hit,
        "ioc_matches": ioc_matches,
        "mitre_details": mitre_details,
        "related_cves": cve_results,
        "ip_intelligence": ip_intel,
        "risk_assessment": risk,
        "threat_intelligence_rag": threat_intel,
        "soc_summary": soc_summary,
        "incident_created": created,
        "incident_deduplicated": incident is not None and not created,
        "incident_reopened": reopened,
        "soar_actions": soar_actions,
    }
