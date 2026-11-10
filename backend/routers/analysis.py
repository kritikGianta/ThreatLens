"""
Threat analysis endpoints — interactive single-log analysis and asynchronous bulk ingestion.
"""

import logging
import threading
import uuid
from datetime import datetime
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from core.rate_limit import limiter
from dependencies.auth import require_writer
from models.database import SessionLocal, get_db
from models.db_models import IngestionJob, User
from services.pipeline import process_log
from services.source_health import mark_source_error, record_source_health

logger = logging.getLogger("threatlens.analysis")

router = APIRouter()

MAX_LOG_LEN = 10_000
BATCH_SIZE = 50


class LogInput(BaseModel):
    log: str = Field(..., min_length=1, max_length=MAX_LOG_LEN)


class BulkLogInput(BaseModel):
    logs: List[str] = Field(..., min_length=1, max_length=1000)

    @field_validator("logs")
    @classmethod
    def clean_lines(cls, v):
        cleaned = [line[:MAX_LOG_LEN] for line in v if line and line.strip()]
        if not cleaned:
            raise ValueError("At least one non-empty log line is required")
        return cleaned


# ========================
#  Single Log Analysis
# ========================
@router.post("/analyze")
@limiter.limit("30/minute")
def analyze_log(request: Request, data: LogInput, db: Session = Depends(get_db), user: User = Depends(require_writer)):
    """Run one log through the full pipeline with enrichment (MITRE, CVE, IP intel, RAG, AI summary)."""
    result = process_log(db, data.log.strip(), source="manual_analysis", enrich=True, summary_extra={"analysed_by": user.username})
    db.commit()
    return result


# ========================
#  Bulk Ingestion (async)
# ========================
def _process_bulk_logs(job_id: str, logs: List[str]) -> None:
    db = SessionLocal()
    try:
        job = db.get(IngestionJob, job_id)
        if not job:
            logger.error("Bulk job %s not found — aborting", job_id)
            return

        for start in range(0, len(logs), BATCH_SIZE):
            for raw_log in logs[start:start + BATCH_SIZE]:
                try:
                    with db.begin_nested():
                        result = process_log(db, raw_log, source="bulk_ingest", summary_extra={"job_id": job_id})
                    job.logs_processed = (job.logs_processed or 0) + 1
                    job.incidents_created = (job.incidents_created or 0) + (1 if result["incident_created"] else 0)
                    job.blocklist_hits = (job.blocklist_hits or 0) + (1 if result["blocklist_hit"] else 0)
                    job.ioc_hits = (job.ioc_hits or 0) + (1 if result["ioc_matches"] else 0)
                except Exception as exc:
                    job.errors = (job.errors or 0) + 1
                    job.error_detail = str(exc)[:500]
                    mark_source_error(db, "bulk_ingest", str(exc)[:500])
                    record_source_health(db, "bulk_ingest", parse_failures=1)
                    logger.warning("Bulk job %s: failed to process a log line: %s", job_id, exc)
            db.commit()  # persist each batch + job progress

        job.status = "completed"
        job.completed_at = datetime.utcnow()
        db.commit()
        logger.info("Bulk job %s completed: %s/%s logs", job_id, job.logs_processed, job.total_logs)
    except Exception as exc:
        logger.exception("Bulk job %s failed", job_id)
        db.rollback()
        job = db.get(IngestionJob, job_id)
        if job:
            job.status = "failed"
            job.error_detail = str(exc)[:500]
            job.completed_at = datetime.utcnow()
            db.commit()
    finally:
        db.close()


@router.post("/ingest", status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("10/minute")
def bulk_ingest(request: Request, data: BulkLogInput, db: Session = Depends(get_db), user: User = Depends(require_writer)):
    """Queue up to 1000 logs for background processing. Poll GET /ingest/status/{job_id}."""
    job_id = uuid.uuid4().hex[:12]
    db.add(IngestionJob(id=job_id, status="processing", total_logs=len(data.logs), logs_processed=0,
                        incidents_created=0, blocklist_hits=0, ioc_hits=0, errors=0))
    db.commit()
    threading.Thread(target=_process_bulk_logs, args=(job_id, data.logs), daemon=True, name=f"bulk-{job_id}").start()
    return {
        "status": "accepted",
        "job_id": job_id,
        "total_logs": len(data.logs),
        "status_url": f"/api/v1/analysis/ingest/status/{job_id}",
    }


@router.get("/ingest/status/{job_id}")
def get_ingestion_status(job_id: str, db: Session = Depends(get_db)):
    job = db.get(IngestionJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found")
    return {
        "job_id": job.id,
        "status": job.status,
        "total_logs": job.total_logs,
        "logs_processed": job.logs_processed,
        "incidents_created": job.incidents_created,
        "blocklist_hits": job.blocklist_hits,
        "ioc_hits": job.ioc_hits,
        "errors": job.errors,
        "error_detail": job.error_detail,
        "progress_pct": round(100 * (job.logs_processed or 0) / max(job.total_logs or 1, 1), 1),
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
    }
