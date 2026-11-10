"""
Log ingestion endpoints — parse-only, the webhook receiver for external forwarders,
and the local Windows Event Log collector controls.

The webhook accepts either an analyst JWT or the static `X-API-Key` header
(INGEST_API_KEY) so agents like Filebeat, Fluentd, Vector or rsyslog can forward logs.
"""

import logging
import re
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from core.rate_limit import limiter
from dependencies.auth import get_current_user, ingest_principal, require_writer
from models.database import get_db
from services.log_collector import get_collector_status, run_collection_cycle_now
from services.parser import parse_log
from services.pipeline import process_log
from services.source_health import mark_source_error, record_source_health

logger = logging.getLogger("threatlens.logs")

router = APIRouter()
public_router = APIRouter()  # mounted without the global JWT dependency

MAX_LOG_LEN = 10_000
_SOURCE_RX = re.compile(r"^[a-z0-9_.-]{1,64}$")


class LogInput(BaseModel):
    log: str = Field(..., min_length=1, max_length=MAX_LOG_LEN)


class WebhookPayload(BaseModel):
    logs: List[str] = Field(..., min_length=1, max_length=500)
    source: Optional[str] = Field(default="webhook", max_length=64)

    @field_validator("logs")
    @classmethod
    def truncate(cls, v):
        return [line[:MAX_LOG_LEN] for line in v if line and line.strip()]

    @field_validator("source")
    @classmethod
    def normalise_source(cls, v):
        v = (v or "webhook").strip().lower().replace(" ", "_")
        if not _SOURCE_RX.match(v):
            raise ValueError("source must match [a-z0-9_.-]{1,64}")
        return v


@router.post("/parse", dependencies=[Depends(get_current_user)])
def parse_log_endpoint(data: LogInput):
    """Parse a single log line without persisting or running detection."""
    return {"parsed_log": parse_log(data.log)}


@public_router.post("/webhook")
@limiter.limit("120/minute")
def webhook_receiver(
    request: Request,
    data: WebhookPayload,
    db: Session = Depends(get_db),
    principal: str = Depends(ingest_principal),
):
    """Synchronously process up to 500 forwarded log lines through the full pipeline."""
    processed = incidents_created = errors = 0
    for raw_log in data.logs:
        try:
            with db.begin_nested():
                result = process_log(db, raw_log, source=data.source, summary_extra={"ingest_mode": "webhook", "principal": principal})
            processed += 1
            incidents_created += 1 if result["incident_created"] else 0
        except Exception as exc:
            errors += 1
            mark_source_error(db, data.source, str(exc)[:500])
            record_source_health(db, data.source, parse_failures=1)
            logger.warning("Webhook: failed to process a log line: %s", exc)
    db.commit()
    return {
        "status": "accepted",
        "source": data.source,
        "logs_received": len(data.logs),
        "logs_processed": processed,
        "incidents_created": incidents_created,
        "errors": errors,
    }


@router.get("/collector/status", dependencies=[Depends(get_current_user)])
def collector_status():
    """Status of the local Windows Event Log collector."""
    return get_collector_status()


@router.post("/collector/run", dependencies=[Depends(require_writer)])
def collector_run_now():
    """Trigger a collector sweep immediately (Windows hosts only)."""
    try:
        return {"status": "completed", **run_collection_cycle_now()}
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
