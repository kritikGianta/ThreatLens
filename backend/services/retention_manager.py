"""
Data retention — keeps tables within configured bounds by pruning the oldest rows.
Limits are tunable from the Settings page (stored in app_config).
"""
from __future__ import annotations

import logging

from sqlalchemy import func
from sqlalchemy.orm import Session

from config import settings
from models.db_models import AuditLog, ChatMessage, Incident, LogEntry
from services.app_settings import get_app_settings

logger = logging.getLogger("threatlens.retention")

MAX_AUDIT_LOGS = 50_000


def enforce_retention_policies(db: Session) -> dict:
    retention = get_app_settings().get("retention", {})
    try:
        result = {
            "logs": _prune(db, LogEntry, retention.get("max_logs", settings.MAX_LOG_ENTRIES)),
            "incidents": _prune(db, Incident, retention.get("max_incidents", settings.MAX_INCIDENTS)),
            "chats": _prune(db, ChatMessage, retention.get("max_chats", settings.MAX_CHAT_MESSAGES)),
            "audit_logs": _prune(db, AuditLog, MAX_AUDIT_LOGS),
        }
        db.commit()
        if any(result.values()):
            logger.info("Retention pruned old records: %s", result)
        return result
    except Exception as exc:
        db.rollback()
        logger.error("Retention sweep failed: %s", exc)
        return {"error": str(exc)}


def _prune(db: Session, model, max_count: int) -> int:
    """Delete the oldest rows (by id) beyond max_count."""
    count = db.query(func.count(model.id)).scalar() or 0
    if count <= max_count:
        return 0
    oldest_kept = db.query(model.id).order_by(model.id.desc()).offset(max_count - 1).limit(1).scalar()
    if oldest_kept is None:
        return 0
    return db.query(model).filter(model.id < oldest_kept).delete(synchronize_session=False)
