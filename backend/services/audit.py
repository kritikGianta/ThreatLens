"""Audit trail — records who did what, for compliance and incident forensics."""
from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import Request
from sqlalchemy.orm import Session

from models.db_models import AuditLog, User

logger = logging.getLogger("threatlens.audit")


def record_audit(
    db: Session,
    action: str,
    *,
    actor: Optional[User] = None,
    actor_name: Optional[str] = None,
    target_type: Optional[str] = None,
    target_id: Any = None,
    details: Optional[dict] = None,
    request: Optional[Request] = None,
    commit: bool = False,
) -> None:
    """Add an audit entry to the current transaction (never raises)."""
    try:
        entry = AuditLog(
            actor=(actor.username if actor else actor_name) or "system",
            actor_role=actor.role if actor else None,
            action=action,
            target_type=target_type,
            target_id=str(target_id) if target_id is not None else None,
            details=details or {},
            ip_address=request.client.host if request and request.client else None,
        )
        db.add(entry)
        if commit:
            db.commit()
    except Exception as exc:  # auditing must never break the primary action
        logger.warning("Failed to record audit event %s: %s", action, exc)


def serialize_audit(entry: AuditLog) -> dict:
    return {
        "id": entry.id,
        "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
        "actor": entry.actor,
        "actor_role": entry.actor_role,
        "action": entry.action,
        "target_type": entry.target_type,
        "target_id": entry.target_id,
        "details": entry.details or {},
        "ip_address": entry.ip_address,
    }
