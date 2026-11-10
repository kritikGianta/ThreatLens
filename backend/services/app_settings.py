"""
Runtime platform settings, stored in the database (table `app_config`) so they are
shared by every API replica and survive container rebuilds. Reads are served from a
short-lived in-memory cache because the detection pipeline consults them per log.
"""
from __future__ import annotations

import threading
import time
from copy import deepcopy
from typing import Optional

from config import settings
from models.database import SessionLocal
from models.db_models import AppConfig

DEFAULT_SETTINGS = {
    "demo_mode": settings.SEED_DEMO_DATA,
    "collector": {
        "enabled": settings.ENABLE_REAL_LOG_COLLECTOR,
        "interval_seconds": settings.REAL_LOG_COLLECTOR_INTERVAL_SECONDS,
        "max_events_per_sweep": settings.REAL_LOG_MAX_EVENTS_PER_SWEEP,
        "bootstrap_minutes": settings.REAL_LOG_BOOTSTRAP_MINUTES,
    },
    "retention": {
        "max_logs": settings.MAX_LOG_ENTRIES,
        "max_incidents": settings.MAX_INCIDENTS,
        "max_chats": settings.MAX_CHAT_MESSAGES,
    },
    "feeds": {
        "threat_intel_auto_refresh": True,
        "refresh_interval_minutes": 60,
        "sources": ["CISA KEV", "Feodo Tracker", "IPsum", "URLhaus", "ThreatFox"],
    },
    "detection": {
        "dedup_window_minutes": 20,
        "group_window_hours": 24,
        "reopen_window_hours": 8,
        "sla_minutes": {"CRITICAL": 30, "HIGH": 120, "MEDIUM": 360, "LOW": 720},
        "auto_close_hours": {"LOW": 24, "MEDIUM": 72},
        "risk_thresholds": {"critical": 80, "high": 55, "medium": 30},
    },
}

# Keys an API client may change, with basic type validation.
_ALLOWED_TOP_LEVEL = set(DEFAULT_SETTINGS)
_CACHE_TTL_SECONDS = 10

_lock = threading.Lock()
_cache: dict = {"value": None, "loaded_at": 0.0}


def _deep_merge(base: dict, incoming: dict) -> dict:
    merged = deepcopy(base)
    for key, value in (incoming or {}).items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _validate(payload: dict) -> dict:
    unknown = set(payload) - _ALLOWED_TOP_LEVEL
    if unknown:
        raise ValueError(f"Unknown settings keys: {', '.join(sorted(unknown))}")
    thresholds = (payload.get("detection") or {}).get("risk_thresholds")
    if thresholds:
        merged = _deep_merge(DEFAULT_SETTINGS["detection"]["risk_thresholds"], thresholds)
        if not (0 < merged["medium"] < merged["high"] < merged["critical"] <= 100):
            raise ValueError("Risk thresholds must satisfy 0 < medium < high < critical <= 100")
    retention = payload.get("retention") or {}
    for key, value in retention.items():
        if not isinstance(value, int) or value < 100:
            raise ValueError(f"retention.{key} must be an integer >= 100")
    return payload


def get_app_settings(force_reload: bool = False) -> dict:
    now = time.monotonic()
    cached = _cache["value"]
    if cached is not None and not force_reload and now - _cache["loaded_at"] < _CACHE_TTL_SECONDS:
        return deepcopy(cached)

    with _lock:
        db = SessionLocal()
        try:
            row = db.get(AppConfig, 1)
            stored = row.data if row else {}
        except Exception:
            stored = {}  # table may not exist yet during first boot
        finally:
            db.close()
        value = _deep_merge(DEFAULT_SETTINGS, stored or {})
        _cache.update({"value": value, "loaded_at": now})
        return deepcopy(value)


def update_app_settings(payload: dict, updated_by: Optional[str] = None, db=None) -> dict:
    """Merge `payload` into the stored settings. When `db` is given the caller owns the commit."""
    _validate(payload or {})
    own_session = db is None
    session = SessionLocal() if own_session else db
    with _lock:
        try:
            row = session.get(AppConfig, 1)
            current = _deep_merge(DEFAULT_SETTINGS, row.data if row else {})
            merged = _deep_merge(current, payload or {})
            if row is None:
                session.add(AppConfig(id=1, data=merged, updated_by=updated_by))
            else:
                row.data = merged
                row.updated_by = updated_by
            if own_session:
                session.commit()
            else:
                session.flush()
        finally:
            if own_session:
                session.close()
        _cache.update({"value": merged, "loaded_at": time.monotonic()})
        return deepcopy(merged)
