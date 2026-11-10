"""
Lightweight real-log collector for local Windows demos.
Polls a few high-signal Windows Event Logs and feeds them into the normal pipeline.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from threading import Lock, Thread
from typing import Dict, List, Optional
import json
import logging
import platform
import re
import subprocess
import time

from config import settings
from models.database import SessionLocal
from services.app_settings import get_app_settings
from services.detector import evaluate_rules
from services.parser import parse_log
from services.pipeline import process_log
from services.source_health import mark_source_error, record_source_health

logger = logging.getLogger("threatlens.collector")

_status = {
    "enabled": settings.ENABLE_REAL_LOG_COLLECTOR,
    "supported": platform.system().lower() == "windows",
    "running": False,
    "last_run_at": None,
    "last_success_at": None,
    "last_error": None,
    "last_events_collected": 0,
    "total_events_collected": 0,
    "last_sources": [],
    "state_file": settings.REAL_LOG_STATE_PATH,
}
_collector_thread = None
_status_lock = Lock()
_state_lock = Lock()
_NOISE_EVENT_IDS = {"400", "403", "600"}


def _channel_specs() -> List[Dict]:
    return [
        {"name": "Security", "ids": [4624, 4625, 4688, 4672, 1102]},
        {"name": "System", "ids": [7045, 7040, 104]},
        {"name": "Windows PowerShell", "ids": [400, 403, 600]},
    ]


def _state_path() -> Path:
    path = Path(settings.REAL_LOG_STATE_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _load_state() -> Dict:
    path = _state_path()
    if not path.exists():
        return {"channels": {}}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"channels": {}}


def _save_state(state: Dict):
    path = _state_path()
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")


def _update_status(**updates):
    with _status_lock:
        _status.update(updates)


def get_collector_status() -> Dict:
    with _status_lock:
        return dict(_status)


def start_real_log_collector():
    global _collector_thread

    if _collector_thread and _collector_thread.is_alive():
        return

    collector_settings = get_app_settings().get("collector", {})
    if not collector_settings.get("enabled", settings.ENABLE_REAL_LOG_COLLECTOR):
        _update_status(enabled=False, running=False, last_error="Collector disabled by configuration")
        return

    if platform.system().lower() != "windows":
        _update_status(supported=False, running=False, last_error="Real log collector currently supports Windows only")
        return

    _collector_thread = Thread(target=_collector_loop, daemon=True, name="threatlens-real-log-collector")
    _collector_thread.start()
    _update_status(running=True, last_error=None)
    logger.info("[Collector] Real log collector started")


def run_collection_cycle_now() -> Dict:
    if platform.system().lower() != "windows":
        raise RuntimeError("Real log collection is only supported on Windows")
    return _run_collection_cycle()


def _collector_loop():
    while True:
        try:
            _run_collection_cycle()
        except Exception as exc:
            logger.warning(f"[Collector] Sweep failed: {exc}")
            _update_status(last_error=str(exc))
        interval = get_app_settings().get("collector", {}).get("interval_seconds", settings.REAL_LOG_COLLECTOR_INTERVAL_SECONDS)
        time.sleep(max(interval, 30))


def _run_collection_cycle() -> Dict:
    state = _load_state()
    state.setdefault("channels", {})
    runtime = get_app_settings().get("collector", {})
    per_channel_limit = max(5, runtime.get("max_events_per_sweep", settings.REAL_LOG_MAX_EVENTS_PER_SWEEP) // max(len(_channel_specs()), 1))

    total_added = 0
    channel_summaries = []

    db = SessionLocal()
    try:
        for spec in _channel_specs():
            added = _collect_channel(db, spec["name"], spec["ids"], per_channel_limit, state)
            channel_summaries.append({"channel": spec["name"], "events_added": added})
            total_added += added

        db.commit()
    except Exception:
        mark_source_error(db, "real_windows_event_log", "Collector sweep failed")
        db.rollback()
        raise
    finally:
        db.close()

    with _state_lock:
        _save_state(state)

    now = datetime.utcnow().isoformat()
    _update_status(
        running=True,
        last_run_at=now,
        last_success_at=now,
        last_error=None,
        last_events_collected=total_added,
        total_events_collected=_status["total_events_collected"] + total_added,
        last_sources=channel_summaries,
    )
    if total_added:
        logger.info(f"[Collector] Added {total_added} real local events")
    return {"events_added": total_added, "channels": channel_summaries}


def _collect_channel(db, channel_name: str, event_ids: List[int], limit: int, state: Dict) -> int:
    channel_state = state["channels"].setdefault(channel_name, {"last_record_id": 0})
    events = _query_windows_events(channel_name, event_ids, limit)

    added = 0
    last_record = channel_state.get("last_record_id", 0)
    for event in events:
        record_id = int(event.get("RecordId") or 0)
        if record_id <= last_record:
            continue
        if _ingest_event(db, event):
            added += 1
        if record_id > channel_state.get("last_record_id", 0):
            channel_state["last_record_id"] = record_id
    return added


def _query_windows_events(channel_name: str, event_ids: List[int], limit: int) -> List[Dict]:
    id_list = ",".join(str(i) for i in event_ids)
    bootstrap_minutes = get_app_settings().get("collector", {}).get("bootstrap_minutes", settings.REAL_LOG_BOOTSTRAP_MINUTES)
    script = f"""
$ErrorActionPreference = 'Stop'
$start = (Get-Date).AddMinutes(-{bootstrap_minutes})
$events = Get-WinEvent -FilterHashtable @{{LogName='{channel_name}'; StartTime=$start; Id={id_list}}} -MaxEvents {limit}
$events |
  Sort-Object RecordId |
  Select-Object RecordId, Id, LogName, ProviderName, MachineName, TimeCreated, LevelDisplayName, Message |
  ConvertTo-Json -Depth 4 -Compress
"""
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except Exception as exc:
        logger.warning(f"[Collector] Failed to query {channel_name}: {exc}")
        return []

    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        if stderr:
            logger.info(f"[Collector] {channel_name} unavailable: {stderr[:180]}")
        return []

    raw = (proc.stdout or "").strip()
    if not raw:
        return []

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning(f"[Collector] Could not decode event payload for {channel_name}")
        return []

    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return data
    return []


def _ingest_event(db, event: Dict) -> bool:
    message = " ".join(str(event.get("Message") or "").split())
    provider = event.get("ProviderName") or "Windows"
    host = event.get("MachineName") or "localhost"
    event_id = event.get("Id")
    event_id_str = str(event_id) if event_id is not None else None
    log_name = event.get("LogName") or "unknown"
    record_id = event.get("RecordId")
    created_at = _parse_time(event.get("TimeCreated")) or datetime.utcnow()
    interval = get_app_settings().get("collector", {}).get("interval_seconds", settings.REAL_LOG_COLLECTOR_INTERVAL_SECONDS)

    raw_log = (
        f"[REAL_LOG] EventID={event_id} LogName={log_name} Provider={provider} "
        f"Host={host} RecordId={record_id} Message={message}"
    )[:4000]

    suspicious_powershell = _is_suspicious_powershell_event(log_name, message)
    has_detection = bool(evaluate_rules(parse_log(raw_log)))
    if _is_low_signal_event(log_name, event_id_str, message, has_detection, suspicious_powershell):
        record_source_health(db, "real_windows_event_log", event_timestamp=created_at, dropped_events=1,
                             collector_interval_seconds=interval)
        return False

    def suppress_benign_powershell(_parsed, detection):
        if (
            log_name == "Windows PowerShell"
            and detection.get("threat_detected") == "Suspicious PowerShell Execution"
            and not suspicious_powershell
        ):
            detection.update({
                "threat_detected": None, "all_threats_detected": [], "confidence": 0, "mitre_candidate": None,
                "all_mitre_techniques": [], "current_stage": None, "all_stages_this_log": [], "severity_override": None,
            })

    process_log(
        db,
        raw_log,
        source="real_windows_event_log",
        event_time=created_at,
        summary_extra={"provider": provider, "channel": log_name, "event_id": event_id_str},
        detection_hook=suppress_benign_powershell,
    )
    record_source_health(db, "real_windows_event_log", event_timestamp=created_at, collector_interval_seconds=interval)
    return True


def _parse_time(value) -> Optional[datetime]:
    """Parse PowerShell's `/Date(1700000000000)/` or ISO-8601 into naive UTC."""
    if not value:
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value)
        match = re.search(r"/Date\((-?\d+)", text)
        if match:
            return datetime.utcfromtimestamp(int(match.group(1)) / 1000)
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def _is_suspicious_powershell_event(log_name: str, message: str) -> bool:
    if log_name != "Windows PowerShell":
        return True

    low = message.lower()
    suspicious_tokens = [
        "encodedcommand",
        "frombase64string",
        "downloadstring",
        "invoke-expression",
        "iex ",
        " net.webclient",
        "bypass",
        "rundll32",
        "mimikatz",
        "procdump",
        "lsass",
        "reverse shell",
        "cobalt",
    ]
    return any(token in low for token in suspicious_tokens)


def _is_low_signal_event(
    log_name: str,
    event_id: Optional[str],
    message: str,
    has_detection: bool,
    suspicious_powershell: bool,
) -> bool:
    if log_name == "Windows PowerShell" and not suspicious_powershell and event_id in _NOISE_EVENT_IDS:
        return True

    if not has_detection and event_id in _NOISE_EVENT_IDS:
        return True

    low = message.lower()
    if "engine state is changed" in low and not suspicious_powershell:
        return True

    return False
