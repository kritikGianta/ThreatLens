"""Measured pipeline performance: processing latency and event throughput (thread-safe)."""
from __future__ import annotations

import threading
import time
from collections import deque
from typing import Dict, List

_lock = threading.Lock()
_latencies_ms: deque = deque(maxlen=2000)
_event_times: deque = deque(maxlen=50_000)   # monotonic seconds of processed logs
_started = time.monotonic()


def record_processed(duration_ms: float) -> None:
    with _lock:
        _latencies_ms.append(duration_ms)
        _event_times.append(time.monotonic())


def _percentile(values: List[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(pct / 100 * (len(ordered) - 1))))
    return round(ordered[index], 1)


def snapshot(window_minutes: int = 30) -> Dict:
    now = time.monotonic()
    with _lock:
        latencies = list(_latencies_ms)
        times = [t for t in _event_times if now - t <= window_minutes * 60]
    per_minute = [0] * window_minutes
    for t in times:
        bucket = int((now - t) // 60)
        if bucket < window_minutes:
            per_minute[window_minutes - 1 - bucket] += 1
    last_minute = per_minute[-1] if per_minute else 0
    return {
        "pipeline_latency_ms": {
            "p50": _percentile(latencies, 50),
            "p95": _percentile(latencies, 95),
            "max": round(max(latencies), 1) if latencies else 0.0,
            "samples": len(latencies),
        },
        "events_per_minute": per_minute,
        "events_last_minute": last_minute,
        "events_in_window": len(times),
        "uptime_seconds": int(now - _started),
    }
