"""Shared outbound HTTP client and a tiny thread-safe TTL cache for enrichment lookups."""
from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Any, Callable

import httpx

from config import settings

USER_AGENT = f"ThreatLens/{settings.APP_VERSION} (+https://github.com/kritikGianta/ThreatLens)"

# httpx.Client is thread-safe and pools connections across the scheduler,
# background ingestion threads and request handlers.
http_client = httpx.Client(
    timeout=httpx.Timeout(settings.OUTBOUND_HTTP_TIMEOUT, connect=5.0),
    headers={"User-Agent": USER_AGENT},
    follow_redirects=True,
)


class TTLCache:
    """Bounded LRU cache with per-entry expiry."""

    def __init__(self, maxsize: int = 512, ttl_seconds: float = 3600):
        self.maxsize = maxsize
        self.ttl = ttl_seconds
        self._data: OrderedDict[Any, tuple[float, Any]] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: Any) -> Any | None:
        with self._lock:
            item = self._data.get(key)
            if not item:
                return None
            stored_at, value = item
            if time.monotonic() - stored_at > self.ttl:
                del self._data[key]
                return None
            self._data.move_to_end(key)
            return value

    def set(self, key: Any, value: Any) -> None:
        with self._lock:
            self._data[key] = (time.monotonic(), value)
            self._data.move_to_end(key)
            while len(self._data) > self.maxsize:
                self._data.popitem(last=False)

    def get_or_compute(self, key: Any, compute: Callable[[], Any], cache_empty: bool = False) -> Any:
        cached = self.get(key)
        if cached is not None:
            return cached
        value = compute()
        if value or cache_empty:
            self.set(key, value)
        return value

    def clear(self) -> None:
        with self._lock:
            self._data.clear()
