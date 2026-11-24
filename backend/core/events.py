"""
In-process real-time event bus feeding the Server-Sent Events stream.

Producers (the analysis pipeline, SOAR, the live simulator, feed ingestion) run in
worker threads. Events tied to a database transaction are queued on the session and
published only after the transaction commits, so the UI never shows an incident that
was rolled back.
"""
from __future__ import annotations

import asyncio
import itertools
import secrets
import threading
import time
from collections import deque
from datetime import datetime
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

from sqlalchemy import event as sa_event
from sqlalchemy.orm import Session

_lock = threading.Lock()
_subscribers: Set[Tuple[asyncio.AbstractEventLoop, asyncio.Queue]] = set()
_recent: Deque[Dict[str, Any]] = deque(maxlen=200)
_sequence = itertools.count(1)

_QUEUE_SIZE = 1000
_PENDING_KEY = "threatlens_pending_events"


def _deliver(queue: asyncio.Queue, item: Dict[str, Any]) -> None:
    if queue.full():
        try:
            queue.get_nowait()  # drop the oldest event for slow consumers
        except asyncio.QueueEmpty:
            pass
    queue.put_nowait(item)


def publish(event_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """Broadcast an event to every connected stream immediately (thread-safe)."""
    item = {
        "id": next(_sequence),
        "type": event_type,
        "ts": datetime.utcnow().isoformat() + "Z",
        "data": data,
    }
    with _lock:
        _recent.append(item)
        subscribers = list(_subscribers)
    for loop, queue in subscribers:
        try:
            loop.call_soon_threadsafe(_deliver, queue, item)
        except RuntimeError:  # event loop already closed
            unsubscribe(queue)
    return item


def queue_event(db: Session, event_type: str, data: Dict[str, Any]) -> None:
    """Publish when `db`'s transaction commits (discarded on rollback)."""
    db.info.setdefault(_PENDING_KEY, []).append((event_type, data))


def subscribe() -> asyncio.Queue:
    queue: asyncio.Queue = asyncio.Queue(maxsize=_QUEUE_SIZE)
    with _lock:
        _subscribers.add((asyncio.get_running_loop(), queue))
    return queue


def unsubscribe(queue: asyncio.Queue) -> None:
    with _lock:
        for entry in [s for s in _subscribers if s[1] is queue]:
            _subscribers.discard(entry)


def recent(limit: int = 50, types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    with _lock:
        items = list(_recent)
    if types:
        items = [i for i in items if i["type"] in types]
    return items[-limit:]


def subscriber_count() -> int:
    with _lock:
        return len(_subscribers)


# ── Session hooks: flush queued events on commit, drop them on rollback ──────
def install_session_hooks(session_factory) -> None:
    @sa_event.listens_for(session_factory, "after_commit")
    def _after_commit(session):  # pragma: no cover - exercised via API tests
        pending = session.info.pop(_PENDING_KEY, None)
        for event_type, data in pending or []:
            publish(event_type, data)

    @sa_event.listens_for(session_factory, "after_rollback")
    def _after_rollback(session):  # pragma: no cover
        session.info.pop(_PENDING_KEY, None)


# ── Short-lived stream tickets (EventSource cannot send Authorization headers) ─
_tickets: Dict[str, Tuple[int, float]] = {}
_TICKET_TTL_SECONDS = 60


def issue_ticket(user_id: int) -> str:
    now = time.monotonic()
    ticket = secrets.token_urlsafe(24)
    with _lock:
        for key in [k for k, (_, exp) in _tickets.items() if exp < now]:
            _tickets.pop(key, None)
        _tickets[ticket] = (user_id, now + _TICKET_TTL_SECONDS)
    return ticket


def redeem_ticket(ticket: str) -> Optional[int]:
    """One-time use: returns the user id, or None if unknown/expired."""
    with _lock:
        entry = _tickets.pop(ticket or "", None)
    if not entry or entry[1] < time.monotonic():
        return None
    return entry[0]
