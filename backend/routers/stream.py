"""
Real-time event stream (Server-Sent Events).

Browsers' EventSource cannot send an Authorization header, so clients first exchange their
access token for a single-use, 60-second ticket (POST /ticket) and open
GET /events?ticket=... — keeping long-lived tokens out of URLs and access logs.
"""
import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from core import events
from dependencies.auth import get_current_user
from models.database import SessionLocal
from models.db_models import User
from services.auth_service import get_user_by_id

router = APIRouter()

HEARTBEAT_SECONDS = 15


@router.post("/ticket")
def stream_ticket(user: User = Depends(get_current_user)):
    return {"ticket": events.issue_ticket(user.id), "expires_in": 60}


@router.get("/recent")
def recent_events(limit: int = Query(50, ge=1, le=200), _: User = Depends(get_current_user)):
    return {"events": events.recent(limit)}


def _authorize_ticket(ticket: str) -> User:
    user_id = events.redeem_ticket(ticket)
    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid or expired stream ticket")
    db = SessionLocal()
    try:
        user = get_user_by_id(db, user_id)
    finally:
        db.close()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or deactivated")
    return user


@router.get("/events")
async def event_stream(request: Request, ticket: str = Query(..., min_length=10, max_length=100)):
    _authorize_ticket(ticket)
    queue = events.subscribe()

    async def generator():
        try:
            yield "retry: 3000\n\n"
            yield f"event: hello\ndata: {json.dumps({'subscribers': events.subscriber_count()})}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    item = await asyncio.wait_for(queue.get(), timeout=HEARTBEAT_SECONDS)
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
                    continue
                yield f"id: {item['id']}\nevent: {item['type']}\ndata: {json.dumps(item, default=str)}\n\n"
        finally:
            events.unsubscribe(queue)

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )
