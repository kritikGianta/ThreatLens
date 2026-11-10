"""AI SOC Copilot endpoints — conversation history is private to each user."""

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from core.rate_limit import limiter
from dependencies.auth import get_current_user
from models.database import get_db
from models.db_models import ChatMessage, User
from services.chat_service import chat

router = APIRouter()


class ChatInput(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)
    session_id: Optional[str] = Field(default=None, max_length=64)


@router.post("/ask")
@limiter.limit("20/minute")
def ask_copilot(request: Request, data: ChatInput, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Ask a natural-language question about your security data. Reuse session_id for multi-turn memory."""
    session_id = data.session_id or f"session_{uuid.uuid4().hex[:16]}"
    result = chat(data.message, db, session_id=session_id, user_id=user.id)

    db.add(ChatMessage(role="user", content=data.message, session_id=session_id, user_id=user.id))
    db.add(ChatMessage(role="assistant", content=result["response"], context_used=result.get("context_used"),
                       session_id=session_id, user_id=user.id))
    db.commit()
    return {
        "response": result["response"],
        "generated_by": result.get("generated_by"),
        "context_used": result.get("context_used"),
        "session_id": session_id,
    }


@router.get("/history")
def get_chat_history(
    session_id: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = db.query(ChatMessage).filter(ChatMessage.user_id == user.id)
    if session_id:
        query = query.filter(ChatMessage.session_id == session_id)
    messages = query.order_by(desc(ChatMessage.timestamp), desc(ChatMessage.id)).limit(limit).all()
    return {
        "messages": [
            {"id": m.id, "role": m.role, "content": m.content, "session_id": m.session_id,
             "timestamp": m.timestamp.isoformat() if m.timestamp else None}
            for m in reversed(messages)
        ]
    }


@router.get("/sessions")
def list_sessions(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    rows = (
        db.query(ChatMessage.session_id, func.min(ChatMessage.timestamp), func.max(ChatMessage.timestamp), func.count(ChatMessage.id))
        .filter(ChatMessage.user_id == user.id, ChatMessage.session_id.isnot(None))
        .group_by(ChatMessage.session_id)
        .order_by(desc(func.max(ChatMessage.timestamp)))
        .limit(20)
        .all()
    )
    sessions = []
    for session_id, started, last, count in rows:
        first = (
            db.query(ChatMessage.content)
            .filter(ChatMessage.session_id == session_id, ChatMessage.user_id == user.id, ChatMessage.role == "user")
            .order_by(ChatMessage.timestamp, ChatMessage.id).first()
        )
        sessions.append({
            "session_id": session_id,
            "title": (first[0][:80] if first else "Conversation"),
            "started_at": started.isoformat() if started else None,
            "last_message_at": last.isoformat() if last else None,
            "message_count": count,
        })
    return {"sessions": sessions}


@router.delete("/sessions/{session_id}")
def delete_session(session_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    deleted = db.query(ChatMessage).filter(ChatMessage.user_id == user.id, ChatMessage.session_id == session_id).delete(synchronize_session=False)
    db.commit()
    return {"deleted": deleted}
