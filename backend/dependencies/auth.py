"""
ThreatLens auth dependencies — JWT validation and role-based access control.

Roles:
  admin   — everything, including user management, settings and destructive resets
  analyst — read + operate (triage incidents, run analysis, manage SOAR rules/blocklist)
  viewer  — read-only
"""
from __future__ import annotations

import hmac
from typing import Optional

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from config import settings
from models.database import get_db
from models.db_models import User
from services.auth_service import decode_token, get_user_by_id

security = HTTPBearer(auto_error=False)

ROLES = ("admin", "analyst", "viewer")
WRITE_ROLES = ("admin", "analyst")


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    """Extract and validate the current user from the Authorization header."""
    if credentials is None or not credentials.credentials:
        raise _unauthorized("Not authenticated")

    payload = decode_token(credentials.credentials)
    if not payload:
        raise _unauthorized("Invalid or expired token")
    if payload.get("type") != "access":
        raise _unauthorized("Invalid token type. Use an access token.")

    try:
        user_id = int(payload.get("sub"))
    except (TypeError, ValueError):
        raise _unauthorized("Token missing user identity")

    user = get_user_by_id(db, user_id)
    if not user:
        raise _unauthorized("User not found")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is deactivated")
    return user


def require_role(*allowed_roles: str):
    """Dependency factory: restricts an endpoint to specific roles."""

    def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This action requires role: {', '.join(allowed_roles)}. Your role: {current_user.role}",
            )
        return current_user

    return role_checker


require_admin = require_role("admin")
require_writer = require_role(*WRITE_ROLES)


def ingest_principal(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db),
) -> str:
    """
    Accept either a static ingest API key (for log forwarders such as Filebeat/Fluentd)
    or a regular analyst/admin JWT. Returns a principal name for auditing.
    """
    if x_api_key:
        if settings.INGEST_API_KEY and hmac.compare_digest(x_api_key, settings.INGEST_API_KEY):
            return "ingest-api-key"
        raise _unauthorized("Invalid ingest API key")

    user = get_current_user(credentials, db)
    if user.role not in WRITE_ROLES:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Viewers cannot ingest logs")
    return user.username
