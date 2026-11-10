"""
ThreatLens Auth Router — registration, login, token refresh, profile and user management.
"""

import re
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy.orm import Session

from config import settings
from core.rate_limit import limiter
from dependencies.auth import ROLES, get_current_user, require_admin
from models.database import get_db
from models.db_models import User
from services.audit import record_audit
from services.auth_service import (
    authenticate_user,
    create_access_token,
    create_refresh_token,
    create_user,
    decode_token,
    get_user_by_email,
    get_user_by_id,
    get_user_by_username,
    hash_password,
    verify_password,
)

router = APIRouter()

_USERNAME_RX = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


def _validate_password(value: str) -> str:
    if len(value) < 8:
        raise ValueError("Password must be at least 8 characters")
    if len(value) > 128:
        raise ValueError("Password must be at most 128 characters")
    if not any(c.isdigit() for c in value):
        raise ValueError("Password must contain at least one number")
    if not any(c.isupper() for c in value):
        raise ValueError("Password must contain at least one uppercase letter")
    if not any(c.islower() for c in value):
        raise ValueError("Password must contain at least one lowercase letter")
    return value


# ========================
#  Request Models
# ========================
class SignupRequest(BaseModel):
    email: EmailStr
    username: str
    password: str
    full_name: Optional[str] = Field(default=None, max_length=255)
    organization: Optional[str] = Field(default=None, max_length=255)

    @field_validator("password")
    @classmethod
    def validate_password(cls, v):
        return _validate_password(v)

    @field_validator("username")
    @classmethod
    def validate_username(cls, v):
        v = v.strip()
        if not _USERNAME_RX.match(v):
            raise ValueError("Username must be 3-32 characters: letters, numbers, '.', '_' or '-'")
        return v


class AdminCreateUserRequest(SignupRequest):
    role: str = "analyst"

    @field_validator("role")
    @classmethod
    def validate_role(cls, v):
        if v not in ROLES:
            raise ValueError(f"Role must be one of: {', '.join(ROLES)}")
        return v


class LoginRequest(BaseModel):
    login: str = Field(..., min_length=1, max_length=255)  # email or username
    password: str = Field(..., min_length=1, max_length=256)


class RefreshRequest(BaseModel):
    refresh_token: str


class UpdateProfileRequest(BaseModel):
    full_name: Optional[str] = Field(default=None, max_length=255)
    organization: Optional[str] = Field(default=None, max_length=255)


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def validate_password(cls, v):
        return _validate_password(v)


class AdminRoleUpdate(BaseModel):
    role: str

    @field_validator("role")
    @classmethod
    def validate_role(cls, v):
        if v not in ROLES:
            raise ValueError(f"Role must be one of: {', '.join(ROLES)}")
        return v


# ========================
#  Helpers
# ========================
def user_to_dict(user: User) -> dict:
    return {
        "id": user.id,
        "email": user.email,
        "username": user.username,
        "full_name": user.full_name,
        "role": user.role,
        "organization": user.organization,
        "is_active": user.is_active,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "last_login": user.last_login.isoformat() if user.last_login else None,
    }


def _token_response(user: User) -> dict:
    claims = {"sub": str(user.id), "role": user.role, "username": user.username}
    return {
        "access_token": create_access_token(claims),
        "refresh_token": create_refresh_token(claims),
        "token_type": "bearer",
        "expires_in": settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user": user_to_dict(user),
    }


def _ensure_unique(db: Session, email: str, username: str) -> None:
    if get_user_by_email(db, email):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="An account with this email already exists")
    if get_user_by_username(db, username):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This username is already taken")


# ========================
#  Public endpoints
# ========================
@router.get("/config")
def auth_config(db: Session = Depends(get_db)):
    """Tells the UI whether self-service signup is available."""
    has_users = db.query(User.id).first() is not None
    return {"signup_enabled": settings.ALLOW_PUBLIC_SIGNUP or not has_users, "bootstrap_required": not has_users}


@router.post("/signup", status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
def signup(request: Request, data: SignupRequest, db: Session = Depends(get_db)):
    """Register a new account. The very first account becomes an admin."""
    is_first_user = db.query(User.id).first() is None
    if not settings.ALLOW_PUBLIC_SIGNUP and not is_first_user:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Self-service signup is disabled. Ask an administrator for an account.")

    _ensure_unique(db, data.email, data.username)
    role = "admin" if is_first_user else "analyst"
    user = create_user(db, email=data.email, username=data.username, password=data.password,
                       full_name=data.full_name, role=role, organization=data.organization)
    record_audit(db, "auth.signup", actor=user, target_type="user", target_id=user.id, request=request, commit=True)

    response = _token_response(user)
    response["message"] = f"Account created. Role: {role}" + (" (first user is automatically admin)" if is_first_user else "")
    return response


@router.post("/login")
@limiter.limit("10/minute")
def login(request: Request, data: LoginRequest, db: Session = Depends(get_db)):
    """Login with email or username. Rate limited to 10 attempts/min per client IP."""
    user = authenticate_user(db, data.login, data.password)
    if not user:
        record_audit(db, "auth.login_failed", actor_name=data.login[:100], request=request, commit=True)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    record_audit(db, "auth.login", actor=user, request=request, commit=True)
    return _token_response(user)


@router.post("/refresh")
@limiter.limit("30/minute")
def refresh_token(request: Request, data: RefreshRequest, db: Session = Depends(get_db)):
    """Exchange a refresh token for a new access/refresh token pair."""
    payload = decode_token(data.refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token")
    try:
        user = get_user_by_id(db, int(payload.get("sub")))
    except (TypeError, ValueError):
        user = None
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or deactivated")
    return _token_response(user)


# ========================
#  Authenticated endpoints
# ========================
@router.get("/me")
def get_profile(current_user: User = Depends(get_current_user)):
    return {"user": user_to_dict(current_user)}


@router.put("/me")
def update_profile(data: UpdateProfileRequest, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if data.full_name is not None:
        current_user.full_name = data.full_name.strip() or None
    if data.organization is not None:
        current_user.organization = data.organization.strip() or None
    db.merge(current_user)
    db.commit()
    return {"message": "Profile updated", "user": user_to_dict(current_user)}


@router.put("/me/password")
def change_password(
    request: Request, data: ChangePasswordRequest,
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db),
):
    user = get_user_by_id(db, current_user.id)
    if not verify_password(data.current_password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")
    user.hashed_password = hash_password(data.new_password)
    record_audit(db, "auth.password_changed", actor=user, target_type="user", target_id=user.id, request=request)
    db.commit()
    return {"message": "Password changed successfully"}


# ========================
#  Admin-only endpoints
# ========================
@router.get("/users")
def list_users(_: User = Depends(require_admin), db: Session = Depends(get_db)):
    users = db.query(User).order_by(User.created_at).all()
    return {"total": len(users), "users": [user_to_dict(u) for u in users]}


@router.post("/users", status_code=status.HTTP_201_CREATED)
def admin_create_user(request: Request, data: AdminCreateUserRequest, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    _ensure_unique(db, data.email, data.username)
    user = create_user(db, email=data.email, username=data.username, password=data.password,
                       full_name=data.full_name, role=data.role, organization=data.organization)
    record_audit(db, "user.create", actor=admin, target_type="user", target_id=user.id,
                 details={"username": user.username, "role": user.role}, request=request, commit=True)
    return {"message": f"User '{user.username}' created", "user": user_to_dict(user)}


@router.put("/users/{user_id}/role")
def update_user_role(request: Request, user_id: int, data: AdminRoleUpdate, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    if user_id == admin.id:
        raise HTTPException(status_code=400, detail="You cannot change your own role")
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    previous = user.role
    user.role = data.role
    record_audit(db, "user.role_change", actor=admin, target_type="user", target_id=user.id,
                 details={"from": previous, "to": data.role}, request=request)
    db.commit()
    return {"message": f"User '{user.username}' role changed to '{data.role}'", "user": user_to_dict(user)}


@router.put("/users/{user_id}/deactivate")
def toggle_user_active(request: Request, user_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    if user_id == admin.id:
        raise HTTPException(status_code=400, detail="You cannot deactivate yourself")
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_active = not user.is_active
    record_audit(db, "user.activate" if user.is_active else "user.deactivate", actor=admin,
                 target_type="user", target_id=user.id, request=request)
    db.commit()
    return {"message": f"User '{user.username}' {'activated' if user.is_active else 'deactivated'}", "user": user_to_dict(user)}
