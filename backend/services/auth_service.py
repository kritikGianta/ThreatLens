"""
ThreatLens Auth Service — password hashing (bcrypt) and JWT issuance (PyJWT).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
import jwt
from sqlalchemy import func
from sqlalchemy.orm import Session

from config import settings
from models.db_models import User

# bcrypt only considers the first 72 bytes of a password.
_BCRYPT_MAX_BYTES = 72


# ========================
#  Password Hashing
# ========================
def hash_password(password: str) -> str:
    secret = password.encode("utf-8")[:_BCRYPT_MAX_BYTES]
    return bcrypt.hashpw(secret, bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    if not plain_password or not hashed_password:
        return False
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8")[:_BCRYPT_MAX_BYTES],
            hashed_password.encode("utf-8"),
        )
    except ValueError:
        return False


# ========================
#  JWT Token Management
# ========================
def _encode(data: dict, token_type: str, expires_delta: timedelta) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        **data,
        "type": token_type,
        "iat": now,
        "exp": now + expires_delta,
        "jti": uuid.uuid4().hex,
        "iss": "threatlens",
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    return _encode(data, "access", expires_delta or timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES))


def create_refresh_token(data: dict) -> str:
    return _encode(data, "refresh", timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS))


def decode_token(token: str) -> Optional[dict]:
    """Decode and validate a JWT. Returns the payload or None."""
    try:
        return jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
            options={"require": ["exp", "sub", "type"]},
        )
    except jwt.PyJWTError:
        return None


# ========================
#  User CRUD
# ========================
def create_user(
    db: Session,
    email: str,
    username: str,
    password: str,
    full_name: str | None = None,
    role: str = "analyst",
    organization: str | None = None,
) -> User:
    user = User(
        email=email.lower().strip(),
        username=username.strip(),
        hashed_password=hash_password(password),
        full_name=full_name,
        role=role,
        organization=organization,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def authenticate_user(db: Session, login: str, password: str) -> Optional[User]:
    """Authenticate by email or username (case-insensitive). Returns User or None."""
    ident = login.strip().lower()
    user = (
        db.query(User)
        .filter((func.lower(User.email) == ident) | (func.lower(User.username) == ident))
        .first()
    )
    if not user or not user.is_active or not verify_password(password, user.hashed_password):
        return None

    user.last_login = datetime.utcnow()
    db.commit()
    return user


def get_user_by_id(db: Session, user_id: int) -> Optional[User]:
    return db.query(User).filter(User.id == user_id).first()


def get_user_by_email(db: Session, email: str) -> Optional[User]:
    return db.query(User).filter(func.lower(User.email) == email.lower().strip()).first()


def get_user_by_username(db: Session, username: str) -> Optional[User]:
    return db.query(User).filter(func.lower(User.username) == username.lower().strip()).first()
