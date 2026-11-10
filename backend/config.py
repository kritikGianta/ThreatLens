"""
ThreatLens runtime configuration.

Every value is read from environment variables (optionally loaded from a `.env`
file). See `.env.example` at the repository root for documentation of each key
and where to obtain the third-party API keys.
"""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent

# Load backend/.env first, then the repository-root .env (used by docker compose).
load_dotenv(BASE_DIR / ".env")
load_dotenv(BASE_DIR.parent / ".env")

# Sentinel value — used to detect if JWT_SECRET was never changed from default.
_DEFAULT_JWT_SECRET = "threatlens-dev-secret-change-me"


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _list(name: str, default: str) -> list[str]:
    return [item.strip() for item in os.getenv(name, default).split(",") if item.strip()]


def _optional(name: str) -> str | None:
    """Return an env var, treating empty strings and `your_..._here` placeholders as unset."""
    value = (os.getenv(name) or "").strip()
    if not value or (value.lower().startswith("your_") and value.lower().endswith("_here")):
        return None
    return value


class Settings:
    BASE_DIR = BASE_DIR
    DATA_DIR = Path(os.getenv("DATA_DIR", str(BASE_DIR / "data")))
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # ── Application ──────────────────────────────────────────────────────────
    APP_NAME = "ThreatLens"
    APP_VERSION = "4.0.0"
    ENVIRONMENT = os.getenv("ENVIRONMENT", "development").lower()  # development | production | test
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
    LOG_FORMAT = os.getenv("LOG_FORMAT", "text").lower()  # text | json

    # ── Database ─────────────────────────────────────────────────────────────
    # DATABASE_URL wins when set (e.g. postgresql+psycopg://user:pass@host:5432/db).
    DATABASE_URL = _optional("DATABASE_URL")
    DB_BACKEND = os.getenv("DB_BACKEND", "sqlite").lower()  # sqlite | postgres
    SQLITE_PATH = os.getenv("SQLITE_PATH", str(DATA_DIR / "threatlens.db"))
    DB_USER = os.getenv("DB_USER", "threatlens")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "")
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_PORT = os.getenv("DB_PORT", "5432")
    DB_NAME = os.getenv("DB_NAME", "threatlens")
    DB_POOL_SIZE = _int("DB_POOL_SIZE", 10)
    DB_MAX_OVERFLOW = _int("DB_MAX_OVERFLOW", 20)

    # ── Third-party API keys (all optional — features degrade gracefully) ─────
    GROQ_API_KEY = _optional("GROQ_API_KEY")
    GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
    GROQ_FAST_MODEL = os.getenv("GROQ_FAST_MODEL", "llama-3.1-8b-instant")
    NVD_API_KEY = _optional("NVD_API_KEY")
    VT_API_KEY = _optional("VT_API_KEY")
    OPENCAGE_API_KEY = _optional("OPENCAGE_API_KEY")
    IPINFO_TOKEN = _optional("IPINFO_TOKEN")
    ABUSECH_AUTH_KEY = _optional("ABUSECH_AUTH_KEY")

    # ── SMTP (SOAR email actions) ─────────────────────────────────────────────
    SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT = _int("SMTP_PORT", 587)
    SMTP_USER = _optional("SMTP_USER") or ""
    SMTP_PASSWORD = _optional("SMTP_PASSWORD") or ""
    SMTP_FROM = _optional("SMTP_FROM") or ""

    # ── Authentication ───────────────────────────────────────────────────────
    JWT_SECRET = _optional("JWT_SECRET") or _DEFAULT_JWT_SECRET
    JWT_ALGORITHM = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES = _int("JWT_ACCESS_EXPIRE_MIN", 30)
    JWT_REFRESH_TOKEN_EXPIRE_DAYS = _int("JWT_REFRESH_EXPIRE_DAYS", 7)
    # When false, only an admin can create additional accounts after the first one.
    ALLOW_PUBLIC_SIGNUP = _bool("ALLOW_PUBLIC_SIGNUP", True)
    # Shared secret for machine-to-machine ingestion (POST /api/v1/logs/webhook).
    INGEST_API_KEY = _optional("INGEST_API_KEY")

    # ── HTTP ─────────────────────────────────────────────────────────────────
    ALLOWED_ORIGINS = _list(
        "ALLOWED_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000,http://localhost:8080,http://127.0.0.1:8080",
    )
    RATE_LIMIT_ENABLED = _bool("RATE_LIMIT_ENABLED", True)
    OUTBOUND_HTTP_TIMEOUT = float(os.getenv("OUTBOUND_HTTP_TIMEOUT", "10"))

    # ── Platform behaviour ───────────────────────────────────────────────────
    SEED_DEMO_DATA = _bool("SEED_DEMO_DATA", True)
    ENABLE_SCHEDULER = _bool("ENABLE_SCHEDULER", True)
    INTEL_INGEST_ON_STARTUP = _bool("INTEL_INGEST_ON_STARTUP", True)

    # Local Windows Event Log collector (only works when the API runs on Windows).
    ENABLE_REAL_LOG_COLLECTOR = _bool("ENABLE_REAL_LOG_COLLECTOR", False)
    REAL_LOG_COLLECTOR_INTERVAL_SECONDS = _int("REAL_LOG_COLLECTOR_INTERVAL_SECONDS", 90)
    REAL_LOG_MAX_EVENTS_PER_SWEEP = _int("REAL_LOG_MAX_EVENTS_PER_SWEEP", 25)
    REAL_LOG_BOOTSTRAP_MINUTES = _int("REAL_LOG_BOOTSTRAP_MINUTES", 120)
    REAL_LOG_STATE_PATH = os.getenv("REAL_LOG_STATE_PATH", str(DATA_DIR / "real_log_collector_state.json"))

    # Retention defaults (overridable at runtime from the Settings page).
    MAX_LOG_ENTRIES = _int("MAX_LOG_ENTRIES", 100_000)
    MAX_INCIDENTS = _int("MAX_INCIDENTS", 25_000)
    MAX_CHAT_MESSAGES = _int("MAX_CHAT_MESSAGES", 5_000)

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"

    @property
    def uses_default_jwt_secret(self) -> bool:
        return (
            self.JWT_SECRET == _DEFAULT_JWT_SECRET
            or self.JWT_SECRET.lower().startswith("change-me")
            or len(self.JWT_SECRET) < 32
        )

    def integration_status(self) -> dict:
        """Which optional integrations are configured (never exposes the values)."""
        return {
            "groq_llm": bool(self.GROQ_API_KEY),
            "nvd_cve": bool(self.NVD_API_KEY),
            "virustotal": bool(self.VT_API_KEY),
            "opencage": bool(self.OPENCAGE_API_KEY),
            "ipinfo": bool(self.IPINFO_TOKEN),
            "abusech": bool(self.ABUSECH_AUTH_KEY),
            "smtp": bool(self.SMTP_USER and self.SMTP_PASSWORD),
            "ingest_api_key": bool(self.INGEST_API_KEY),
        }


settings = Settings()
