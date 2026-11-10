"""
ThreatLens API — AI-powered security operations platform.
"""
from __future__ import annotations

import logging
import threading
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from config import settings
from core.logging import configure_logging, request_id_ctx
from core.rate_limit import limiter

configure_logging()

from dependencies.auth import get_current_user  # noqa: E402
from models.database import SessionLocal, check_database, init_db, safe_database_url  # noqa: E402
from routers import alerts, analysis, assets, auth, chat, cve, dashboard, logs, mitre, report, system  # noqa: E402
from services.alert_service import create_default_rules  # noqa: E402
from services.app_settings import get_app_settings  # noqa: E402
from services.correlation_engine import run_correlation_sweep  # noqa: E402
from services.incident_ops import run_incident_lifecycle_sweep  # noqa: E402
from services.log_collector import start_real_log_collector  # noqa: E402
from services.log_seed import seed_demo_attacks  # noqa: E402
from services.retention_manager import enforce_retention_policies  # noqa: E402
from services.threat_intel_ingestion import ingest_all  # noqa: E402
from state import metrics  # noqa: E402

logger = logging.getLogger("threatlens")

scheduler = BackgroundScheduler(job_defaults={"coalesce": True, "max_instances": 1, "misfire_grace_time": 120})


# ── Scheduled jobs ───────────────────────────────────────────────────────────
def _with_session(fn):
    db = SessionLocal()
    try:
        return fn(db)
    finally:
        db.close()


def _job_correlation():
    findings = run_correlation_sweep()
    metrics["last_correlation_sweep"] = datetime.utcnow().isoformat()
    metrics["last_correlation_findings"] = len(findings)


def _job_intel_refresh(force: bool = False):
    if not force and not get_app_settings().get("feeds", {}).get("threat_intel_auto_refresh", True):
        return
    try:
        ingest_all()
        metrics["last_intel_refresh"] = datetime.utcnow().isoformat()
    except Exception:
        logger.exception("Threat intel refresh failed")


def _job_retention():
    _with_session(enforce_retention_policies)
    metrics["last_retention_run"] = datetime.utcnow().isoformat()


def _job_lifecycle():
    _with_session(run_incident_lifecycle_sweep)
    metrics["last_incident_lifecycle_run"] = datetime.utcnow().isoformat()


# ── Lifespan ─────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    metrics["start_time"] = datetime.utcnow()
    logger.info("Starting ThreatLens %s (%s) — database: %s", settings.APP_VERSION, settings.ENVIRONMENT, safe_database_url())

    if settings.uses_default_jwt_secret:
        if settings.is_production:
            raise RuntimeError("JWT_SECRET must be set to a strong random value when ENVIRONMENT=production")
        logger.warning("JWT_SECRET is using the development default — set it in .env before deploying")

    init_db()
    db = SessionLocal()
    try:
        create_default_rules(db)
        seed_demo_attacks(db)
    except Exception:
        logger.exception("Startup seeding failed (continuing)")
    finally:
        db.close()

    if settings.INTEL_INGEST_ON_STARTUP:
        # Never block startup on third-party feeds.
        threading.Thread(target=_job_intel_refresh, kwargs={"force": True}, daemon=True, name="intel-bootstrap").start()

    if settings.ENABLE_SCHEDULER:
        interval = int(get_app_settings().get("feeds", {}).get("refresh_interval_minutes", 60))
        scheduler.add_job(_job_correlation, "interval", minutes=5, id="correlation_sweep", replace_existing=True)
        scheduler.add_job(_job_intel_refresh, "interval", minutes=max(interval, 15), id="intel_refresh", replace_existing=True)
        scheduler.add_job(_job_retention, "interval", minutes=30, id="retention_sweep", replace_existing=True)
        scheduler.add_job(_job_lifecycle, "interval", minutes=20, id="incident_lifecycle", replace_existing=True)
        scheduler.start()
        logger.info("Background scheduler started (correlation 5m, intel %sm, retention 30m, lifecycle 20m)", max(interval, 15))

    start_real_log_collector()
    yield

    if scheduler.running:
        scheduler.shutdown(wait=False)
    logger.info("ThreatLens shut down cleanly")


# ── Application ──────────────────────────────────────────────────────────────
app = FastAPI(
    title="ThreatLens API",
    version=settings.APP_VERSION,
    description=(
        "AI-powered security operations platform: hybrid log parsing, multi-rule detection, "
        "campaign correlation, threat intelligence, SOAR automation and an AI SOC copilot."
    ),
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(GZipMiddleware, minimum_size=1024)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Request-ID"],
    expose_headers=["X-Request-ID"],
)


@app.middleware("http")
async def request_context(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex[:16]
    token = request_id_ctx.set(request_id)
    metrics["requests_total"] += 1
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        metrics["requests_errors"] += 1
        raise
    finally:
        duration = time.perf_counter() - started
        if duration > 5:
            logger.warning("Slow request %s %s took %.1fs", request.method, request.url.path, duration)
        request_id_ctx.reset(token)
    if response.status_code >= 500:
        metrics["requests_errors"] += 1
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = response.headers.get("Cache-Control", "no-store")
    return response


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    # Only return type/location/message — never echo submitted input (e.g. passwords) back.
    errors = [
        {"type": e.get("type"), "loc": list(e.get("loc", ())), "msg": str(e.get("msg", "")).removeprefix("Value error, ")}
        for e in exc.errors()
    ]
    return JSONResponse(status_code=422, content={"detail": errors, "request_id": request_id_ctx.get()})


@app.exception_handler(Exception)
async def unhandled_error_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "request_id": request_id_ctx.get()},
    )


# ── Routes ───────────────────────────────────────────────────────────────────
API = "/api/v1"
protected = [Depends(get_current_user)]

app.include_router(auth.router, prefix=f"{API}/auth", tags=["Authentication"])
app.include_router(logs.public_router, prefix=f"{API}/logs", tags=["Log Ingestion"])  # JWT or X-API-Key
app.include_router(logs.router, prefix=f"{API}/logs", tags=["Log Ingestion"])
app.include_router(analysis.router, prefix=f"{API}/analysis", tags=["Threat Analysis"], dependencies=protected)
app.include_router(mitre.router, prefix=f"{API}/mitre", tags=["MITRE ATT&CK"], dependencies=protected)
app.include_router(cve.router, prefix=f"{API}/cve", tags=["CVE Lookup"], dependencies=protected)
app.include_router(dashboard.router, prefix=f"{API}/dashboard", tags=["Dashboard & Incidents"], dependencies=protected)
app.include_router(chat.router, prefix=f"{API}/chat", tags=["AI Copilot"], dependencies=protected)
app.include_router(alerts.router, prefix=f"{API}/alerts", tags=["SOAR & Threat Intel"], dependencies=protected)
app.include_router(report.router, prefix=f"{API}/reports", tags=["SOC Reports"], dependencies=protected)
app.include_router(assets.router, prefix=f"{API}/assets", tags=["Monitored Assets"], dependencies=protected)
app.include_router(system.router, prefix=f"{API}/system", tags=["System"], dependencies=protected)


@app.get("/", include_in_schema=False)
def root():
    return {
        "platform": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "operational",
        "docs": "/docs",
        "health": "/health",
        "readiness": "/ready",
    }


@app.get("/health", tags=["System"])
def health():
    """Liveness probe — the process is up. Does not touch dependencies."""
    uptime = str(datetime.utcnow() - metrics["start_time"]).split(".")[0] if metrics["start_time"] else None
    return {
        "status": "healthy",
        "version": settings.APP_VERSION,
        "uptime": uptime,
        "scheduler_running": scheduler.running,
        "metrics": {
            "requests_total": metrics["requests_total"],
            "requests_errors": metrics["requests_errors"],
            "error_rate": f"{(metrics['requests_errors'] / max(metrics['requests_total'], 1)) * 100:.2f}%",
            "last_correlation_sweep": metrics["last_correlation_sweep"],
            "last_correlation_findings": metrics["last_correlation_findings"],
            "last_intel_refresh": metrics["last_intel_refresh"],
            "last_retention_run": metrics["last_retention_run"],
            "last_incident_lifecycle_run": metrics["last_incident_lifecycle_run"],
        },
    }


@app.get("/ready", tags=["System"])
def ready():
    """Readiness probe — the database is reachable."""
    if check_database():
        return {"status": "ready", "database": "ok"}
    return JSONResponse(status_code=503, content={"status": "not_ready", "database": "unreachable"})
