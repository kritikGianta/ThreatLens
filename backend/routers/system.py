"""System status: integration configuration, scheduler state and platform metadata."""

from fastapi import APIRouter

from config import settings
from core.llm import llm_enabled
from models.database import IS_SQLITE, check_database
from services.log_collector import get_collector_status
from services.mitre_service import technique_count
from state import metrics

router = APIRouter()

INTEGRATIONS = [
    ("groq_llm", "Groq LLM", "AI SOC summaries, Copilot answers and LLM log-parsing fallback", "GROQ_API_KEY"),
    ("virustotal", "VirusTotal", "IP reputation scoring", "VT_API_KEY"),
    ("nvd_cve", "NIST NVD", "Higher rate limit for CVE enrichment (works without a key at 5 req/30s)", "NVD_API_KEY"),
    ("abusech", "abuse.ch", "URLhaus and ThreatFox threat-intel feeds", "ABUSECH_AUTH_KEY"),
    ("ipinfo", "IPinfo", "Fallback IP geolocation", "IPINFO_TOKEN"),
    ("opencage", "OpenCage", "Geolocation enrichment (address, timezone)", "OPENCAGE_API_KEY"),
    ("smtp", "SMTP", "SOAR email alert actions", "SMTP_USER / SMTP_PASSWORD"),
    ("ingest_api_key", "Ingest API key", "Machine-to-machine log forwarding to /api/v1/logs/webhook", "INGEST_API_KEY"),
]


@router.get("/status")
def system_status():
    configured = settings.integration_status()
    return {
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "database": {"engine": "sqlite" if IS_SQLITE else "postgresql", "reachable": check_database()},
        "llm": {"enabled": llm_enabled(), "model": settings.GROQ_MODEL if llm_enabled() else None},
        "mitre_techniques_loaded": technique_count(),
        "integrations": [
            {"key": key, "name": name, "purpose": purpose, "env_var": env, "configured": configured.get(key, False)}
            for key, name, purpose, env in INTEGRATIONS
        ],
        "collector": get_collector_status(),
        "signup_open": settings.ALLOW_PUBLIC_SIGNUP,
        "security_warnings": (
            ["JWT_SECRET is using the development default"] if settings.uses_default_jwt_secret else []
        ),
        "jobs": {k: v for k, v in metrics.items() if k.startswith("last_")},
    }
