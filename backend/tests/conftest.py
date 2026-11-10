"""
Test configuration: an isolated SQLite database, no background jobs, no outbound
network calls (enrichment providers are stubbed).
"""
import os
import sys
import tempfile
from pathlib import Path

import pytest

_TMP = Path(tempfile.mkdtemp(prefix="threatlens-tests-"))
os.environ.update({
    "ENVIRONMENT": "test",
    "DATABASE_URL": "",
    "DB_BACKEND": "sqlite",
    "SQLITE_PATH": str(_TMP / "test.db"),
    "SEED_DEMO_DATA": "false",
    "ENABLE_SCHEDULER": "false",
    "INTEL_INGEST_ON_STARTUP": "false",
    "ENABLE_REAL_LOG_COLLECTOR": "false",
    "RATE_LIMIT_ENABLED": "false",
    "GROQ_API_KEY": "",
    "VT_API_KEY": "",
    "NVD_API_KEY": "",
    "INGEST_API_KEY": "test-ingest-key",
    "JWT_SECRET": "test-secret-not-for-production-0123456789",
    "LOG_LEVEL": "WARNING",
})
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
import services.pipeline as pipeline  # noqa: E402


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    monkeypatch.setattr(pipeline, "search_cves", lambda *_a, **_k: [])
    monkeypatch.setattr(
        pipeline, "enrich_ip",
        lambda ip: {"ip": ip, "geo": {"city": "Test", "country": "Test", "lat": None, "lon": None},
                    "reputation": {"malicious": 0, "suspicious": 0}, "risk_assessment": {"risk_score": 0}},
    )


@pytest.fixture(scope="session")
def client():
    with TestClient(main.app) as test_client:
        yield test_client


def _signup(client, username, email, password="SecurePass123!"):
    response = client.post("/api/v1/auth/signup", json={"email": email, "username": username, "password": password})
    if response.status_code == 409:
        response = client.post("/api/v1/auth/login", json={"login": username, "password": password})
    assert response.status_code in (200, 201), response.text
    return response.json()


@pytest.fixture(scope="session")
def admin_tokens(client):
    return _signup(client, "admin", "admin@example.com")


@pytest.fixture(scope="session")
def admin_headers(admin_tokens):
    return {"Authorization": f"Bearer {admin_tokens['access_token']}"}


@pytest.fixture(scope="session")
def analyst_headers(client, admin_headers):
    data = _signup(client, "analyst1", "analyst1@example.com")
    return {"Authorization": f"Bearer {data['access_token']}"}


@pytest.fixture(scope="session")
def viewer_headers(client, admin_headers):
    data = _signup(client, "viewer1", "viewer1@example.com")
    users = client.get("/api/v1/auth/users", headers=admin_headers).json()["users"]
    viewer_id = next(u["id"] for u in users if u["username"] == "viewer1")
    client.put(f"/api/v1/auth/users/{viewer_id}/role", json={"role": "viewer"}, headers=admin_headers)
    login = client.post("/api/v1/auth/login", json={"login": "viewer1", "password": "SecurePass123!"}).json()
    return {"Authorization": f"Bearer {login['access_token']}"}
