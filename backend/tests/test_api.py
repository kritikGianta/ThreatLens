"""
API tests mirroring FEATURE_VALIDATION_GUIDE.md and TESTING_GUIDE.md.
"""
import time

MIMIKATZ = "2024-05-05 10:00:00 PROCESS_CREATE process=mimikatz.exe user=jdoe src_ip=203.0.113.99 event_id=4688 host=PROD-DB-01"
PSEXEC = "2024-05-05 10:15:00 SERVICE_START service=psexecsvc.exe src_ip=203.0.113.99 event_id=7045"
POWERSHELL = "Jan 15 11:45:23 server01 PowerShell[1234]: Invoke-Expression -EncodedCommand dABlAHMAdA== user=SYSTEM event_id=4104"


# ── Platform ────────────────────────────────────────────────────────────────
def test_health_and_ready(client):
    assert client.get("/health").json()["status"] == "healthy"
    assert client.get("/ready").json()["database"] == "ok"
    assert "X-Request-ID" in client.get("/health").headers


# ── Authentication (TESTING_GUIDE §2) ────────────────────────────────────────
def test_protected_routes_require_auth(client):
    assert client.get("/api/v1/dashboard/stats").status_code == 401
    assert client.get("/api/v1/dashboard/stats", headers={"Authorization": "Bearer junk"}).status_code == 401


def test_first_user_is_admin(client, admin_tokens):
    assert admin_tokens["user"]["role"] == "admin"
    assert admin_tokens["refresh_token"]


def test_login_refresh_and_profile(client, admin_headers):
    login = client.post("/api/v1/auth/login", json={"login": "ADMIN@example.com", "password": "SecurePass123!"})
    assert login.status_code == 200
    refreshed = client.post("/api/v1/auth/refresh", json={"refresh_token": login.json()["refresh_token"]})
    assert refreshed.status_code == 200
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {refreshed.json()['access_token']}"})
    assert me.json()["user"]["username"] == "admin"
    # An access token must not be accepted as a refresh token
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": login.json()["access_token"]}).status_code == 401


def test_invalid_login(client, admin_headers):
    response = client.post("/api/v1/auth/login", json={"login": "admin", "password": "WrongPass999!"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"


def test_signup_validation(client, admin_headers):
    weak = client.post("/api/v1/auth/signup", json={"email": "x@example.com", "username": "x_user", "password": "short"})
    assert weak.status_code == 422
    bad_name = client.post("/api/v1/auth/signup", json={"email": "y@example.com", "username": "a b!", "password": "SecurePass123!"})
    assert bad_name.status_code == 422
    bad_email = client.post("/api/v1/auth/signup", json={"email": "not-an-email", "username": "zuser", "password": "SecurePass123!"})
    assert bad_email.status_code == 422


def test_second_user_is_analyst(client, analyst_headers):
    assert client.get("/api/v1/auth/me", headers=analyst_headers).json()["user"]["role"] == "analyst"
    assert client.get("/api/v1/auth/users", headers=analyst_headers).status_code == 403


def test_viewer_is_read_only(client, viewer_headers):
    assert client.get("/api/v1/dashboard/stats", headers=viewer_headers).status_code == 200
    assert client.post("/api/v1/analysis/analyze", json={"log": MIMIKATZ}, headers=viewer_headers).status_code == 403
    assert client.post("/api/v1/alerts/blocklist", json={"ip_address": "198.51.100.1"}, headers=viewer_headers).status_code == 403


# ── Threat Studio (FEATURE_VALIDATION Phase 1) ───────────────────────────────
def test_analyze_credential_dumping(client, analyst_headers):
    data = client.post("/api/v1/analysis/analyze", json={"log": MIMIKATZ}, headers=analyst_headers).json()
    assert data["detection_result"]["threat_detected"] == "Credential Dumping Attempt"
    assert data["mitre_details"]["id"] == "T1003"
    assert "Credential Access" in data["mitre_details"]["tactics"]
    assert data["risk_assessment"]["risk_score"] >= 80
    assert data["risk_assessment"]["risk_level"] in ("HIGH", "CRITICAL")
    assert data["incident_id"]
    summary = data["soc_summary"]
    assert summary["executive_summary"] and summary["recommended_actions"]
    assert summary["generated_by"].startswith("rule-engine")  # no GROQ key in tests


def test_analyze_powershell(client, analyst_headers):
    data = client.post("/api/v1/analysis/analyze", json={"log": POWERSHELL}, headers=analyst_headers).json()
    assert data["parsed_log"]["log_type"] == "windows"
    assert data["detection_result"]["threat_detected"] == "Suspicious PowerShell Execution"
    assert data["risk_assessment"]["risk_factors"]


def test_benign_log_creates_no_incident(client, analyst_headers):
    data = client.post("/api/v1/analysis/analyze", json={"log": "sshd[9]: Accepted password for jsmith from 192.168.1.10 port 22 ssh2"},
                       headers=analyst_headers).json()
    assert data["detection_result"]["threat_detected"] is None
    assert data["incident_id"] is None


# ── Campaigns (Phase 2) ──────────────────────────────────────────────────────
def test_campaign_links_stages(client, analyst_headers):
    client.post("/api/v1/analysis/analyze", json={"log": PSEXEC}, headers=analyst_headers)
    campaigns = client.get("/api/v1/dashboard/campaigns", headers=analyst_headers).json()["campaigns"]
    campaign = next(c for c in campaigns if "203.0.113.99" in c["source_ips"])
    assert {"Credential Access", "Lateral Movement"} <= set(campaign["stages"])


# ── Investigation (Phase 3) ──────────────────────────────────────────────────
def test_investigate_and_timeline(client, analyst_headers):
    dossier = client.get("/api/v1/dashboard/investigate/203.0.113.99", headers=analyst_headers).json()
    assert dossier["incident_count"] >= 2 and dossier["log_count"] >= 2 and dossier["campaigns"]
    timeline = client.get("/api/v1/dashboard/timeline/203.0.113.99", headers=analyst_headers).json()
    stamps = [e["timestamp"] for e in timeline["timeline"]]
    assert stamps == sorted(stamps) and timeline["campaign"]


# ── SOAR (Phase 4) ───────────────────────────────────────────────────────────
def test_soar_rule_auto_blocks(client, analyst_headers):
    rule = client.post("/api/v1/alerts/rules", headers=analyst_headers, json={
        "name": "Auto-block Critical", "condition_type": "risk_level", "condition_value": "critical", "action_type": "block_ip",
    })
    assert rule.status_code == 201
    bad = client.post("/api/v1/alerts/rules", headers=analyst_headers, json={
        "name": "bad", "condition_type": "nope", "condition_value": "x", "action_type": "block_ip",
    })
    assert bad.status_code == 422

    log = MIMIKATZ.replace("203.0.113.99", "198.51.100.66")
    result = client.post("/api/v1/analysis/analyze", json={"log": log}, headers=analyst_headers).json()
    assert result["risk_assessment"]["risk_level"] == "CRITICAL"
    blocked = client.get("/api/v1/alerts/blocklist", headers=analyst_headers).json()["blocked_ips"]
    assert any(b["ip_address"] == "198.51.100.66" for b in blocked)
    export = client.get("/api/v1/alerts/blocklist/export?fmt=txt", headers=analyst_headers)
    assert "198.51.100.66" in export.text


def test_manual_block_validation(client, analyst_headers):
    assert client.post("/api/v1/alerts/blocklist", json={"ip_address": "not-an-ip"}, headers=analyst_headers).status_code == 422
    first = client.post("/api/v1/alerts/blocklist", json={"ip_address": "192.0.2.200"}, headers=analyst_headers)
    assert first.status_code == 201
    assert client.post("/api/v1/alerts/blocklist", json={"ip_address": "192.0.2.200"}, headers=analyst_headers).status_code == 409
    assert client.delete(f"/api/v1/alerts/blocklist/{first.json()['id']}", headers=analyst_headers).status_code == 200


# ── Incidents / case management ──────────────────────────────────────────────
def test_incident_workflow_and_404(client, analyst_headers):
    incidents = client.get("/api/v1/dashboard/incidents?limit=5", headers=analyst_headers).json()["incidents"]
    incident_id = incidents[0]["id"]
    updated = client.put(f"/api/v1/dashboard/incidents/{incident_id}", headers=analyst_headers,
                         json={"status": "Investigating", "owner": "analyst1", "analyst_notes": "Looking into it"})
    assert updated.status_code == 200
    assert updated.json()["incident"]["workflow_state"] == "Investigate"
    invalid = client.put(f"/api/v1/dashboard/incidents/{incident_id}", headers=analyst_headers, json={"status": "Bogus"})
    assert invalid.status_code == 422
    assert client.get("/api/v1/dashboard/incidents/999999", headers=analyst_headers).status_code == 404
    detail = client.get(f"/api/v1/dashboard/incidents/{incident_id}/detail", headers=analyst_headers).json()
    assert detail["related_logs"]
    report = client.get(f"/api/v1/reports/incident/{incident_id}", headers=analyst_headers)
    assert report.status_code == 200


def test_dashboard_stats_shape(client, analyst_headers):
    stats = client.get("/api/v1/dashboard/stats", headers=analyst_headers).json()
    for key in ("total_logs_ingested", "total_incidents", "severity_breakdown", "incident_sources", "log_sources",
                "top_threat_types", "mitre_technique_distribution", "activity_24h"):
        assert key in stats
    assert len(stats["activity_24h"]) == 24
    assert stats["log_sources"].get("manual_analysis", 0) >= 3


# ── Ingestion channels ───────────────────────────────────────────────────────
def test_webhook_with_api_key(client):
    payload = {"logs": ["sshd[1]: Failed password for root from 198.51.100.200 port 22 ssh2"] * 4, "source": "filebeat-prod"}
    assert client.post("/api/v1/logs/webhook", json=payload).status_code == 401
    assert client.post("/api/v1/logs/webhook", json=payload, headers={"X-API-Key": "wrong"}).status_code == 401
    response = client.post("/api/v1/logs/webhook", json=payload, headers={"X-API-Key": "test-ingest-key"})
    assert response.status_code == 200
    body = response.json()
    assert body["logs_processed"] == 4 and body["incidents_created"] == 1  # grouped brute-force case


def test_bulk_ingest_job(client, analyst_headers):
    logs = [f"sshd[{i}]: Failed password for admin from 198.51.100.150 port 22 ssh2" for i in range(12)] + [""]
    job = client.post("/api/v1/analysis/ingest", json={"logs": logs}, headers=analyst_headers)
    assert job.status_code == 202
    job_id = job.json()["job_id"]
    for _ in range(50):
        status = client.get(f"/api/v1/analysis/ingest/status/{job_id}", headers=analyst_headers).json()
        if status["status"] != "processing":
            break
        time.sleep(0.2)
    assert status["status"] == "completed"
    assert status["logs_processed"] == 12 and status["errors"] == 0
    assert client.get("/api/v1/analysis/ingest/status/nope", headers=analyst_headers).status_code == 404


# ── Copilot (Phase 6) ────────────────────────────────────────────────────────
def test_copilot_answers_from_data_without_llm(client, analyst_headers, admin_headers):
    response = client.post("/api/v1/chat/ask", headers=analyst_headers,
                           json={"message": "Summarize the campaign for 203.0.113.99"}).json()
    assert "203.0.113.99" in response["response"]
    assert response["generated_by"] == "rule-engine"
    history = client.get(f"/api/v1/chat/history?session_id={response['session_id']}", headers=analyst_headers).json()
    assert len(history["messages"]) == 2
    # history is private to the user who created it
    other = client.get(f"/api/v1/chat/history?session_id={response['session_id']}", headers=admin_headers).json()
    assert other["messages"] == []


# ── MITRE / Threat intel ─────────────────────────────────────────────────────
def test_mitre_endpoints(client, analyst_headers):
    tech = client.get("/api/v1/mitre/technique/t1110", headers=analyst_headers).json()
    assert tech["name"] == "Brute Force" and tech["sub_techniques"]
    assert client.get("/api/v1/mitre/technique/T0000", headers=analyst_headers).status_code == 404
    results = client.get("/api/v1/mitre/search?q=credential", headers=analyst_headers).json()["results"]
    assert results
    assert client.get("/api/v1/mitre/tactics", headers=analyst_headers).json()["tactics"]


def test_intel_iocs_filtering(client, analyst_headers):
    data = client.get("/api/v1/alerts/intel/iocs?source=CISA_KEV&limit=5", headers=analyst_headers).json()
    assert "total" in data and isinstance(data["iocs"], list)
    stats = client.get("/api/v1/alerts/intel/stats", headers=analyst_headers).json()
    assert {f["source"] for f in stats["feeds"]} >= {"CISA_KEV", "FEODO_TRACKER", "URLHAUS"}


# ── Settings & audit ─────────────────────────────────────────────────────────
def test_settings_admin_only_and_validated(client, admin_headers, analyst_headers):
    assert client.put("/api/v1/dashboard/settings", json={"demo_mode": False}, headers=analyst_headers).status_code == 403
    bad = client.put("/api/v1/dashboard/settings", headers=admin_headers,
                     json={"detection": {"risk_thresholds": {"critical": 10, "high": 50, "medium": 30}}})
    assert bad.status_code == 422
    good = client.put("/api/v1/dashboard/settings", headers=admin_headers, json={"retention": {"max_logs": 50000}})
    assert good.status_code == 200 and good.json()["retention"]["max_logs"] == 50000


def test_audit_log_records_actions(client, admin_headers):
    entries = client.get("/api/v1/dashboard/audit-logs?limit=200", headers=admin_headers).json()["entries"]
    actions = {e["action"] for e in entries}
    assert {"auth.signup", "incident.update", "soar.rule_create", "blocklist.add", "settings.update"} <= actions


def test_system_status(client, admin_headers):
    status = client.get("/api/v1/system/status", headers=admin_headers).json()
    assert status["database"]["reachable"] is True
    assert any(i["env_var"] == "GROQ_API_KEY" and i["configured"] is False for i in status["integrations"])
