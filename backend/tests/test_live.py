"""Tests for the live layer: event bus, stream auth, simulator scenarios, map/executive/matrix endpoints."""
import pytest

from core import events
from models.database import SessionLocal
from models.db_models import Incident
from services import simulator as sim
from services.pipeline import process_log


# ── Event bus ───────────────────────────────────────────────────────────────
def test_events_publish_only_after_commit(client):
    before = len(events.recent(200))
    db = SessionLocal()
    try:
        events.queue_event(db, "test", {"n": 1})
        db.rollback()
        assert len(events.recent(200)) == before  # dropped on rollback
        events.queue_event(db, "test", {"n": 2})
        db.commit()
    finally:
        db.close()
    last = events.recent(1)[0]
    assert last["type"] == "test" and last["data"] == {"n": 2}


def test_pipeline_emits_log_and_incident_events(client):
    db = SessionLocal()
    try:
        process_log(db, "cmd.exe /c vssadmin.exe delete shadows /all /quiet src_ip=198.51.100.77", source="test_events")
        db.commit()
    finally:
        db.close()
    types = [e["type"] for e in events.recent(20)]
    assert "log" in types and "incident" in types
    incident = next(e for e in reversed(events.recent(50)) if e["type"] == "incident")
    assert incident["data"]["threat_type"] == "Ransomware Activity"
    assert incident["data"]["risk_level"] == "CRITICAL"


def test_stream_tickets_are_single_use(client, analyst_headers):
    assert client.post("/api/v1/stream/ticket").status_code == 401
    ticket = client.post("/api/v1/stream/ticket", headers=analyst_headers).json()["ticket"]
    assert events.redeem_ticket(ticket) is not None
    assert events.redeem_ticket(ticket) is None  # cannot be replayed
    assert client.get("/api/v1/stream/events?ticket=not-a-valid-ticket").status_code == 401


# ── Simulator ───────────────────────────────────────────────────────────────
@pytest.mark.parametrize("scenario_id,expected", [
    ("ransomware", {"Ransomware Activity", "Credential Dumping Attempt", "Lateral Movement Detected", "Event Log Cleared"}),
    ("web_attack", {"SQL Injection Attempt", "Web Shell Upload Attempt", "Command and Control Communication"}),
    ("insider", {"Malicious Office Macro Execution", "Data Exfiltration Attempt", "Persistence Mechanism Detected"}),
    ("credential_stuffing", {"Successful Login After Brute Force"}),
])
def test_scenarios_produce_expected_detections(client, scenario_id, expected):
    result = sim.run_scenario_sync(scenario_id)
    detected = {d["threat"] for d in result["detections"]}
    assert expected <= detected, detected - expected


def test_credential_stuffing_triggers_distributed_correlation(client):
    db = SessionLocal()
    try:
        assert db.query(Incident).filter(Incident.threat_type == "Distributed Brute Force").count() >= 1
    finally:
        db.close()


def test_benign_traffic_creates_no_incidents():
    from services.detector import evaluate_rules
    from services.parser import parse_log

    for _ in range(300):
        line = sim._benign_event()
        assert not evaluate_rules(parse_log(line)), line


def test_demo_controls_require_writer(client, viewer_headers, analyst_headers):
    status = client.get("/api/v1/demo/status", headers=viewer_headers).json()
    assert {c["id"] for c in status["catalog"]} == set(sim.SCENARIOS)
    assert client.post("/api/v1/demo/scenarios/ransomware/launch", headers=viewer_headers).status_code == 403
    assert client.post("/api/v1/demo/traffic/start", json={"rate": "normal"}, headers=viewer_headers).status_code == 403
    assert client.post("/api/v1/demo/scenarios/nope/launch", headers=analyst_headers).status_code == 404
    assert client.post("/api/v1/demo/traffic/start", json={"rate": "ludicrous"}, headers=analyst_headers).status_code == 422


# ── Map / executive / ATT&CK matrix ─────────────────────────────────────────
def test_threat_map_geolocates_external_attackers(client, analyst_headers, monkeypatch):
    import services.ip_intel_service as intel

    db = SessionLocal()
    try:
        process_log(db, "edge-fw01 kernel: [DROP] IN=eth0 SRC=8.8.4.4 DST=203.0.113.10 PROTO=TCP DPT=3389 BLOCKED", source="test_map")
        db.commit()
    finally:
        db.close()
    monkeypatch.setattr(intel, "geolocate_many", lambda ips: {ip: {"lat": 37.4, "lon": -122.1, "city": "Mountain View",
                                                                    "country": "United States", "country_code": "US"} for ip in ips})
    monkeypatch.setattr(intel, "get_hq_location", lambda: {"name": "HQ", "lat": 12.97, "lon": 77.59, "source": "test"})
    data = client.get("/api/v1/dashboard/threat-map?hours=24", headers=analyst_headers).json()
    assert data["hq"]["name"] == "HQ"
    point = next(p for p in data["points"] if p["ip"] == "8.8.4.4")
    assert point["country"] == "United States" and point["alerts"] >= 1
    assert all(not p["ip"].startswith("10.") for p in data["points"])


def test_executive_metrics(client, analyst_headers):
    data = client.get("/api/v1/dashboard/executive?hours=168", headers=analyst_headers).json()
    for key in ("incidents", "alerts", "noise_reduction_pct", "sla_compliance_pct", "automation_rate_pct", "performance"):
        assert key in data
    assert data["alerts"] >= data["incidents"] > 0
    assert data["performance"]["pipeline_latency_ms"]["samples"] > 0


def test_attack_matrix(client, analyst_headers):
    data = client.get("/api/v1/mitre/matrix", headers=analyst_headers).json()
    assert data["detectable_techniques"] >= 15 and data["rules"] >= 19
    ids = {t["id"] for col in data["matrix"] for t in col["techniques"]}
    assert {"T1486", "T1003", "T1110"} <= ids


def test_demo_viewer_is_read_only(client, monkeypatch):
    from config import settings
    from services.log_seed import ensure_demo_viewer

    monkeypatch.setattr(settings, "DEMO_VIEWER_PASSWORD", "JudgeDemo2026!")
    db = SessionLocal()
    try:
        ensure_demo_viewer(db)
    finally:
        db.close()
    login = client.post("/api/v1/auth/login", json={"login": "judge", "password": "JudgeDemo2026!"})
    assert login.status_code == 200 and login.json()["user"]["role"] == "viewer"
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    assert client.get("/api/v1/dashboard/stats", headers=headers).status_code == 200
    assert client.post("/api/v1/analysis/analyze", json={"log": "x"}, headers=headers).status_code == 403


# ── Regressions found by the real attack lab ────────────────────────────────
def test_scanner_urls_do_not_trigger_host_rules():
    from services.detector import evaluate_rules
    from services.parser import parse_log

    line = ('172.20.0.3 - - [24/Nov/2026:15:33:20 +0000] "GET /ftp/upload/beacon.php HTTP/1.1" 404 153 "-" '
            '"Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"')
    assert {r["name"] for r in evaluate_rules(parse_log(line))} == {"Reconnaissance Activity"}


def test_soar_history_survives_grouping_and_reruns_on_escalation(client):
    db = SessionLocal()
    try:
        ip = "198.51.100.199"
        for _ in range(3):  # third failure opens a Brute Force case
            process_log(db, f"sshd[1]: Failed password for admin from {ip} port 22 ssh2", source="test_soar")
        db.commit()
        incident = db.query(Incident).filter(Incident.source_ip == ip, Incident.threat_type == "Brute Force Attack").one()
        fired = {a["rule"] for a in incident.soc_summary["soar_actions"]}
        assert "Brute Force Auto-Block" in fired
        for _ in range(4):  # grouped repeats must not wipe the SOAR history
            process_log(db, f"sshd[1]: Failed password for admin from {ip} port 22 ssh2", source="test_soar")
        db.commit()
        db.refresh(incident)
        assert incident.alert_count >= 5
        rules = [a["rule"] for a in incident.soc_summary["soar_actions"]]
        assert "Brute Force Auto-Block" in rules and len(rules) == len(set(rules))  # no duplicate firing
    finally:
        db.close()
