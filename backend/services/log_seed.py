"""
ThreatLens demo data seeder.

On first start-up with an empty database (and SEED_DEMO_DATA=true) a realistic,
multi-stage attack scenario is replayed through the real analysis pipeline with
historical timestamps, so every dashboard has meaningful data immediately.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta

from sqlalchemy import func as sqlfunc
from sqlalchemy.orm import Session

from config import settings
from models.db_models import LogEntry
from services.pipeline import process_log

logger = logging.getLogger("threatlens.seeder")


def seed_demo_attacks(db: Session, force: bool = False) -> dict:
    """Replay the demo scenario if the logs table is empty (or force=True)."""
    if not settings.SEED_DEMO_DATA and not force:
        logger.info("Demo seeding disabled (SEED_DEMO_DATA=false)")
        return {"seeded": False, "reason": "disabled"}

    count = db.query(sqlfunc.count(LogEntry.id)).scalar() or 0
    if count > 0 and not force:
        logger.info("Database already has %d logs — skipping demo seed", count)
        return {"seeded": False, "reason": "database not empty"}

    logger.info("Seeding simulated multi-stage attack scenario...")
    injected = incidents = 0
    for ts, raw_log in _build_attack_scenario(datetime.utcnow()):
        try:
            with db.begin_nested():
                result = process_log(db, raw_log, source="demo_seed", event_time=ts, summary_extra={"seeded": True})
            injected += 1
            incidents += 1 if result["incident_created"] else 0
        except Exception as exc:
            logger.warning("Seeder failed on a log line: %s", exc)
    db.commit()
    logger.info("Demo seed complete — %d logs, %d incidents", injected, incidents)
    return {"seeded": True, "logs": injected, "incidents": incidents}


def _build_attack_scenario(now: datetime) -> list:
    """
    Builds a realistic multi-stage APT attack scenario.
    Returns list of (timestamp, raw_log_string) tuples, sorted chronologically.
    
    Scenario 1: External Brute Force → Credential Dump → Lateral Movement → Exfiltration
    Scenario 2: Port Scanning → Blocked
    Scenario 3: C2 Beacon Activity
    Plus benign background noise
    """
    logs = []

    # ──────────────────────────────────────────────
    # SCENARIO 1: Full APT Kill Chain (attacker 203.0.113.45)
    # ──────────────────────────────────────────────
    atk1 = "203.0.113.45"  # RFC 5737 documentation range
    user1 = "admin"

    # Phase 1: Reconnaissance (nmap scan — 72h ago)
    t = now - timedelta(hours=72)
    logs.append((t, f"{t.strftime('%b %d %H:%M:%S')} fw-main kernel: [DROP] IN=eth0 SRC={atk1} DST=10.0.0.5 PROTO=TCP DPT=22 nmap scan detected"))

    # Phase 2: Brute Force (spread across 48h — triggers "Slow Brute Force")
    for i in range(8):
        t = now - timedelta(hours=48 - (i * 5))
        logs.append((t, f"{t.strftime('%b %d %H:%M:%S')} auth-server sshd[{1000+i}]: Failed password for {user1} from {atk1} port 54322 ssh2"))

    # Phase 3: Successful Login After Brute Force (2h ago — CRITICAL)
    t = now - timedelta(hours=2)
    logs.append((t, f"{t.strftime('%b %d %H:%M:%S')} auth-server sshd[1200]: Accepted password for {user1} from {atk1} port 54322 ssh2"))

    # Phase 4: Credential Dumping (90 min ago)
    t = now - timedelta(minutes=90)
    logs.append((t, f'{t.strftime("%Y-%m-%d %H:%M:%S")} WinEventLog:Security: 4688: Process created by {user1}: "procdump.exe -ma lsass.exe lsass.dmp" Source Network Address: {atk1} Host=SRV-DB-01'))

    # Phase 5: Lateral Movement (60 min ago)
    t = now - timedelta(minutes=60)
    logs.append((t, f'{t.strftime("%Y-%m-%d %H:%M:%S")} WinEventLog:Security: 4688: Process created by {user1}: "psexec.exe \\\\dc01 -u {user1} cmd" Source Network Address: {atk1} Host=SRV-DB-01'))

    # Phase 6: Persistence (45 min ago)
    t = now - timedelta(minutes=45)
    logs.append((t, f'{t.strftime("%Y-%m-%d %H:%M:%S")} WinEventLog:Security: 4688: Process created: "schtasks /create /tn WindowsUpdate /tr C:\\Temp\\backdoor.exe /sc onlogon" Source Network Address: {atk1} Host=DC01'))

    # Phase 7: Defense Evasion — clearing logs (30 min ago)
    t = now - timedelta(minutes=30)
    logs.append((t, f'{t.strftime("%Y-%m-%d %H:%M:%S")} WinEventLog:Security: 1102: The audit log was cleared. Subject: {user1} Source Network Address: {atk1} Host=DC01'))

    # Phase 8: Data Exfiltration (15 min ago)
    t = now - timedelta(minutes=15)
    logs.append((t, f'{t.strftime("%b %d %H:%M:%S")} proxy-server squid[823]: {atk1} POST https://storage.external-cloud.io/upload - curl/7.68.0 send transfer'))

    # ──────────────────────────────────────────────
    # SCENARIO 2: High-Speed Port Scanning (blocked — 198.51.100.23)
    # ──────────────────────────────────────────────
    atk2 = "198.51.100.23"  # RFC 5737 documentation range
    for i, port in enumerate([445, 3389]):  # 2 scans — enough to show detection, not flood
        t = now - timedelta(minutes=10) + timedelta(seconds=i)
        logs.append((t, f"{t.strftime('%b %d %H:%M:%S')} fw-main kernel: [DROP] IN=eth0 SRC={atk2} DST=10.0.0.5 PROTO=TCP DPT={port} BLOCKED"))

    # ──────────────────────────────────────────────
    # SCENARIO 3: C2 Beacon (internal compromised host)
    # ──────────────────────────────────────────────
    t = now - timedelta(minutes=20)
    logs.append((t, f'{t.strftime("%Y-%m-%d %H:%M:%S")} WinEventLog:Security: 4688: Process created: "rundll32.exe beacon.dll,Start" reverse shell callback C2 src_ip=10.0.4.17 Host=WS-FIN-07'))

    # ──────────────────────────────────────────────
    # SCENARIO 4: Privilege Escalation Attempt (failed)
    # ──────────────────────────────────────────────
    t = now - timedelta(minutes=55)
    logs.append((t, f"{t.strftime('%b %d %H:%M:%S')} linux-ws1 sudo: user2: failed to sudo runas root - privilege escalation denied ; Status: Failed"))

    # ──────────────────────────────────────────────
    # BENIGN NOISE (normal operations — keeps ratios realistic)
    # ──────────────────────────────────────────────
    benign_users = ["jsmith", "mwilson", "kpatel", "agarcia"]
    benign_ips = ["192.168.1.10", "192.168.1.25", "10.0.0.50", "172.16.0.100"]
    for i in range(15):
        t = now - timedelta(hours=i * 3)
        u = benign_users[i % len(benign_users)]
        ip = benign_ips[i % len(benign_ips)]
        logs.append((t, f"{t.strftime('%b %d %H:%M:%S')} auth-server sshd[{2000+i}]: Accepted password for {u} from {ip} port {50000+i} ssh2"))

    # Sort chronologically
    logs.sort(key=lambda x: x[0])
    return logs
