"""
ThreatLens lab log shipper — tails log files and forwards new lines to the ThreatLens webhook,
exactly like Filebeat/Fluent Bit would in production. Standard library only.
"""
import json
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ENDPOINT = os.environ.get("THREATLENS_URL", "http://backend:8000/api/v1/logs/webhook")
API_KEY = os.environ.get("INGEST_API_KEY", "")
LOG_DIR = Path(os.environ.get("LOG_DIR", "/var/log/lab"))
STATE_FILE = LOG_DIR / ".shipper-offsets.json"
FILES = {"auth.log": "lab-ssh", "access.log": "lab-web", "commands.log": "lab-shell"}
BATCH = 200
INTERVAL = 1.0


def log(msg: str) -> None:
    print(f"[shipper] {datetime.now(timezone.utc).strftime('%H:%M:%S')} {msg}", flush=True)


def load_offsets() -> dict:
    try:
        return json.loads(STATE_FILE.read_text())
    except (OSError, ValueError):
        return {}


def normalise(source: str, line: str) -> str:
    # sshd -E writes bare messages; give them the syslog shape SIEM parsers expect.
    if source == "lab-ssh" and "sshd" not in line:
        stamp = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
        return f"{stamp} lab-victim sshd[0]: {line}"
    return line


def post(source: str, lines: list) -> bool:
    body = json.dumps({"source": source, "logs": lines}).encode()
    request = urllib.request.Request(ENDPOINT, data=body, method="POST",
                                     headers={"Content-Type": "application/json", "X-API-Key": API_KEY})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            result = json.loads(response.read() or b"{}")
            log(f"{source}: shipped {len(lines)} lines → {result.get('incidents_created', 0)} new incidents")
            return True
    except urllib.error.HTTPError as exc:
        log(f"{source}: HTTP {exc.code} — {exc.read()[:200]!r}")
        return exc.code < 500 and exc.code != 401  # drop bad batches, retry on auth/server errors
    except (urllib.error.URLError, OSError) as exc:
        log(f"{source}: backend unreachable ({exc}); retrying")
        return False


def main() -> None:
    if not API_KEY:
        log("INGEST_API_KEY is empty — set it in .env so the shipper can authenticate")
    offsets = load_offsets()
    log(f"watching {LOG_DIR} → {ENDPOINT}")
    while True:
        for name, source in FILES.items():
            path = LOG_DIR / name
            if not path.exists():
                continue
            size = path.stat().st_size
            offset = offsets.get(name, 0)
            if size < offset:  # truncated / rotated
                offset = 0
            if size == offset:
                continue
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                handle.seek(offset)
                chunk = handle.read()
            complete = chunk[: chunk.rfind("\n") + 1]  # only whole lines
            lines = [normalise(source, l) for l in complete.splitlines() if l.strip()]
            sent_ok = True
            for start in range(0, len(lines), BATCH):
                if not post(source, lines[start:start + BATCH]):
                    sent_ok = False
                    break
            if sent_ok:
                offsets[name] = offset + len(complete.encode("utf-8"))
                STATE_FILE.write_text(json.dumps(offsets))
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
