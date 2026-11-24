"""
Pipeline throughput benchmark.

Pushes a realistic mix of benign and malicious log lines through the full analysis
pipeline (parse → detect → correlate → score → persist → case management → SOAR) and
reports events/second and per-event latency.

Run against a throwaway database — never your live one:
    docker compose exec db createdb -U threatlens threatlens_bench
    docker compose exec -e DATABASE_URL=postgresql+psycopg://threatlens:<password>@db:5432/threatlens_bench \
        -e SEED_DEMO_DATA=false backend python -m benchmarks.throughput --events 5000
"""
import argparse
import os
import random
import statistics
import sys
import time

os.environ.setdefault("SEED_DEMO_DATA", "false")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.database import SessionLocal, init_db, safe_database_url  # noqa: E402
from services.alert_service import create_default_rules  # noqa: E402
from services.pipeline import process_log  # noqa: E402
from services.simulator import _benign_event, _internet_noise  # noqa: E402

MALICIOUS = [
    "WinEventLog:Security EventID=4688 Account Name: admin Source Network Address: 198.51.100.{n} Process created: \"procdump64.exe -ma lsass.exe\"",
    "cmd.exe /c vssadmin.exe delete shadows /all /quiet src_ip=203.0.113.{n}",
    "sshd[1]: Failed password for root from 192.0.2.{n} port 22 ssh2",
    "198.51.100.{n} - - [24/Nov/2026:10:00:00 +0000] \"GET /p?id=1%27%20UNION%20ALL%20SELECT%20NULL-- HTTP/1.1\" 200 1 \"-\" \"sqlmap/1.8\"",
]


def build_events(count: int, malicious_ratio: float):
    events = []
    for _ in range(count):
        if random.random() < malicious_ratio:
            if random.random() < 0.5:
                events.append(random.choice(MALICIOUS).format(n=random.randint(1, 254)))
            else:
                events.extend(_internet_noise(f"198.51.100.{random.randint(1, 254)}")[:1])
        else:
            events.append(_benign_event())
    return events[:count]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--events", type=int, default=3000)
    parser.add_argument("--malicious-ratio", type=float, default=0.15)
    parser.add_argument("--batch", type=int, default=50)
    args = parser.parse_args()

    print(f"Database: {safe_database_url()}")
    init_db()
    db = SessionLocal()
    create_default_rules(db)
    events = build_events(args.events, args.malicious_ratio)
    latencies, detections = [], 0
    started = time.perf_counter()
    for start in range(0, len(events), args.batch):
        for line in events[start:start + args.batch]:
            t0 = time.perf_counter()
            result = process_log(db, line, source="benchmark")
            latencies.append((time.perf_counter() - t0) * 1000)
            detections += 1 if result["detection_result"].get("threat_detected") else 0
        db.commit()
    elapsed = time.perf_counter() - started
    db.close()

    latencies.sort()
    pct = lambda p: latencies[min(len(latencies) - 1, int(p / 100 * len(latencies)))]  # noqa: E731
    print(f"Events processed : {len(events):,}  ({detections:,} detections)")
    print(f"Wall time        : {elapsed:.1f} s")
    print(f"Throughput       : {len(events) / elapsed:,.0f} events/second (single worker, synchronous)")
    print(f"Latency per event: p50 {pct(50):.1f} ms · p95 {pct(95):.1f} ms · mean {statistics.mean(latencies):.1f} ms")


if __name__ == "__main__":
    main()
