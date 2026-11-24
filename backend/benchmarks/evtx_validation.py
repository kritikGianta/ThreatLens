"""
Detection validation against real attack recordings.

Uses the public EVTX-ATTACK-SAMPLES dataset (https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES,
GPL-3.0 — downloaded on demand, not redistributed): ~280 Windows event-log captures of real
attack techniques, organised by MITRE ATT&CK tactic. Every event is rendered the way the Windows
collector renders it and run through ThreatLens's detection rules. A recording counts as
detected when at least one of its events triggers a rule.

    pip install python-evtx==0.8.1
    python -m benchmarks.evtx_validation --download   # or --dataset /path/to/EVTX-ATTACK-SAMPLES
"""
import argparse
import io
import os
import sys
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.detector import evaluate_rules  # noqa: E402
from services.parser import parse_log  # noqa: E402

DATASET_ZIP = "https://codeload.github.com/sbousseaden/EVTX-ATTACK-SAMPLES/zip/refs/heads/master"
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
TACTICS = ["Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
           "Discovery", "Lateral Movement", "Command and Control"]


def render(xml_text: str) -> str:
    """Flatten an event record into the key=value line format the Windows collector produces."""
    root = ET.fromstring(xml_text)
    system = root.find("e:System", NS)
    event_id = system.findtext("e:EventID", default="", namespaces=NS) if system is not None else ""
    channel = system.findtext("e:Channel", default="", namespaces=NS) if system is not None else ""
    computer = system.findtext("e:Computer", default="", namespaces=NS) if system is not None else ""
    fields = []
    for data in root.iter():
        tag = data.tag.split("}")[-1]
        if tag in ("Data", "Param") or (data.text and data.text.strip() and tag not in ("EventID", "Channel", "Computer", "Provider")):
            name = data.attrib.get("Name") or tag
            value = (data.text or "").strip()
            if value:
                fields.append(f"{name}={value}")
    return f"[REAL_LOG] WinEventLog:{channel} EventID={event_id} Computer={computer} " + " ".join(fields)


def iter_events(path: Path):
    from Evtx.Evtx import Evtx  # python-evtx

    with Evtx(str(path)) as log:
        for record in log.records():
            try:
                yield render(record.xml())
            except Exception:
                continue


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, help="Path to an extracted EVTX-ATTACK-SAMPLES checkout")
    parser.add_argument("--download", action="store_true", help="Download the dataset to ./.evtx-dataset")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    root = args.dataset
    if args.download:
        target = Path(".evtx-dataset")
        if not target.exists():
            print("Downloading EVTX-ATTACK-SAMPLES …")
            data = urllib.request.urlopen(DATASET_ZIP, timeout=120).read()
            zipfile.ZipFile(io.BytesIO(data)).extractall(target)
        root = next(target.iterdir())
    if not root or not root.exists():
        parser.error("provide --dataset or --download")

    per_tactic = defaultdict(lambda: [0, 0])
    rules_hit = defaultdict(int)
    events_total = 0
    for tactic in TACTICS:
        for path in sorted((root / tactic).rglob("*.evtx")):
            detected = set()
            for line in iter_events(path):
                events_total += 1
                detected |= {r["name"] for r in evaluate_rules(parse_log(line))}
            # The dataset authors often cleared the log before recording a technique; that incidental
            # log-clear event must not earn credit for detecting an unrelated technique.
            if tactic != "Defense Evasion":
                detected.discard("Event Log Cleared")
            per_tactic[tactic][1] += 1
            if detected:
                per_tactic[tactic][0] += 1
                for name in detected:
                    rules_hit[name] += 1
            if args.verbose:
                print(f"  {'✓' if detected else '·'} {tactic:22} {path.name:60} {', '.join(sorted(detected))}")

    hit = sum(v[0] for v in per_tactic.values())
    total = sum(v[1] for v in per_tactic.values())
    print(f"\nEvents analysed: {events_total:,}")
    print(f"Recordings detected: {hit} / {total}  ({100 * hit / max(total, 1):.0f}%)\n")
    print(f"{'Tactic':24} {'Detected':>10}")
    for tactic in TACTICS:
        h, t = per_tactic[tactic]
        if t:
            print(f"{tactic:24} {h:>4} / {t:<4} {100 * h / t:5.0f}%")
    print("\nRules that fired (recordings):")
    for name, count in sorted(rules_hit.items(), key=lambda x: -x[1]):
        print(f"  {count:>4}  {name}")


if __name__ == "__main__":
    main()
