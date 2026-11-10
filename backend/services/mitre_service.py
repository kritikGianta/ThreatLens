"""
MITRE ATT&CK knowledge base.

Techniques are loaded from `data/mitre_cache.json` (shipped with the repo so the
platform works offline). `refresh_cache()` rebuilds it from MITRE's official STIX
bundle on GitHub.
"""
from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Dict, List, Optional

from config import settings
from core.http import http_client

logger = logging.getLogger("threatlens.mitre")

CACHE_FILE = Path(settings.DATA_DIR) / "mitre_cache.json"
MITRE_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
)

TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
]

_lock = threading.Lock()
_techniques: Optional[List[Dict]] = None
_by_id: Dict[str, Dict] = {}


def _tactic_name(phase: str) -> str:
    special = {"command-and-control": "Command and Control"}
    return special.get(phase, phase.replace("-", " ").title())


def parse_stix_bundle(bundle: dict) -> List[Dict]:
    techniques = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ref = next((r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if not ref or not ref.get("external_id"):
            continue
        techniques.append({
            "id": ref["external_id"],
            "name": obj.get("name"),
            "description": obj.get("description"),
            "tactics": [
                _tactic_name(p["phase_name"])
                for p in obj.get("kill_chain_phases", [])
                if p.get("kill_chain_name") == "mitre-attack"
            ],
            "platforms": obj.get("x_mitre_platforms", []),
            "detection": obj.get("x_mitre_detection"),
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
            "url": ref.get("url") or f"https://attack.mitre.org/techniques/{ref['external_id'].replace('.', '/')}/",
        })
    techniques.sort(key=lambda t: t["id"])
    return techniques


def _index(techniques: List[Dict]) -> None:
    global _techniques, _by_id
    _techniques = techniques
    _by_id = {t["id"].upper(): t for t in techniques}


def _load() -> List[Dict]:
    if _techniques is not None:
        return _techniques
    with _lock:
        if _techniques is not None:
            return _techniques
        try:
            data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
            if isinstance(data, list) and data:
                _index(data)
                logger.info("Loaded %d MITRE techniques from %s", len(data), CACHE_FILE.name)
                return _techniques
        except FileNotFoundError:
            logger.warning("MITRE cache %s not found — fetching from GitHub", CACHE_FILE)
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("MITRE cache unreadable (%s) — fetching from GitHub", exc)
    refresh_cache()
    return _techniques or []


def refresh_cache() -> List[Dict]:
    """Download the official ATT&CK STIX bundle and rebuild the local cache."""
    try:
        response = http_client.get(MITRE_STIX_URL, timeout=60)
        response.raise_for_status()
        techniques = parse_stix_bundle(response.json())
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(json.dumps(techniques, indent=1), encoding="utf-8")
        with _lock:
            _index(techniques)
        logger.info("MITRE cache refreshed with %d techniques", len(techniques))
        return techniques
    except Exception as exc:
        logger.error("Failed to refresh MITRE ATT&CK data: %s", exc)
        with _lock:
            if _techniques is None:
                _index([])
        return _techniques or []


def get_technique_by_id(technique_id: str) -> Optional[Dict]:
    if not technique_id:
        return None
    _load()
    return _by_id.get(technique_id.strip().upper())


def search_techniques(query: str, limit: int = 25, tactic: Optional[str] = None) -> List[Dict]:
    techniques = _load()
    q = (query or "").strip().lower()
    exact, name_hits, desc_hits = [], [], []
    for tech in techniques:
        if tactic and tactic not in tech.get("tactics", []):
            continue
        tid = tech["id"].lower()
        name = (tech.get("name") or "").lower()
        if not q:
            name_hits.append(tech)
        elif tid == q:
            exact.append(tech)
        elif tid.startswith(q) or q in name:
            name_hits.append(tech)
        elif q in (tech.get("description") or "").lower():
            desc_hits.append(tech)
    results = (exact + name_hits + desc_hits)[:limit]
    return [
        {
            "id": t["id"],
            "name": t["name"],
            "tactics": t.get("tactics", []),
            "description": (t.get("description") or "")[:240],
            "is_subtechnique": t.get("is_subtechnique", False),
        }
        for t in results
    ]


def list_tactics() -> List[Dict]:
    counts: Dict[str, int] = {}
    for tech in _load():
        for tactic in tech.get("tactics", []):
            counts[tactic] = counts.get(tactic, 0) + 1
    ordered = [name for name in TACTIC_ORDER if name in counts]
    ordered += sorted(name for name in counts if name not in TACTIC_ORDER)  # newer ATT&CK tactics
    return [{"name": name, "technique_count": counts[name]} for name in ordered]


def technique_count() -> int:
    return len(_load())
