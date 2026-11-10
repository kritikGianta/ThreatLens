"""
Threat intelligence feed ingestion.

Keyless feeds (always on):
  - CISA KEV        — Known Exploited Vulnerabilities catalogue
  - Feodo Tracker   — abuse.ch botnet C2 IP blocklist
  - IPsum           — aggregated malicious-IP list (stamparm/ipsum, level 5 = seen on 5+ blocklists)
Feeds requiring a free abuse.ch Auth-Key (ABUSECH_AUTH_KEY):
  - URLhaus         — recent malware distribution URLs
  - ThreatFox       — recent IOCs (IPs, domains, hashes) with malware attribution
"""
from __future__ import annotations

import logging
import threading
from datetime import datetime
from typing import Callable, Dict, Iterable, List

import httpx
from sqlalchemy import func
from sqlalchemy.orm import Session

from config import settings
from core.http import http_client
from models.database import SessionLocal
from models.db_models import ThreatIntelEntry

logger = logging.getLogger("threatlens.intel")

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FEODO_TRACKER_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
IPSUM_URL = "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/5.txt"
URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/100/"
THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"

FEEDS = {
    "CISA_KEV": {"label": "CISA KEV", "requires_key": False, "ioc_types": ["cve"]},
    "FEODO_TRACKER": {"label": "Feodo Tracker", "requires_key": False, "ioc_types": ["ip"]},
    "IPSUM": {"label": "IPsum", "requires_key": False, "ioc_types": ["ip"]},
    "URLHAUS": {"label": "URLhaus", "requires_key": True, "ioc_types": ["url"]},
    "THREATFOX": {"label": "ThreatFox", "requires_key": True, "ioc_types": ["ip", "domain", "url", "hash"]},
}

_ingest_lock = threading.Lock()
_last_results: Dict = {}


def _existing_values(db: Session, source: str) -> set:
    return {row[0] for row in db.query(ThreatIntelEntry.ioc_value).filter(ThreatIntelEntry.source == source).all()}


def _store(db: Session, source: str, entries: Iterable[Dict]) -> int:
    existing = _existing_values(db, source)
    added = 0
    for entry in entries:
        value = (entry.get("ioc_value") or "")[:500]
        if not value or value in existing:
            continue
        existing.add(value)
        db.add(ThreatIntelEntry(source=source, **{**entry, "ioc_value": value}))
        added += 1
    db.flush()
    return added


def _get_json(url: str, **kwargs):
    response = http_client.get(url, timeout=30, **kwargs)
    response.raise_for_status()
    return response.json()


def _cisa_kev() -> List[Dict]:
    data = _get_json(CISA_KEV_URL)
    vulns = sorted(data.get("vulnerabilities", []), key=lambda v: v.get("dateAdded", ""), reverse=True)[:300]
    return [
        {
            "title": f"{v.get('cveID')}: {v.get('vulnerabilityName', 'Unknown')}",
            "description": (
                f"Vendor: {v.get('vendorProject', 'N/A')}. Product: {v.get('product', 'N/A')}. "
                f"{v.get('shortDescription', '')} Required action: {v.get('requiredAction', 'N/A')}. "
                f"Added: {v.get('dateAdded', 'N/A')}. Due: {v.get('dueDate', 'N/A')}."
            ),
            "ioc_type": "cve",
            "ioc_value": v.get("cveID", ""),
            "severity": "CRITICAL" if v.get("knownRansomwareCampaignUse") == "Known" else "HIGH",
            "tags": [t for t in (v.get("vendorProject"), v.get("product"), f"ransomware:{v.get('knownRansomwareCampaignUse', 'Unknown')}") if t],
            "raw_data": v,
        }
        for v in vulns
    ]


def _feodo() -> List[Dict]:
    data = _get_json(FEODO_TRACKER_URL)
    items = data if isinstance(data, list) else []
    return [
        {
            "title": f"Botnet C2: {item.get('ip_address')} ({item.get('malware', 'unknown')})",
            "description": (
                f"Malware: {item.get('malware', 'Unknown')}. Port: {item.get('port', 'N/A')}. "
                f"Status: {item.get('status', 'N/A')}. Country: {item.get('country', 'N/A')}. "
                f"AS: {item.get('as_name', 'N/A')}. Identified as a botnet command-and-control server."
            ),
            "ioc_type": "ip",
            "ioc_value": item.get("ip_address", ""),
            "severity": "CRITICAL" if item.get("status") == "online" else "HIGH",
            "tags": [t for t in (item.get("malware"), "C2", item.get("country")) if t],
            "raw_data": item,
        }
        for item in items[:1000]
    ]


def _ipsum() -> List[Dict]:
    response = http_client.get(IPSUM_URL, timeout=30)
    response.raise_for_status()
    ips = [line.strip() for line in response.text.splitlines() if line.strip() and not line.startswith("#")]
    return [
        {
            "title": f"Malicious IP: {ip}",
            "description": "Listed on 5 or more independent public blocklists (IPsum aggregate). Associated with scanning, brute force, spam or malware activity.",
            "ioc_type": "ip",
            "ioc_value": ip,
            "severity": "HIGH",
            "tags": ["ipsum", "multi-blocklist"],
            "raw_data": {"feed": "ipsum", "level": 5},
        }
        for ip in ips[:5000]
    ]


def _urlhaus() -> List[Dict]:
    response = http_client.get(URLHAUS_API_URL, headers={"Auth-Key": settings.ABUSECH_AUTH_KEY}, timeout=30)
    response.raise_for_status()
    return [
        {
            "title": f"Malicious URL: {item.get('url', '')[:80]}",
            "description": (
                f"Threat: {item.get('threat', 'Unknown')}. Status: {item.get('url_status', 'N/A')}. "
                f"Tags: {', '.join(item.get('tags') or [])}. Reporter: {item.get('reporter', 'N/A')}."
            ),
            "ioc_type": "url",
            "ioc_value": item.get("url", ""),
            "severity": "HIGH",
            "tags": item.get("tags") or ["malware"],
            "raw_data": item,
        }
        for item in response.json().get("urls", [])
    ]


def _threatfox() -> List[Dict]:
    response = http_client.post(
        THREATFOX_API_URL,
        json={"query": "get_iocs", "days": 3},
        headers={"Auth-Key": settings.ABUSECH_AUTH_KEY},
        timeout=30,
    )
    response.raise_for_status()
    entries = []
    for item in (response.json().get("data") or [])[:1000]:
        ioc = str(item.get("ioc", ""))
        ioc_type = item.get("ioc_type", "")
        if ioc_type == "ip:port":
            ioc, normalized = ioc.split(":")[0], "ip"
        elif ioc_type in ("domain", "url"):
            normalized = ioc_type
        elif "hash" in ioc_type:
            normalized = "hash"
        else:
            normalized = ioc_type or "other"
        entries.append({
            "title": f"{item.get('malware_printable', 'Malware')} {normalized.upper()}: {ioc[:80]}",
            "description": (
                f"Threat type: {item.get('threat_type_desc', 'N/A')}. Malware: {item.get('malware_printable', 'N/A')}. "
                f"Confidence: {item.get('confidence_level', 'N/A')}%. First seen: {item.get('first_seen', 'N/A')}."
            ),
            "ioc_type": normalized,
            "ioc_value": ioc,
            "severity": "CRITICAL" if (item.get("confidence_level") or 0) >= 75 else "HIGH",
            "tags": (item.get("tags") or []) + [item.get("malware_printable") or "malware"],
            "raw_data": item,
        })
    return entries


_FETCHERS: Dict[str, Callable[[], List[Dict]]] = {
    "CISA_KEV": _cisa_kev,
    "FEODO_TRACKER": _feodo,
    "IPSUM": _ipsum,
    "URLHAUS": _urlhaus,
    "THREATFOX": _threatfox,
}


def ingest_all() -> Dict:
    """Run every feed. Each feed commits independently so one failure never blocks others."""
    if not _ingest_lock.acquire(blocking=False):
        return {"status": "already_running", "feeds": _last_results.get("feeds", {})}
    try:
        results: Dict[str, Dict] = {}
        for source, fetch in _FETCHERS.items():
            if FEEDS[source]["requires_key"] and not settings.ABUSECH_AUTH_KEY:
                results[source] = {"status": "skipped", "message": "Set ABUSECH_AUTH_KEY to enable this feed"}
                continue
            db = SessionLocal()
            try:
                entries = fetch()
                added = _store(db, source, entries)
                db.commit()
                results[source] = {"status": "ok", "fetched": len(entries), "new_entries": added}
            except httpx.HTTPStatusError as exc:
                db.rollback()
                results[source] = {"status": "error", "message": f"HTTP {exc.response.status_code}"}
            except Exception as exc:
                db.rollback()
                logger.warning("Feed %s failed: %s", source, exc)
                results[source] = {"status": "error", "message": str(exc)[:200]}
            finally:
                db.close()
        _last_results.clear()
        _last_results.update({"completed_at": datetime.utcnow().isoformat(), "feeds": results})
        logger.info("Threat intel ingestion complete: %s", {k: v.get("new_entries", v["status"]) for k, v in results.items()})
        return {"status": "completed", "feeds": results}
    finally:
        _ingest_lock.release()


def get_intel_stats(db: Session) -> Dict:
    total = db.query(func.count(ThreatIntelEntry.id)).scalar() or 0
    by_source = dict(db.query(ThreatIntelEntry.source, func.count(ThreatIntelEntry.id)).group_by(ThreatIntelEntry.source).all())
    by_type = dict(db.query(ThreatIntelEntry.ioc_type, func.count(ThreatIntelEntry.id)).group_by(ThreatIntelEntry.ioc_type).all())
    last = db.query(func.max(ThreatIntelEntry.ingested_at)).scalar()
    return {
        "total_entries": total,
        "by_source": by_source,
        "by_type": by_type,
        "last_ingested_at": last.isoformat() if last else None,
        "feeds": [
            {
                "source": key,
                "label": meta["label"],
                "requires_key": meta["requires_key"],
                "enabled": not meta["requires_key"] or bool(settings.ABUSECH_AUTH_KEY),
                "count": by_source.get(key, 0),
                "last_result": (_last_results.get("feeds") or {}).get(key),
            }
            for key, meta in FEEDS.items()
        ],
        "last_run": _last_results.get("completed_at"),
    }
