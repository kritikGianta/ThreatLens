"""CVE lookup via the NIST National Vulnerability Database (NVD) 2.0 API, with caching."""
from __future__ import annotations

import logging
from typing import Dict, List

import httpx

from config import settings
from core.http import TTLCache, http_client

logger = logging.getLogger("threatlens.cve")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# NVD's unauthenticated limit is 5 requests / 30s — cache aggressively.
_cache = TTLCache(maxsize=256, ttl_seconds=6 * 3600)


def _extract_cvss(metrics: dict):
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData", {})
            return data.get("baseScore"), data.get("baseSeverity") or entries[0].get("baseSeverity")
    return None, None


def _fetch(keyword: str, max_results: int) -> List[Dict]:
    headers = {"apiKey": settings.NVD_API_KEY} if settings.NVD_API_KEY else {}
    try:
        response = http_client.get(
            NVD_URL,
            params={"keywordSearch": keyword, "resultsPerPage": max_results},
            headers=headers,
            timeout=12,
        )
    except httpx.TimeoutException:
        logger.warning("NVD API request timed out for %r", keyword)
        return []
    except httpx.HTTPError as exc:
        logger.warning("NVD API connection failed: %s", exc)
        return []

    if response.status_code in (403, 429):
        logger.warning("NVD API rate limited (HTTP %s). Add NVD_API_KEY to raise the limit.", response.status_code)
        return []
    if response.status_code != 200:
        logger.warning("NVD API returned HTTP %s", response.status_code)
        return []

    results = []
    for item in response.json().get("vulnerabilities", []):
        cve = item.get("cve", {})
        score, severity = _extract_cvss(cve.get("metrics", {}))
        description = next(
            (d.get("value") for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            None,
        )
        results.append({
            "cve_id": cve.get("id"),
            "id": cve.get("id"),  # alias kept for older UI code
            "description": description,
            "cvss_score": score,
            "severity": severity,
            "published": cve.get("published"),
            "url": f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}",
        })
    return results


def search_cves(keyword: str, max_results: int = 5) -> List[Dict]:
    """Search NVD for CVEs matching a keyword. Never raises; returns [] on failure."""
    keyword = (keyword or "").strip()
    if len(keyword) < 2:
        return []
    key = (keyword.lower(), max_results)
    cached = _cache.get(key)
    if cached is not None:
        return cached
    results = _fetch(keyword, max_results)
    if results:
        _cache.set(key, results)
    return results
