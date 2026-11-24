"""
IP intelligence: geolocation (ip-api.com → ipinfo.io fallback, OpenCage enrichment)
and reputation (VirusTotal). Every provider is optional and cached.
"""
from __future__ import annotations

import ipaddress
import logging
from datetime import datetime
from typing import Dict, Optional

import httpx

from config import settings
from core.http import TTLCache, http_client

logger = logging.getLogger("threatlens.ip_intel")

VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"
IPAPI_URL = "http://ip-api.com/json/{}"  # free tier is HTTP-only; no key required
IPINFO_URL = "https://ipinfo.io/{}/json"
OPENCAGE_URL = "https://api.opencagedata.com/geocode/v1/json"

HIGH_RISK_COUNTRIES = {"RU", "CN", "IR", "KP", "SY"}

_geo_cache = TTLCache(maxsize=2000, ttl_seconds=24 * 3600)
_rep_cache = TTLCache(maxsize=2000, ttl_seconds=6 * 3600)


def is_public_ip(ip: Optional[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except (TypeError, ValueError):
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_multicast or addr.is_reserved or addr.is_link_local)


def _private_geo(ip: str) -> Dict:
    return {
        "ip": ip, "city": "Private network", "region": "", "country": "Internal", "country_code": "LOCAL",
        "lat": None, "lon": None, "isp": "Internal network", "org": "RFC1918 / reserved range", "source": "local",
    }


def _geo_ipapi(ip: str) -> Optional[Dict]:
    try:
        response = http_client.get(
            IPAPI_URL.format(ip),
            params={"fields": "status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,timezone"},
            timeout=5,
        )
        data = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.debug("ip-api.com lookup failed for %s: %s", ip, exc)
        return None
    if data.get("status") != "success":
        return None
    return {
        "ip": ip, "city": data.get("city") or "Unknown", "region": data.get("regionName", ""),
        "country": data.get("country") or "Unknown", "country_code": data.get("countryCode", ""),
        "lat": data.get("lat"), "lon": data.get("lon"), "isp": data.get("isp") or "Unknown",
        "org": data.get("org") or "Unknown", "as": data.get("as", ""), "timezone": data.get("timezone", ""),
        "source": "ip-api.com",
    }


def _geo_ipinfo(ip: str) -> Optional[Dict]:
    if not settings.IPINFO_TOKEN:
        return None
    try:
        response = http_client.get(IPINFO_URL.format(ip), params={"token": settings.IPINFO_TOKEN}, timeout=5)
        data = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.debug("ipinfo.io lookup failed for %s: %s", ip, exc)
        return None
    if "loc" not in data:
        return None
    lat, lon = (float(x) for x in data["loc"].split(","))
    return {
        "ip": ip, "city": data.get("city") or "Unknown", "region": data.get("region", ""),
        "country": data.get("country") or "Unknown", "country_code": data.get("country", ""),
        "lat": lat, "lon": lon, "isp": data.get("org") or "Unknown", "org": data.get("org") or "Unknown",
        "timezone": data.get("timezone", ""), "source": "ipinfo.io",
    }


def _opencage_enrich(lat: float, lon: float) -> Optional[Dict]:
    if not settings.OPENCAGE_API_KEY:
        return None
    try:
        response = http_client.get(
            OPENCAGE_URL,
            params={"q": f"{lat},{lon}", "key": settings.OPENCAGE_API_KEY, "no_annotations": 0, "language": "en"},
            timeout=5,
        )
        results = response.json().get("results") or []
    except (httpx.HTTPError, ValueError) as exc:
        logger.debug("OpenCage lookup failed: %s", exc)
        return None
    if not results:
        return None
    result = results[0]
    annotations = result.get("annotations", {})
    return {
        "formatted_address": result.get("formatted", ""),
        "continent": result.get("components", {}).get("continent", ""),
        "currency": annotations.get("currency", {}).get("name", ""),
        "flag": annotations.get("flag", ""),
    }


def get_ip_geolocation(ip: str) -> Dict:
    if not is_public_ip(ip):
        return _private_geo(ip)
    cached = _geo_cache.get(ip)
    if cached:
        return cached

    geo = _geo_ipapi(ip) or _geo_ipinfo(ip)
    if geo is None:
        return {"ip": ip, "city": "Unknown", "country": "Unknown", "country_code": "", "lat": None, "lon": None,
                "isp": "Unknown", "org": "Unknown", "source": "unavailable"}
    if geo.get("lat") is not None and geo.get("lon") is not None:
        extra = _opencage_enrich(geo["lat"], geo["lon"])
        if extra:
            geo.update(extra)
    _geo_cache.set(ip, geo)
    return geo


def get_ip_reputation(ip: str) -> Dict:
    empty = {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}
    if not is_public_ip(ip):
        return {**empty, "source": "skipped (private IP)"}
    if not settings.VT_API_KEY:
        return {**empty, "source": "not configured"}
    cached = _rep_cache.get(ip)
    if cached:
        return cached
    try:
        response = http_client.get(VT_URL.format(ip), headers={"x-apikey": settings.VT_API_KEY}, timeout=10)
        if response.status_code == 404:
            result = {**empty, "source": "virustotal"}
        else:
            response.raise_for_status()
            attributes = response.json()["data"]["attributes"]
            stats = attributes.get("last_analysis_stats", {})
            result = {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": attributes.get("reputation"),
                "as_owner": attributes.get("as_owner"),
                "source": "virustotal",
            }
    except (httpx.HTTPError, KeyError, ValueError) as exc:
        logger.warning("VirusTotal lookup failed for %s: %s", ip, exc)
        return {**empty, "source": "error"}
    _rep_cache.set(ip, result)
    return result


def enrich_ip(ip: str) -> Dict:
    """Geolocation + reputation + a simple standalone IP risk assessment."""
    geo = get_ip_geolocation(ip)
    reputation = get_ip_reputation(ip)

    score, factors = 0, []
    if reputation.get("malicious"):
        score += reputation["malicious"] * 10
        factors.append(f"Malicious ({reputation['malicious']} VirusTotal detections)")
    if reputation.get("suspicious"):
        score += reputation["suspicious"] * 5
        factors.append(f"Suspicious ({reputation['suspicious']} VirusTotal verdicts)")
    if geo.get("country_code") in HIGH_RISK_COUNTRIES:
        score += 20
        factors.append(f"High-risk geography: {geo.get('country')}")
    score = min(score, 100)
    level = "CRITICAL" if score >= 70 else "HIGH" if score >= 40 else "MEDIUM" if score >= 20 else "LOW"

    return {
        "ip": ip,
        "is_public": is_public_ip(ip),
        "geo": geo,
        "reputation": reputation,
        "risk_assessment": {"risk_score": score, "risk_level": level, "risk_factors": factors},
        "enriched_at": datetime.utcnow().isoformat(),
    }


# ── Batch geolocation for the live threat map ───────────────────────────────
IPAPI_BATCH_URL = "http://ip-api.com/batch"
_hq_cache: Dict = {}
_geo_failures = TTLCache(maxsize=4000, ttl_seconds=60)   # don't hammer the provider after a failed lookup
_batch_backoff = {"until": 0.0}


def geolocate_many(ips) -> Dict[str, Dict]:
    """Geolocate many public IPs with ip-api's batch endpoint (100 per call), using the shared cache."""
    results: Dict[str, Dict] = {}
    pending = []
    import time as _time

    for ip in dict.fromkeys(ips):
        if not is_public_ip(ip):
            continue
        cached = _geo_cache.get(ip)
        if cached and cached.get("lat") is not None:
            results[ip] = cached
        elif not _geo_failures.get(ip):
            pending.append(ip)
    if _time.monotonic() < _batch_backoff["until"]:
        return results  # provider asked us to slow down
    for start in range(0, len(pending), 100):
        chunk = pending[start:start + 100]
        try:
            response = http_client.post(
                IPAPI_BATCH_URL,
                params={"fields": "status,query,country,countryCode,regionName,city,lat,lon,isp,org,as"},
                json=chunk,
                timeout=8,
            )
            if response.status_code != 200:
                logger.warning("ip-api batch returned HTTP %s", response.status_code)
                if response.status_code == 429:
                    _batch_backoff["until"] = _time.monotonic() + 30
                break
            if response.headers.get("X-Rl") == "0":  # last request allowed in this window
                _batch_backoff["until"] = _time.monotonic() + float(response.headers.get("X-Ttl", "30"))
            rows = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning("ip-api batch lookup failed: %s", exc)
            break
        for row in rows:
            if row.get("status") != "success":
                if row.get("query"):
                    _geo_failures.set(row["query"], True)
                continue
            geo = {
                "ip": row["query"], "city": row.get("city") or "Unknown", "region": row.get("regionName", ""),
                "country": row.get("country") or "Unknown", "country_code": row.get("countryCode", ""),
                "lat": row.get("lat"), "lon": row.get("lon"), "isp": row.get("isp") or "Unknown",
                "org": row.get("org") or "Unknown", "as": row.get("as", ""), "source": "ip-api.com",
            }
            _geo_cache.set(row["query"], geo)
            results[row["query"]] = geo
    return results


def get_hq_location() -> Dict:
    """Location of 'our' network on the threat map: env override, else this server's public IP location."""
    import os

    if os.getenv("ORG_HQ_LAT") and os.getenv("ORG_HQ_LON"):
        try:
            return {"name": os.getenv("ORG_HQ_NAME") or "Headquarters", "lat": float(os.getenv("ORG_HQ_LAT")),
                    "lon": float(os.getenv("ORG_HQ_LON")), "source": "configured"}
        except ValueError:
            pass
    if _hq_cache:
        return _hq_cache
    try:
        data = http_client.get("http://ip-api.com/json/", params={"fields": "status,city,country,lat,lon"}, timeout=5).json()
        if data.get("status") == "success":
            _hq_cache.update({"name": os.getenv("ORG_HQ_NAME") or f"HQ · {data.get('city')}, {data.get('country')}",
                              "lat": data["lat"], "lon": data["lon"], "source": "server public IP"})
            return _hq_cache
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("Could not determine HQ location: %s", exc)
    return {"name": os.getenv("ORG_HQ_NAME") or "Headquarters", "lat": 20.0, "lon": 0.0, "source": "fallback"}
