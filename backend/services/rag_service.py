"""
ThreatLens RAG service — retrieves threat-intelligence context for detections.

Two strategies are combined:
  1. Direct indicator match — exact lookup of IPs / CVEs / domains in the IOC table.
  2. Semantic TF-IDF search over a corpus made of the curated knowledge base
     (data/threat_docs/*.txt) plus descriptive feed entries (CVEs, ThreatFox, URLhaus).
     The vector index is cached and only rebuilt when the corpus changes.
"""
from __future__ import annotations

import logging
import re
import threading
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sqlalchemy import func
from sqlalchemy.orm import Session

from config import settings
from models.db_models import ThreatIntelEntry

logger = logging.getLogger("threatlens.rag")

# Feeds that carry descriptive text worth embedding (raw IP lists add only noise).
_TEXT_SOURCES = ("CISA_KEV", "THREATFOX", "URLHAUS", "MANUAL")
_MAX_DB_DOCS = 1500

_lock = threading.Lock()
_index: Dict = {"key": None, "vectorizer": None, "matrix": None, "docs": []}
_kb_cache: Optional[List[Dict]] = None


def load_knowledge_base() -> List[Dict]:
    """Load curated threat write-ups from data/threat_docs (once per process)."""
    global _kb_cache
    if _kb_cache is not None:
        return _kb_cache
    docs = []
    docs_dir = Path(settings.DATA_DIR) / "threat_docs"
    for path in sorted(docs_dir.glob("*.txt")) if docs_dir.exists() else []:
        try:
            content = path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            logger.warning("Could not read %s: %s", path.name, exc)
            continue
        if len(content) < 50:
            continue
        first_line = content.splitlines()[0].strip()
        title = first_line.split("—")[0].strip() or path.stem.replace("_", " ").title()
        severity_match = re.search(r"Severity:\s*([A-Z]+)", content)
        docs.append({
            "intel_id": None,
            "source": f"KNOWLEDGE_BASE:{path.name}",
            "title": title,
            "description": content[:1200],
            "text": content,
            "ioc_type": "technique",
            "ioc_value": None,
            "severity": severity_match.group(1) if severity_match else "HIGH",
            "mitre": sorted(set(re.findall(r"T\d{4}(?:\.\d{3})?", content)))[:8],
        })
    _kb_cache = docs
    logger.info("Loaded %d knowledge-base documents", len(docs))
    return docs


def _corpus_key(db: Session):
    row = (
        db.query(func.count(ThreatIntelEntry.id), func.max(ThreatIntelEntry.id))
        .filter(ThreatIntelEntry.source.in_(_TEXT_SOURCES))
        .one()
    )
    return (row[0] or 0, row[1] or 0, len(load_knowledge_base()))


def _build_index(db: Session):
    key = _corpus_key(db)
    if _index["key"] == key and _index["vectorizer"] is not None:
        return _index
    with _lock:
        if _index["key"] == key and _index["vectorizer"] is not None:
            return _index
        docs = list(load_knowledge_base())
        entries = (
            db.query(ThreatIntelEntry)
            .filter(ThreatIntelEntry.source.in_(_TEXT_SOURCES))
            .order_by(ThreatIntelEntry.ingested_at.desc())
            .limit(_MAX_DB_DOCS)
            .all()
        )
        for entry in entries:
            docs.append({
                "intel_id": entry.id,
                "source": entry.source,
                "title": entry.title,
                "description": entry.description,
                "text": f"{entry.title} {entry.description} {' '.join(map(str, entry.tags or []))}",
                "ioc_type": entry.ioc_type,
                "ioc_value": entry.ioc_value,
                "severity": entry.severity,
            })
        if len(docs) < 2:
            _index.update({"key": key, "vectorizer": None, "matrix": None, "docs": docs})
            return _index
        vectorizer = TfidfVectorizer(stop_words="english", max_features=20000, ngram_range=(1, 2), sublinear_tf=True)
        matrix = vectorizer.fit_transform([d["text"] for d in docs])
        _index.update({"key": key, "vectorizer": vectorizer, "matrix": matrix, "docs": docs})
        logger.info("RAG index rebuilt over %d documents", len(docs))
        return _index


def _public(doc: Dict, relevance: str, score: float) -> Dict:
    return {
        "intel_id": doc.get("intel_id"),
        "source": doc.get("source"),
        "title": doc.get("title"),
        "description": (doc.get("description") or "")[:600],
        "ioc_type": doc.get("ioc_type"),
        "ioc_value": doc.get("ioc_value"),
        "severity": doc.get("severity"),
        "relevance": relevance,
        "relevance_score": round(float(score), 3),
    }


def check_ioc_match(indicator: Optional[str], db: Session) -> List[Dict]:
    """Exact lookup of an indicator (normally a source IP) in the IOC table."""
    if not indicator:
        return []
    matches = db.query(ThreatIntelEntry).filter(ThreatIntelEntry.ioc_value == indicator).limit(10).all()
    return [
        {
            "intel_id": m.id,
            "source": m.source,
            "title": m.title,
            "severity": m.severity,
            "ioc_type": m.ioc_type,
            "ioc_value": m.ioc_value,
            "relevance": "direct_match",
        }
        for m in matches
    ]


def retrieve_threat_intel(query: str, db: Session, top_k: int = 3, indicators: Iterable[str] = ()) -> List[Dict]:
    """Return the most relevant intel for a detection (direct indicator hits first)."""
    results: List[Dict] = []
    seen = set()

    for indicator in indicators or ():
        for match in check_ioc_match(indicator, db):
            if match["intel_id"] not in seen:
                seen.add(match["intel_id"])
                results.append({**match, "description": match["title"], "relevance_score": 1.0})

    if query:
        try:
            index = _build_index(db)
            if index["vectorizer"] is not None:
                similarities = cosine_similarity(index["vectorizer"].transform([query]), index["matrix"]).flatten()
                for idx in similarities.argsort()[::-1][: top_k * 3]:
                    if similarities[idx] < 0.04 or len(results) >= top_k:
                        break
                    doc = index["docs"][idx]
                    marker = doc.get("intel_id") or doc.get("source")
                    if marker in seen:
                        continue
                    seen.add(marker)
                    relevance = "knowledge_base" if doc.get("intel_id") is None else "semantic_match"
                    results.append(_public(doc, relevance, similarities[idx]))
        except Exception as exc:  # retrieval must never break analysis
            logger.warning("Semantic threat-intel search failed: %s", exc)

    return results[:top_k]
