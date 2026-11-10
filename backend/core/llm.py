"""
Thin client for the Groq chat-completions API (OpenAI-compatible).

All callers must handle `LLMUnavailable` and fall back to deterministic output —
the platform is fully functional without an LLM key.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any

import httpx

from config import settings
from core.http import http_client

logger = logging.getLogger("threatlens.llm")

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"


class LLMUnavailable(RuntimeError):
    """Raised when the LLM is not configured or the call failed."""


def llm_enabled() -> bool:
    return bool(settings.GROQ_API_KEY)


def chat_completion(
    messages: list[dict[str, str]],
    *,
    model: str | None = None,
    temperature: float = 0.2,
    max_tokens: int = 800,
    timeout: float = 25.0,
    json_mode: bool = False,
) -> str:
    if not settings.GROQ_API_KEY:
        raise LLMUnavailable("GROQ_API_KEY is not configured")

    payload: dict[str, Any] = {
        "model": model or settings.GROQ_MODEL,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    if json_mode:
        payload["response_format"] = {"type": "json_object"}

    try:
        response = http_client.post(
            GROQ_URL,
            json=payload,
            headers={"Authorization": f"Bearer {settings.GROQ_API_KEY}"},
            timeout=timeout,
        )
    except httpx.TimeoutException as exc:
        raise LLMUnavailable("LLM request timed out") from exc
    except httpx.HTTPError as exc:
        raise LLMUnavailable(f"LLM connection failed: {exc}") from exc

    if response.status_code == 429:
        raise LLMUnavailable("LLM rate limit reached")
    if response.status_code != 200:
        logger.warning("Groq API returned %s: %s", response.status_code, response.text[:300])
        raise LLMUnavailable(f"LLM returned HTTP {response.status_code}")

    try:
        return response.json()["choices"][0]["message"]["content"]
    except (KeyError, IndexError, ValueError) as exc:
        raise LLMUnavailable("Malformed LLM response") from exc


def extract_json(raw_text: str) -> dict | None:
    """Extract the first JSON object from an LLM response."""
    if not raw_text:
        return None
    cleaned = raw_text.replace("```json", "").replace("```", "").strip()
    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if not match:
        return None
    try:
        data = json.loads(match.group(0))
        return data if isinstance(data, dict) else None
    except json.JSONDecodeError:
        return None
