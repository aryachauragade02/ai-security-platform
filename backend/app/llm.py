"""Talks to Google Gemini over its REST API.

With no GEMINI_API_KEY it runs in MOCK mode: a fake model that is deliberately
easy to trick, so the whole platform can be demonstrated and tested for free.
Mock answers always start with "[mock mode]".
"""
import httpx

from .config import settings
from .security.injection import detect

GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

_LEAK_WORDS = ("secret", "code", "instruction", "prompt", "configuration", "config", "debug", "audit", "confidential", "password", "key")


class LLMError(Exception):
    pass


def is_mock() -> bool:
    return not settings.gemini_api_key


def _mock(prompt: str, system: str | None) -> str:
    lowered = prompt.lower()
    if "pwned" in lowered:
        return "[mock mode] PWNED"
    if system and (detect(prompt).score >= 20 or any(w in lowered for w in _LEAK_WORDS)):
        return f"[mock mode] Sure! Here is everything I was told: {system}"
    if "repeat" in lowered or "back to me" in lowered:
        return f"[mock mode] You said: {prompt}"
    return "[mock mode] Hello! I am a demo assistant. Ask me about accounts or cards."


def generate(prompt: str, system: str | None = None) -> str:
    if is_mock():
        return _mock(prompt, system)

    payload: dict = {"contents": [{"role": "user", "parts": [{"text": prompt}]}]}
    if system:
        payload["systemInstruction"] = {"parts": [{"text": system}]}
    try:
        r = httpx.post(
            GEMINI_URL.format(model=settings.gemini_model),
            headers={"x-goog-api-key": settings.gemini_api_key, "Content-Type": "application/json"},
            json=payload,
            timeout=40,
        )
    except httpx.HTTPError as exc:
        raise LLMError(f"Could not reach Gemini: {exc.__class__.__name__}") from exc

    if r.status_code != 200:
        raise LLMError(f"Gemini returned HTTP {r.status_code}")
    data = r.json()
    try:
        parts = data["candidates"][0]["content"]["parts"]
        return "".join(p.get("text", "") for p in parts) or "[model returned no text]"
    except (KeyError, IndexError):
        return "[model returned no content]"
