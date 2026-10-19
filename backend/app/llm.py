"""Talks to Google Gemini over its REST API.

With no GEMINI_API_KEY it runs in MOCK mode: a fake model that is deliberately
easy to trick, so the whole platform can be demonstrated and tested for free.
Mock answers always start with "[mock mode]".
"""
import time

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


# Models tried in order if the first one is overloaded (503/429) or missing (404).
FALLBACK_MODELS = ("gemini-3.6-flash", "gemini-2.5-flash")
RETRY_STATUS = {429, 500, 502, 503, 504}


def _call(model: str, payload: dict) -> httpx.Response:
    return httpx.post(
        GEMINI_URL.format(model=model),
        headers={"x-goog-api-key": settings.gemini_api_key, "Content-Type": "application/json"},
        json=payload,
        timeout=40,
    )


def generate(prompt: str, system: str | None = None) -> str:
    if is_mock():
        return _mock(prompt, system)

    payload: dict = {"contents": [{"role": "user", "parts": [{"text": prompt}]}]}
    if system:
        payload["systemInstruction"] = {"parts": [{"text": system}]}

    models = [settings.gemini_model] + [m for m in FALLBACK_MODELS if m != settings.gemini_model]
    last_status = None
    for model in models:
        for attempt in range(2):  # one quick retry for a busy server
            try:
                r = _call(model, payload)
            except httpx.HTTPError as exc:
                raise LLMError(f"Could not reach Gemini: {exc.__class__.__name__}") from exc
            if r.status_code == 200:
                data = r.json()
                try:
                    parts = data["candidates"][0]["content"]["parts"]
                    return "".join(p.get("text", "") for p in parts) or "[model returned no text]"
                except (KeyError, IndexError):
                    return "[model returned no content]"
            last_status = r.status_code
            if r.status_code in RETRY_STATUS and attempt == 0:
                time.sleep(1.5)
                continue
            break  # 404 or a persistent error: move on to the next model
    raise LLMError(f"Gemini returned HTTP {last_status} (tried {', '.join(models)}). Try again in a minute.")
