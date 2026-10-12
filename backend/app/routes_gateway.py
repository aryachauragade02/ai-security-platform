import hashlib
import time
import uuid
from collections import Counter
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from . import gateway, llm
from .auth import require_gateway_key
from .config import settings
from .security.ratelimit import SlidingWindowLimiter
from .store import get_store

router = APIRouter()
chat_limiter = SlidingWindowLimiter(settings.rate_limit_per_minute, 60)
demo_limiter = SlidingWindowLimiter(settings.demo_rate_limit_per_minute, 60)


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _run(prompt: str, **kwargs) -> dict:
    try:
        return gateway.process(prompt, **kwargs)
    except llm.LLMError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


class ChatIn(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    system: str | None = Field(default=None, max_length=2000)


class DemoIn(BaseModel):
    message: str = Field(min_length=1, max_length=1000)
    protect: bool = True


@router.post("/v1/chat")
def chat(body: ChatIn, request: Request, key: str = Depends(require_gateway_key)):
    """Protected chat: your app sends prompts here instead of calling the model directly."""
    who = "key:" + hashlib.sha256(key.encode()).hexdigest()[:10] if key else client_ip(request)
    if not chat_limiter.allow(who):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    return _run(body.message, client=who, source="api", system=body.system)


@router.post("/v1/demo/chat")
def demo_chat(body: DemoIn, request: Request):
    """Public playground for the dashboard. Talks to a fake bank bot that holds a secret code."""
    ip = client_ip(request)
    if not demo_limiter.allow(ip):
        raise HTTPException(status_code=429, detail="Too many demo requests, wait a minute")
    return _run(
        body.message,
        client=ip,
        source="demo",
        system=gateway.DEMO_SYSTEM,
        protect=body.protect,
        secrets=(gateway.CANARY,),
    )


class OAIMessage(BaseModel):
    role: str
    content: str | list[dict[str, Any]]


class OAIRequest(BaseModel):
    model: str | None = None
    messages: list[OAIMessage] = Field(min_length=1)


def _text(content) -> str:
    if isinstance(content, str):
        return content
    return " ".join(p.get("text", "") for p in content if isinstance(p, dict))


@router.post("/v1/chat/completions")
def openai_compatible(body: OAIRequest, request: Request, key: str = Depends(require_gateway_key)):
    """OpenAI-style endpoint: any app built for the OpenAI API can point its base URL here."""
    who = "key:" + hashlib.sha256(key.encode()).hexdigest()[:10] if key else client_ip(request)
    if not chat_limiter.allow(who):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    system = "\n".join(_text(m.content) for m in body.messages if m.role == "system") or None
    user_msgs = [_text(m.content) for m in body.messages if m.role == "user"]
    if not user_msgs:
        raise HTTPException(status_code=422, detail="At least one user message is required")
    result = _run(user_msgs[-1], client=who, source="openai-compat", system=system)
    text = result["reply"] if not result["blocked"] else "Request blocked by AI Security Platform: " + result["reason"]
    return {
        "id": "chatcmpl-" + uuid.uuid4().hex[:24],
        "object": "chat.completion",
        "created": int(time.time()),
        "model": body.model or settings.gemini_model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": text},
                "finish_reason": "content_filter" if result["blocked"] else "stop",
            }
        ],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        "security": {
            "blocked": result["blocked"],
            "risk_score": result["risk_score"],
            "matched_rules": result["matched_rules"],
        },
    }


@router.get("/v1/logs")
def logs(limit: int = Query(50, ge=1, le=200)):
    return get_store().select("request_logs", limit=limit)


@router.get("/v1/stats")
def stats():
    rows = get_store().select("request_logs", limit=1000)
    total = len(rows)
    blocked = sum(1 for r in rows if r.get("action") == "blocked")
    rules: Counter = Counter()
    pii = 0
    latency = []
    for r in rows:
        rules.update(r.get("matched_rules") or [])
        found = r.get("pii_findings") or {}
        pii += sum((found.get("input") or {}).values()) + sum((found.get("output") or {}).values())
        if r.get("latency_ms") is not None:
            latency.append(r["latency_ms"])
    return {
        "total_requests": total,
        "blocked": blocked,
        "allowed": total - blocked,
        "block_rate": round(100 * blocked / total, 1) if total else 0,
        "pii_redactions": pii,
        "avg_latency_ms": round(sum(latency) / len(latency)) if latency else 0,
        "top_rules": [{"rule": k, "count": v} for k, v in rules.most_common(6)],
    }
