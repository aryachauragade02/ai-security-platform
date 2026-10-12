"""Agent permission layer (OWASP LLM06 Excessive Agency).

Before an AI agent runs a tool, it asks POST /v1/agents/check. The answer is
allow, deny, or require_approval (a human must approve it on the dashboard).
Default is deny: a tool with no policy is never allowed.
"""
import json
import re
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from .auth import require_admin
from .store import get_store

router = APIRouter()

DANGEROUS = [
    re.compile(p, re.I)
    for p in (
        r"rm\s+-rf",
        r"drop\s+table",
        r"delete\s+from\s+\w+\s*(;|$)",
        r"/etc/passwd",
        r"\.\./",
        r"curl\s+[^|]*\|\s*(sh|bash)",
        r"chmod\s+777",
    )
]

DEFAULT_POLICIES = [
    ("support-bot", "search_kb", "allow"),
    ("support-bot", "read_file", "allow"),
    ("support-bot", "send_email", "require_approval"),
    ("support-bot", "delete_file", "deny"),
    ("support-bot", "run_shell", "deny"),
]

Decision = Literal["allow", "deny", "require_approval"]


def seed_default_policies() -> None:
    store = get_store()
    if store.select("agent_policies", limit=1):
        return
    store.insert_many(
        "agent_policies",
        [{"agent_id": a, "tool": t, "decision": d} for a, t, d in DEFAULT_POLICIES],
    )


def decide(agent_id: str, tool: str, arguments: dict) -> tuple[str, str]:
    blob = json.dumps(arguments)
    for pattern in DANGEROUS:
        if pattern.search(blob):
            return "deny", f"Dangerous argument blocked (matched {pattern.pattern})"
    policies = get_store().select("agent_policies", eq={"agent_id": agent_id}, limit=500)
    exact = next((p for p in policies if p["tool"] == tool), None)
    wildcard = next((p for p in policies if p["tool"] == "*"), None)
    policy = exact or wildcard
    if not policy:
        return "deny", "No policy for this tool: denied by default"
    return policy["decision"], "Matched policy for " + (tool if exact else "*")


class CheckIn(BaseModel):
    agent_id: str = Field(min_length=1, max_length=64)
    tool: str = Field(min_length=1, max_length=64)
    arguments: dict[str, Any] = Field(default_factory=dict)


class PolicyIn(BaseModel):
    agent_id: str = Field(min_length=1, max_length=64)
    tool: str = Field(min_length=1, max_length=64)
    decision: Decision


@router.get("/v1/agents/policies")
def list_policies():
    return get_store().select("agent_policies", limit=500, newest_first=False)


@router.put("/v1/agents/policies", dependencies=[Depends(require_admin)])
def set_policy(body: PolicyIn):
    store = get_store()
    existing = store.select("agent_policies", eq={"agent_id": body.agent_id, "tool": body.tool}, limit=1)
    if existing:
        return store.update("agent_policies", {"id": existing[0]["id"]}, {"decision": body.decision})[0]
    return store.insert("agent_policies", body.model_dump())


@router.post("/v1/agents/check")
def check_tool_call(body: CheckIn):
    decision, reason = decide(body.agent_id, body.tool, body.arguments)
    status = {"allow": "allowed", "deny": "denied", "require_approval": "pending"}[decision]
    call = get_store().insert("tool_calls", {
        "agent_id": body.agent_id,
        "tool": body.tool,
        "arguments": body.arguments,
        "decision": decision,
        "status": status,
        "reason": reason,
    })
    return {"call_id": call["id"], "decision": decision, "status": status, "reason": reason}


@router.get("/v1/agents/tool-calls")
def list_tool_calls(limit: int = Query(50, ge=1, le=200)):
    return get_store().select("tool_calls", limit=limit)


def _resolve(call_id: str, new_status: str) -> dict:
    store = get_store()
    rows = store.select("tool_calls", eq={"id": call_id}, limit=1)
    if not rows:
        raise HTTPException(status_code=404, detail="Tool call not found")
    if rows[0]["status"] != "pending":
        raise HTTPException(status_code=409, detail="Only pending calls can be approved or rejected")
    return store.update("tool_calls", {"id": call_id}, {"status": new_status})[0]


@router.post("/v1/agents/tool-calls/{call_id}/approve", dependencies=[Depends(require_admin)])
def approve(call_id: str):
    return _resolve(call_id, "approved")


@router.post("/v1/agents/tool-calls/{call_id}/reject", dependencies=[Depends(require_admin)])
def reject(call_id: str):
    return _resolve(call_id, "rejected")
