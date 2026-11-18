"""Protected repository MCP endpoint: authorize at the actual file boundary, then record effects."""

from __future__ import annotations

import hashlib
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy.orm import Session

from ..detect import Engine
from ..schema import AgentEvent, Enforcement, Finding, ResponseAction, SensorType
from ..sensor.actions import labels_for
from ..sensor.decision import (
    EnforcementPoint,
    approval_channel,
    input_guard_hits,
    point_response,
    withheld_response,
)
from ..task_grants import DENIAL_META, GrantError, TaskClaims, relative_path, verify_task
from . import audit_chain, resource_files
from .auth import DbSession
from .db import Device, Project, utcnow
from .policy_admin import policy_for
from .records import store_event, store_finding
from .task_access import CurrentDevice, online_claims

router = APIRouter(prefix="/v1/resources", tags=["protected resources"])
POINT = EnforcementPoint(
    SensorType.MCP_PROXY, "protected repository gateway", "none", in_path=True, supports_approval=False
)
TOOLS = [
    {
        "name": "read_file",
        "description": "Read a file from the task's protected repository",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False},
    },
    {
        "name": "write_file",
        "description": "Replace a file within the task's authorized source or test scope",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
            "required": ["path", "content"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": False},
    },
    {
        "name": "create_pr",
        "description": "Record a pull request from a pushed work branch (feature/, fix/, test/) to main",
        "inputSchema": {
            "type": "object",
            "properties": {"branch": {"type": "string"}, "title": {"type": "string"}},
            "required": ["branch", "title"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
    },
    {
        "name": "run_ci",
        "description": "Run the project's configured CI on a pushed work branch",
        "inputSchema": {
            "type": "object",
            "properties": {"branch": {"type": "string"}},
            "required": ["branch"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
    },
]
GIT_TOOLS = {"create_pr": "pr.create", "run_ci": "ci.run"}  # tool → the grant action it needs


class ReadArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str = Field(min_length=1, max_length=512)


class WriteArgs(ReadArgs):
    content: str = Field(max_length=resource_files.MAX_FILE_BYTES)


def denial(mid: Any, text: str) -> dict[str, Any]:
    """A refusal written by this server (authorization, threat policy, invalid input, failed operation),
    never resource content or CI output. The mark lets the endpoint's protected-resource gateway tell the
    server's own wording from external input (2026-11-19: the injection classifier scored "task
    authorization denied: grant_revoked" 1.0). Only honoured from a protected resource upstream."""
    out = tool_result(mid, text, True)
    out["result"]["_meta"] = {DENIAL_META: True}
    return out


def tool_result(mid: Any, text: str, error: bool = False) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": mid,
        "result": {
            "content": [{"type": "text", "text": text}],
            "isError": error,
        },
    }


def operation_event(
    device: Device, claims: TaskClaims, payload: dict[str, Any], *, authorized: bool = True
) -> AgentEvent:
    event = AgentEvent.model_validate(
        {
            "ts": utcnow(),
            "endpoint": {"device_id": device.device_id},
            "principal": {"user_id": claims.user_id},
            "agent": {"type": claims.agent_type, "session_id": claims.session_id},
            "source": {"sensor": "mcp_proxy"},
            "payload": payload,
            "labels": {
                "sga_source": "protected_repository",
                "sga_task_grant_id": claims.grant_id,
                "sga_authorization": "allow" if authorized else "deny",
                "sga_input_source": "mcp:protected-repository",
            },
        }
    )
    return event.model_copy(
        update={"labels": event.labels | labels_for(event) | ({"sga_posture": "ok"} if authorized else {})}
    )


def record(
    db: Session,
    device: Device,
    event: AgentEvent,
    findings: list[Finding],
    enforcement: Enforcement | None = None,
) -> None:
    """Inspection sees the original; storage retains metadata instead of repository contents."""
    payload = event.payload
    if event.kind == "tool.call" and "content" in payload.arguments:
        arguments = dict(payload.arguments)
        content = str(arguments.pop("content"))
        arguments["content_sha256"] = hashlib.sha256(content.encode()).hexdigest()
        event = event.model_copy(update={"payload": payload.model_copy(update={"arguments": arguments})})
    elif event.kind == "tool.result":
        event = event.model_copy(
            update={
                "payload": payload.model_copy(
                    update={
                        "output_preview": "[protected repository output omitted]",
                    }
                )
            }
        )
    now = utcnow()
    store_event(db, device, event, now, server_built=True)  # this gateway is the control plane
    for finding in findings:
        if enforcement is not None:
            finding = finding.model_copy(update={"response": enforcement})
        store_finding(db, device.device_id, finding, now, server_built=True)
    db.commit()


def auth_failure(
    request: Request,
    db: Session,
    device: Device,
    token: str,
    code: str,
    payload: dict[str, Any] | None = None,
    evidence: str = "file I/O was not invoked",
) -> None:
    audit_chain.append(
        db,
        "resource_denial",
        uuid4().hex,
        {
            "device_id": device.device_id,
            "reason": code,
            "stage": "blocked",
            "confirmation": "confirmed",
        },
    )
    try:
        claims = verify_task(token, request.app.state.signing_key.public_key())
    except GrantError:
        db.commit()
        return
    if claims.device_id != device.device_id:
        db.commit()
        return
    # A signature proves the claims' origin, not current authority. A revoked registration is
    # still stored as unscoped by the common collection path; it cannot grant someone visibility.
    event = operation_event(
        device,
        claims,
        payload
        or {
            "kind": "tool.call",
            "call_id": uuid4().hex,
            "tool": "protected-resource",
            "arguments": {},
        },
        authorized=False,
    )
    finding = Finding(
        ts=event.ts,
        rule_id="task-authorization-denied",
        severity="medium",
        category="tool_misuse",
        title="작업 권한 거부",
        explanation=code,
        principal=event.principal,
        agent=event.agent,
        endpoint=event.endpoint,
        evidence_event_ids=(event.event_id,),
        labels=event.labels,
    )
    enforcement = Enforcement(
        action=ResponseAction.BLOCK,
        enforced=True,
        enforcer=SensorType.MCP_PROXY,
        stage="blocked",
        confirmation="confirmed",
        evidence=evidence,
    )
    record(db, device, event, [finding], enforcement)


def judge_in_session(request: Request, device: Device, session_id: str, event: AgentEvent) -> Any:
    """The session's own engine (server/gateway_state.py): sequence rules, rate limits and dedup see the
    session's earlier calls at this gateway, as the endpoint daemon's engine does."""
    policy = policy_for(request.app, device.group_name, device.device_id)
    key = request.app.state.signing_key.public_key()
    return request.app.state.session_engines.process(
        device.device_id, session_id, policy, lambda: Engine(policy.to_ruleset(key)), event
    )


def call_tool(
    request: Request, db: Session, device: Device, token: str, mid: Any, params: dict[str, Any]
) -> dict[str, Any]:
    name = params.get("name")
    if name in GIT_TOOLS:
        return call_git_tool(request, db, device, token, mid, str(name), params.get("arguments") or {})
    if name not in {"read_file", "write_file"}:
        return denial(mid, "Unsupported protected resource tool")
    try:
        args = (WriteArgs if name == "write_file" else ReadArgs).model_validate(params.get("arguments") or {})
        path = relative_path(args.path)
        action = resource_files.permission_for(path, write=name == "write_file")
    except (ValueError, ValidationError):
        auth_failure(request, db, device, token, "unsupported_or_invalid_resource")
        return denial(mid, "Task authorization denied: unsupported or invalid resource")
    payload = {
        "kind": "tool.call",
        "call_id": uuid4().hex,
        "tool": "Write" if name == "write_file" else "Read",
        "provider": {"kind": "mcp", "mcp_server": "protected-repository"},
        "arguments": args.model_dump() | {"path": path},
    }
    try:
        claims = online_claims(request, token, device_id=device.device_id, action=action, path=path)
    except HTTPException as exc:
        auth_failure(request, db, device, token, str(exc.detail), payload)
        return denial(mid, str(exc.detail))
    project = db.get(Project, claims.project_id)
    assert project is not None and project.workspace_root is not None
    event = operation_event(device, claims, payload)
    verdict = judge_in_session(request, device, claims.session_id, event)
    response, enforcement = point_response(verdict, POINT, approval_channel(verdict, POINT))
    if response["decision"] != "allow":
        record(db, device, event, verdict.findings + verdict.enforcing_repeats, enforcement)
        return denial(mid, response.get("reason", "Blocked by threat policy"))
    audit_chain.append(
        db,
        "resource_operation",
        event.event_id,
        {
            "actor": claims.user_id,
            "grant_id": claims.grant_id,
            "path": path,
            "action": action,
            "stage": "authorized",
            "project_id": claims.project_id,
        },
    )
    record(db, device, event, verdict.findings)  # durable intent before any file operation
    try:
        root = resource_files.project_root(request.app.state.settings.resource_root, project.workspace_root)
        online_claims(request, token, device_id=device.device_id, action=action, path=path)
        if isinstance(args, WriteArgs):
            resource_files.write_file(root, path, args.content)
            text = "Protected file updated"
        else:
            text = resource_files.read_file(root, path)
    except (HTTPException, GrantError, OSError, UnicodeError) as exc:
        reason = str(exc.detail) if isinstance(exc, HTTPException) else "Protected file access failed"
        confirmation = "confirmed" if isinstance(exc, HTTPException) else "unconfirmed"
        if isinstance(args, WriteArgs) and not isinstance(exc, HTTPException):
            reason = "Protected write failed or may have completed. Inspect the file before retrying."
        audit_chain.append(
            db,
            "resource_outcome",
            event.event_id,
            {
                "stage": "failed",
                "confirmation": confirmation,
                "reason": reason,
            },
        )
        db.commit()
        return denial(mid, reason)
    result_event = operation_event(
        device,
        claims,
        {
            "kind": "tool.result",
            "call_id": payload["call_id"],
            "tool": payload["tool"],
            "provider": payload["provider"],
            "ok": True,
            "output_preview": text,
            "output_bytes": len(text.encode()),
        },
    )
    result_verdict = judge_in_session(request, device, claims.session_id, result_event)
    hits = input_guard_hits(result_verdict)
    enforcement = None
    if hits:
        replacement, enforcement = withheld_response(POINT, hits)
        text = replacement["reason"]
    audit_chain.append(
        db,
        "resource_outcome",
        event.event_id,
        {
            "actor": claims.user_id,
            "grant_id": claims.grant_id,
            "project_id": claims.project_id,
            "stage": "result_withheld" if hits else "applied",
            "confirmation": "confirmed",
        },
    )
    try:
        record(
            db, device, result_event, result_verdict.findings + result_verdict.enforcing_repeats, enforcement
        )
    except Exception:
        db.rollback()
        return denial(
            mid, "Operation may have completed; outcome recording failed. Do not retry automatically."
        )
    return denial(mid, text) if hits else tool_result(mid, text)  # withheld: the server's notice


def call_git_tool(
    request: Request, db: Session, device: Device, token: str, mid: Any, name: str, args: dict[str, Any]
) -> dict[str, Any]:
    """PR records and CI runs on the project's repository (server/resource_git.py)."""
    from . import resource_git

    payload = {
        "kind": "tool.call",
        "call_id": uuid4().hex,
        "tool": name,
        "provider": {"kind": "mcp", "mcp_server": "protected-repository"},
        "arguments": {k: str(v)[:200] for k, v in args.items() if k in {"branch", "title"}},
    }
    if not isinstance(args, dict) or set(args) - {"branch", "title"}:
        return denial(mid, "Task authorization denied: invalid arguments")
    try:
        claims = online_claims(request, token, device_id=device.device_id, action=GIT_TOOLS[name])
    except HTTPException as exc:
        auth_failure(
            request, db, device, token, str(exc.detail), payload, evidence="the operation was not run"
        )
        return denial(mid, str(exc.detail))
    if reason := resource_git.threat_check(request, db, device, claims, payload):
        return denial(mid, reason)
    try:
        # Right before it runs: the newest state, not the state at the first check.
        online_claims(request, token, device_id=device.device_id, action=GIT_TOOLS[name])
        if name == "create_pr":
            return tool_result(mid, resource_git.create_pr(request, db, device, claims, args))
        text, passed = resource_git.run_ci(request, db, device, claims, args)
        return tool_result(mid, text, not passed)
    except HTTPException as exc:
        return denial(mid, str(exc.detail))
    except GrantError as exc:
        return denial(mid, str(exc))


def safe_call_tool(
    request: Request, db: Session, device: Device, token: str, mid: Any, params: dict[str, Any]
) -> dict[str, Any]:
    try:
        return call_tool(request, db, device, token, mid, params)
    except Exception:
        db.rollback()
        return denial(mid, "Protected operation failed; inspect its recorded intent before retrying.")


@router.post("/mcp")
async def mcp(request: Request, device: CurrentDevice, db: DbSession) -> Any:
    if request.app.state.settings.resource_root is None:
        raise HTTPException(503, "protected resources are disabled")
    raw = bytearray()
    async for chunk in request.stream():
        raw.extend(chunk)
        if len(raw) > 2 * resource_files.MAX_FILE_BYTES:
            raise HTTPException(413, "oversized protected resource request")
    import json

    try:
        doc = json.loads(raw)
    except ValueError as exc:
        raise HTTPException(400, "invalid MCP request") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("params", {}), dict):
        raise HTTPException(400, "an individual MCP request is required")
    mid, method, params = doc.get("id"), doc.get("method"), doc.get("params") or {}
    if method in {"notifications/initialized", "notifications/cancelled"}:
        return Response(status_code=202)
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": mid,
            "result": {
                "protocolVersion": params.get("protocolVersion", "2024-11-05"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "sg-advance-protected-repository", "version": "1"},
            },
        }
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": mid, "result": {}}
    if method == "tools/call":
        if mid is None or isinstance(mid, bool) or not isinstance(mid, str | int):
            raise HTTPException(400, "tool calls require a request ID")
        # File I/O, SQL and policy work must not block the ASGI loop while the body is already read.
        import asyncio

        return await asyncio.to_thread(
            safe_call_tool, request, db, device, request.headers.get("x-sga-task-grant", ""), mid, params
        )
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "method not found"}}
