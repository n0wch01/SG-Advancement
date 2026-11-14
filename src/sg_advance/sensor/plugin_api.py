"""Local verdict API for in-process enforcement points (OpenClaw plugin, later Claude Code hooks).

The OpenClaw gateway plugin calls this from ``before_tool_call`` *before* a tool runs::

    plugin ──JSON line──▶ unix socket (SGA_HOME/sga.sock, 0600) ──▶ daemon engine
           ◀──verdict────

Protocol: one JSON object per line, one response line per request.

``{"op": "hello", "plugin": "sg-advance", "version": ...}``
    → ``{"ok": true}``. Marks the plugin as present (enables bypass detection).
``{"op": "bye", "plugin": "sg-advance", "reason": "disposed"}`` → ``{"ok": true}``. The instance is
    being unloaded; a loss is reported unless a new instance says hello within 30s.
``{"op": "tool_call", "agentId", "sessionKey", "sessionId", "runId", "toolCallId", "toolName",
   "toolKind", "params", "requester": {...}}``
    → ``{"ok": true, "decision": "allow"|"block"|"approve"|"hold", "action", "rules", "title", "reason"}``
    ``hold`` (M11 ``security_approval``) adds ``hold_id`` and ``wait_ms``: the plugin then asks
``{"op": "await_hold", "hold_id"}`` → ``{"ok": true, "decision": "allow"|"block", "reason"}`` once
    security decided or the wait ended (sensor/security_hold.py); ``{"op": "cancel_hold", "hold_id"}``
    when the run was aborted meanwhile.

The daemon judges with its stateful engine (sequence/rate rules see every adapter's events) and
records the event with the enforcement the plugin is about to apply. When the daemon is down the
plugin runs ``sga-sensor evaluate`` instead: same request on stdin, stateless judgement from
the signed policy cache, recorded with ``labels.sga_verdict = "degraded"``.

Windows (M12) has no unix socket server in asyncio: the daemon listens on 127.0.0.1 (a random port)
and writes ``SGA_HOME/sga-api.json`` ``{"host", "port", "token"}`` in the user's profile. Every request
must carry ``"auth": token``; anything else on the PC that can reach loopback but not that file is refused.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..detect import Verdict, rule_titles
from ..redact import redact_text
from ..schema import AgentEvent, Enforcement, EventKind, ResponseAction, SensorType
from ..schema.events import ApprovalResolution
from .adapters.base import AdapterContext
from .adapters.openclaw_people import OpenClawPeople
from .security_hold import peer_gone, summary_for

log = logging.getLogger(__name__)

SOCKET_NAME = "sga.sock"
_BLOCKING = {ResponseAction.BLOCK, ResponseAction.ABORT_SESSION, ResponseAction.QUARANTINE}


# ── request → AgentEvent ────────────────────────────────────────────────────


def plugin_event(
    req: dict[str, Any],
    *,
    user_id: str,
    hostname: str | None,
    tool_plugins: dict[str, str],
    people: OpenClawPeople | None = None,
) -> AgentEvent:
    tool = str(req.get("toolName") or "unknown")
    params = req.get("params")
    arguments = params if isinstance(params, dict) else ({} if params is None else {"input": params})
    if tool in tool_plugins:
        provider = {"kind": "plugin", "plugin_id": tool_plugins[tool]}
    else:
        provider = {"kind": "builtin"} if tool_plugins else {"kind": "unknown"}
    return _plugin_envelope(
        req,
        user_id=user_id,
        hostname=hostname,
        people=people,
        payload={
            "kind": "tool.call",
            "call_id": str(req.get("toolCallId") or f"plugin:{time.time_ns()}"),
            "tool": tool,
            "provider": provider,
            "arguments": arguments,
        },
    )


def _plugin_labels(req: dict[str, Any]) -> dict[str, str]:
    labels = {"sga_source": "openclaw_plugin"}
    requester = req.get("requester") if isinstance(req.get("requester"), dict) else {}
    for key in ("channel", "senderId"):  # who asked for this run (M5b attributes users from it)
        if isinstance(requester.get(key), str):
            labels[f"requester_{key.lower()}"] = requester[key]
    if isinstance(req.get("toolKind"), str):
        labels["openclaw.tool_kind"] = req["toolKind"]
    return labels


def _plugin_envelope(
    req: dict[str, Any],
    *,
    user_id: str,
    hostname: str | None,
    payload: dict[str, Any],
    people: OpenClawPeople | None = None,
) -> AgentEvent:
    session_key = req.get("sessionKey") if isinstance(req.get("sessionKey"), str) else None
    run_id = req.get("runId") if isinstance(req.get("runId"), str) else None
    # The plugin's tool context has no gateway profile; the WebSocket side learned who it is.
    people = people or OpenClawPeople()
    who = people.attribute(session_key, run_id, user_id)
    return AgentEvent.model_validate(
        {
            "ts": datetime.now(UTC),
            "endpoint": {"device_id": "pending", "hostname": hostname},
            "principal": who.principal,
            "agent": {
                "type": "openclaw",
                "session_id": session_key or str(req.get("sessionId") or "unknown"),
                "run_id": run_id,
                **people.lineage(session_key),
            },
            "source": {"sensor": "openclaw_plugin"},
            "payload": payload,
            "labels": who.labels | _plugin_labels(req),
        }
    )


_SEVERITY_RANK = ["info", "low", "medium", "high", "critical"]


def max_severity(verdict: Verdict) -> str | None:
    sev = [str(h.rule.severity) for h in verdict.hits]
    return max(sev, key=_SEVERITY_RANK.index) if sev else None


@dataclass(frozen=True)
class EnforcementPoint:
    """Who applies the verdict before the tool runs, for the enforcement record."""

    sensor: SensorType
    name: str  # "openclaw plugin", "claude code hook"
    asks: str  # where a require_approval verdict is answered
    # The point itself sits between the agent and the side effect (it does not forward what it
    # refuses), so a refusal is confirmed on the spot. Hooks and plugins hand the decision to the agent:
    # unconfirmed until evidence arrives (a result for a refused call contradicts it).
    in_path: bool = False

    def outcome(self, in_path_evidence: str) -> dict[str, str]:
        if self.in_path:
            return {"confirmation": "confirmed", "evidence": in_path_evidence}
        return {"confirmation": "unconfirmed", "evidence": f"{self.asks} applies the decision"}


OPENCLAW_PLUGIN = EnforcementPoint(SensorType.OPENCLAW_PLUGIN, "openclaw plugin", "OpenClaw")
CLAUDE_CODE_HOOK = EnforcementPoint(SensorType.CLAUDE_CODE_HOOK, "claude code hook", "Claude Code")
MCP_GATEWAY = EnforcementPoint(
    SensorType.MCP_PROXY, "mcp gateway", "the agent's own approval prompt", in_path=True
)


# Input PEP (KISA agentic AI ZT guide 2.4, P6-7): tool results with injection findings this severe never
# reach the model at the points that can rewrite a result (MCP gateway, Claude Code PostToolUse).
INPUT_GUARD_SEVERITIES = frozenset({"high", "critical"})


def input_guard_hits(verdict: Verdict) -> list[Any]:
    return [
        h for h in verdict.hits
        if str(h.rule.category) == "prompt_injection" and str(h.rule.severity) in INPUT_GUARD_SEVERITIES
    ]  # fmt: skip


def withheld_response(point: EnforcementPoint, hits: list[Any]) -> tuple[dict[str, Any], Enforcement]:
    titles = rule_titles(hits)
    return {
        "ok": True,
        "decision": "withhold",
        "reason": f"SG-Advance: tool result withheld, it looks like a prompt injection ({titles})",
        "rules": [h.rule.id for h in hits],
    }, Enforcement(
        action=ResponseAction.BLOCK,
        enforced=True,
        enforcer=point.sensor,
        detail=f"input pep: {point.name} withheld the tool result from the model",
        stage="result_withheld",
        **(
            point.outcome("the result was replaced before it was sent to the agent")
            if point.in_path
            else {
                "confirmation": "unconfirmed",
                "evidence": "Claude Code keeps the original result if the replacement does not fit the "
                "tool's output shape; the block reason still reaches the model",
            }
        ),
    )


# A rule tagged ``approval:security`` sends its approval to the security hold even where the person could
# be asked. No bundled rule carries it (decision 2026-11-14); a security team can add it to a rule.
SECURITY_HOLD_TAG = "approval:security"


def approval_channel(verdict: Verdict, point: EnforcementPoint) -> ResponseAction:
    """Grades decide *how* approval happens, never whether (CLAUDE.md). Decision 2026-11-14: the person
    approves first, including grade 3-1, and the security team reviews those approvals afterwards (review
    queue, ``user-approved-high-risk``). Only very high risk is blocked outright (the rules' own response).
    A point that cannot ask anyone (the MCP gateway) still goes to the security hold, where the call is
    re-checked and bound to the exact request; so does a rule tagged ``approval:security``.
    Limitation: the agent's own prompt runs the call the moment the person clicks, with no re-check."""
    if verdict.action is ResponseAction.REQUIRE_APPROVAL:
        asking = [h for h in verdict.hits if h.rule.response is ResponseAction.REQUIRE_APPROVAL]
        if point.in_path or any(SECURITY_HOLD_TAG in h.rule.tags for h in asking):
            return ResponseAction.SECURITY_APPROVAL
    return verdict.action


def held_enforcement(point: EnforcementPoint, why: str) -> Enforcement:
    return Enforcement(
        action=ResponseAction.SECURITY_APPROVAL,
        enforced=True,
        enforcer=point.sensor,
        detail=f"pre-exec: held for security approval in the console ({why})",
        stage="held",
        **point.outcome("the request is held by the gateway and not forwarded"),
    )


# Irreversible (grade 3-1) calls the person approves get their own prompt (2026-11-14, KISA guide
# scenario 4: approval fatigue; the user chose "warning text only", the flow stays one click). The
# same text reaches Claude Code's ask dialog (permissionDecisionReason) and OpenClaw's approval card,
# where the plugin also raises the severity to critical. What will run is shown clipped and masked:
# the prompt is local, but a secret in a command has no business in an approval dialog either.
IRREVERSIBLE_TAG = "grade:3-1"
IRREVERSIBLE_TITLE = "SG-Advance: 되돌릴 수 없는 작업 확인"
_WHAT_KEYS = ("command", "cmd", "sql", "query", "statement", "url", "file_path", "path", "prompt")
_WHAT_MAX = 160


def _what_runs(event: AgentEvent) -> str:
    p = event.payload
    args: dict[str, Any] = getattr(p, "arguments", None) or {}
    text = next((str(args[k]) for k in _WHAT_KEYS if isinstance(args.get(k), str) and args[k]), None)
    if text is None:
        text = json.dumps(args, ensure_ascii=False, default=str) if args else ""
    text = " ".join(redact_text(text).split())
    tool = getattr(p, "tool", "") or "tool"
    clipped = text if len(text) <= _WHAT_MAX else text[: _WHAT_MAX - 1] + "…"
    return f"{tool}: {clipped}" if clipped else tool


def irreversible_prompt(verdict: Verdict, titles: str) -> str:
    return (
        f"[되돌릴 수 없음 · 3-1] {titles}. 실행할 것: {_what_runs(verdict.event)}. "
        "한 번 실행하면 되돌릴 수 없습니다. 승인하면 보안팀이 사후 검토합니다."
    )


def plugin_response(
    verdict: Verdict, point: EnforcementPoint = OPENCLAW_PLUGIN, action: ResponseAction | None = None
) -> tuple[dict[str, Any], Enforcement | None]:
    """What the plugin (or hook) should do, and the enforcement record that matches it. ``action``:
    the channel chosen by ``approval_channel`` when it differs from the verdict's."""
    action = action or verdict.action
    rules = verdict.rule_ids
    reason = rule_titles(verdict.hits)
    sensor = point.sensor
    base = {"ok": True, "action": action.value, "rules": rules}
    if severity := max_severity(verdict):
        base["severity"] = severity
    if action in _BLOCKING:
        detail = f"pre-exec: {point.name} blocked the tool call"
        return base | {"decision": "block", "reason": f"SG-Advance: {reason}"}, Enforcement(
            action=action, enforced=True, enforcer=sensor, detail=detail,
            stage="blocked", **point.outcome("the request was not forwarded upstream"),
        )  # fmt: skip
    if action is ResponseAction.SECURITY_APPROVAL:  # no daemon to wait with (cached-policy CLI)
        detail = "pre-exec: security approval needs the sensor daemon; blocked"
        return base | {
            "decision": "block",
            "reason": f"SG-Advance: 보안팀 승인이 필요한 호출이지만 센서 데몬이 없어 차단했습니다 ({reason})",
        }, Enforcement(
            action=ResponseAction.BLOCK, enforced=True, enforcer=sensor, detail=detail,
            stage="blocked", **point.outcome("the request was not forwarded upstream"),
        )  # fmt: skip
    if action is ResponseAction.REQUIRE_APPROVAL:
        detail = f"pre-exec: user approval requested through {point.asks}"
        if any(IRREVERSIBLE_TAG in h.rule.tags for h in verdict.hits):
            base |= {"grade": "3-1"}  # the plugin raises its approval card to critical
            prompt = {"title": IRREVERSIBLE_TITLE, "reason": irreversible_prompt(verdict, reason)}
        else:
            prompt = {"title": "SG-Advance", "reason": reason}
        return base | {"decision": "approve"} | prompt, Enforcement(
            action=action, enforced=True, enforcer=sensor, detail=detail
        )
    return base | {"decision": "allow"}, None


def finding_ids_for(verdict: Any, action: ResponseAction) -> list[str]:
    """The findings a hold or approval record points at. A hold or block also reports the hits dedup
    suppressed (``Sensor._enforced_repeats``); the agent's own prompt does not, so it doesn't list them."""
    if action is ResponseAction.REQUIRE_APPROVAL:
        return [f.finding_id for f in verdict.findings]
    return verdict.enforced_ids


def pending_for(result: Any, action: ResponseAction, response: dict[str, Any]) -> dict[str, Any]:
    """What a prompt or a hold keeps about the call, to link the answer back to it."""
    return {
        "event_id": result.event.event_id,
        "finding_ids": finding_ids_for(result.verdict, action),
        "rule_ids": result.verdict.rule_ids,
        "max_severity": response.get("severity"),
        "requested_at": result.event.ts,
    }


def hold_reason(point: EnforcementPoint, verdict: Verdict) -> str:
    """Why a call went to security instead of the person (the enforcement record's detail)."""
    if verdict.action is not ResponseAction.REQUIRE_APPROVAL:
        return "policy"  # the rule (or a team policy) asks for security itself
    return "the gateway cannot ask the person" if point.in_path else SECURITY_HOLD_TAG


def open_hold(
    ctx: AdapterContext,
    result: Any,
    response: dict[str, Any],
    pending: dict[str, Any],
    point: EnforcementPoint,
    req: dict[str, Any],
) -> tuple[dict[str, Any], Enforcement]:
    """Hold the call for security (the one place both the plugin and event paths open a hold)."""
    assert ctx.holds is not None
    response = {k: v for k, v in response.items() if k != "reason"}
    response["reason"] = rule_titles(result.verdict.hits)
    hold = ctx.holds.open(req, pending, summary_for(result.event, response, pending), call_event=result.event)
    response |= {"decision": "hold", "hold_id": hold.id, "wait_ms": int(ctx.holds.wait_seconds * 1000)}
    return response, held_enforcement(point, hold_reason(point, result.verdict))


def judge(
    ctx: AdapterContext, req: dict[str, Any], *, labels: dict[str, str] | None = None
) -> dict[str, Any]:
    """Evaluate one plugin request with the sensor's engine and record it."""
    event = plugin_event(
        req,
        user_id=ctx.user_id,
        hostname=ctx.hostname,
        tool_plugins=ctx.plugins.tool_plugins,
        people=ctx.people,
    )
    if labels:
        event = event.model_copy(update={"labels": event.labels | labels})
    result = ctx.evaluate(event)
    action = approval_channel(result.verdict, OPENCLAW_PLUGIN)
    response, enforcement = plugin_response(result.verdict, OPENCLAW_PLUGIN, action)
    pending = pending_for(result, action, response)
    if action is ResponseAction.SECURITY_APPROVAL and ctx.holds is not None:
        response, enforcement = open_hold(ctx, result, response, pending, OPENCLAW_PLUGIN, req)
    ctx.record(result, enforcement)
    call_id = event.payload.call_id  # type: ignore[union-attr]
    ctx.plugins.mark(call_id)
    if response.get("decision") == "approve":  # keep what asked, to link the person's answer
        ctx.plugins.remember_approval(call_id, pending)
    return response


def resolution_from_call(
    call: AgentEvent,
    decision: str,
    pending: dict[str, Any],
    *,
    approver: str | None = None,
    via: str = "user",
    labels: dict[str, str] | None = None,
) -> AgentEvent:
    """``approval.resolved`` in the same envelope (who, which agent, which conversation) as the
    tool call that was held. For enforcement points that hand over a full event (Claude Code)."""
    requested_at = pending.get("requested_at")
    now = datetime.now(UTC)
    wait_ms = int((now - requested_at).total_seconds() * 1000) if requested_at else None
    p = call.payload
    return call.model_copy(
        update={
            "event_id": AgentEvent.model_fields["event_id"].default_factory(),  # type: ignore[misc]
            "ts": now,
            "payload": ApprovalResolution(
                call_id=p.call_id,  # type: ignore[union-attr]
                tool=p.tool,  # type: ignore[union-attr]
                decision=decision,  # type: ignore[arg-type]
                approved=decision in ("allow-once", "allow-always"),
                rule_ids=tuple(pending.get("rule_ids") or ()),
                max_severity=pending.get("max_severity"),
                request_event_id=pending.get("event_id"),
                finding_ids=tuple(pending.get("finding_ids") or ()),
                requested_at=requested_at,
                wait_ms=max(wait_ms, 0) if wait_ms is not None else None,
                approver=approver,
                via=via,  # type: ignore[arg-type]
            ),
            "labels": call.labels | (labels or {}),
        }
    )


def judge_event(
    ctx: AdapterContext, doc: dict[str, Any], point: EnforcementPoint = CLAUDE_CODE_HOOK
) -> dict[str, Any]:
    """Judge and record an event an enforcement point built itself (Claude Code hooks, M6).

    ``tool.call``: the same verdicts as the OpenClaw plugin (block / approve → the agent's own
    prompt / hold for security / allow). ``prompt.user``: blocked only by a blocking verdict.
    Anything else is recorded. A ``tool.result`` for a call that was sent to the person's own
    prompt means they approved it: recorded as ``approval.resolved`` (a refusal leaves no result,
    so it cannot be told apart from an abandoned call)."""
    event = AgentEvent.model_validate(doc)
    result = ctx.evaluate(event)
    kind = result.event.kind
    if kind is EventKind.TOOL_CALL:
        action = approval_channel(result.verdict, point)
        response, enforcement = plugin_response(result.verdict, point, action)
        pending = pending_for(result, action, response) | {"call": result.event}
        if action is ResponseAction.SECURITY_APPROVAL and ctx.holds is not None:
            tool_req = {"toolName": result.event.payload.tool}  # type: ignore[union-attr]
            response, enforcement = open_hold(ctx, result, response, pending, point, tool_req)
        ctx.record(result, enforcement)
        if response.get("decision") == "approve" and point.sensor is SensorType.CLAUDE_CODE_HOOK:
            # Claude Code asked the person: a later result means they approved. The MCP gateway asks no one.
            ctx.plugins.remember_approval(result.event.payload.call_id, pending)  # type: ignore[union-attr]
        return response
    withheld: dict[str, Any] | None = None
    if kind is EventKind.TOOL_RESULT and (hits := input_guard_hits(result.verdict)):
        withheld, enforcement = withheld_response(point, hits)
        ctx.record(result, enforcement)
    else:
        ctx.record(result)
    if kind is EventKind.TOOL_RESULT:
        asked = ctx.plugins.take_approval(result.event.payload.call_id)  # type: ignore[union-attr]
        if asked and isinstance(asked.get("call"), AgentEvent):
            inferred = resolution_from_call(
                asked["call"], "allow-once", asked, labels={"sga_approval_inferred": "tool_result"}
            )
            ctx.record(ctx.evaluate(inferred))
    if withheld is not None:
        return withheld
    if kind is EventKind.PROMPT_USER and result.verdict.action in _BLOCKING:
        reason = rule_titles(result.verdict.hits)
        return {
            "ok": True,
            "decision": "block",
            "reason": f"SG-Advance: {reason}",
            "rules": result.verdict.rule_ids,
        }
    return {"ok": True, "decision": "allow"}


DECISIONS = ("allow-once", "allow-always", "deny", "timeout", "cancelled")


def resolution_event(
    ctx: AdapterContext, req: dict[str, Any], pending: dict[str, Any] | None = None
) -> AgentEvent:
    """``approval.resolved`` from the plugin's ``onResolution``. ``pending`` (daemon memory) links
    it to the held tool.call and its findings; without it (daemon restarted, or the cached-policy
    CLI asked) the plugin's own copy of rules, severity and request time is used."""
    decision = req.get("decision")
    if decision not in DECISIONS:
        raise ValueError(f"unknown decision {decision!r}")
    pending = pending or {}
    requested_at = pending.get("requested_at")
    if requested_at is None and isinstance(req.get("requestedAt"), int | float):
        requested_at = datetime.fromtimestamp(req["requestedAt"] / 1000, UTC)
    now = datetime.now(UTC)
    wait_ms = int((now - requested_at).total_seconds() * 1000) if requested_at else None
    judged_by = req.get("source") if req.get("source") in ("daemon", "degraded", "fallback") else "daemon"
    rules = pending.get("rule_ids") or [r for r in (req.get("rules") or []) if isinstance(r, str)]
    return _plugin_envelope(
        req,
        user_id=ctx.user_id,
        hostname=ctx.hostname,
        people=ctx.people,
        payload={
            "kind": "approval.resolved",
            "call_id": str(req.get("toolCallId") or "unknown"),
            "tool": str(req.get("toolName") or "unknown"),
            "decision": decision,
            "approved": decision in ("allow-once", "allow-always"),
            "rule_ids": rules,
            "max_severity": pending.get("max_severity") or req.get("severity"),
            "request_event_id": pending.get("event_id"),
            "finding_ids": pending.get("finding_ids") or [],
            "requested_at": requested_at,
            "wait_ms": max(wait_ms, 0) if wait_ms is not None else None,
            "judged_by": judged_by,
        },
    )


def record_resolution(ctx: AdapterContext, req: dict[str, Any]) -> AgentEvent:
    pending = ctx.plugins.take_approval(str(req.get("toolCallId") or ""))
    event = resolution_event(ctx, req, pending)
    ctx.record(ctx.evaluate(event))
    p = event.payload
    log.info("approval %s for %s (%s)", p.decision, p.tool, ", ".join(p.rule_ids) or "no rules")  # type: ignore[union-attr]
    return event


def record_health(ctx: AdapterContext, status: str, detail: str, last_seen: float | None = None) -> None:
    """Report the plugin's liveness as an event, so rules (and the console) see control gaps."""
    payload: dict[str, Any] = {
        "kind": "sensor.health",
        "component": "openclaw_plugin",
        "status": status,
        "detail": detail,
    }
    if last_seen is not None:
        payload["last_seen"] = datetime.fromtimestamp(last_seen, UTC)
    event = AgentEvent.model_validate(
        {
            "ts": datetime.now(UTC),
            "endpoint": {"device_id": "pending", "hostname": ctx.hostname},
            "principal": {"user_id": ctx.user_id},
            "agent": {"type": "openclaw", "session_id": "sensor:openclaw_plugin"},
            "source": {"sensor": "openclaw_plugin"},
            "payload": payload,
        }
    )
    ctx.record(ctx.evaluate(event))


# ── unix socket server ──────────────────────────────────────────────────────


ENDPOINT_FILE = "sga-api.json"


class LocalApiServer:
    """``path``: a unix socket (macOS, Linux). ``tcp=True``: loopback TCP + token, the endpoint
    written to ``path`` instead (Windows)."""

    def __init__(self, ctx: AdapterContext, path: Path, *, tcp: bool = False) -> None:
        self.ctx = ctx
        self.path = path
        self.tcp = tcp
        self.token: str | None = None
        self._server: asyncio.base_events.Server | None = None

    async def start(self) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.tcp:
            import secrets

            from .state import write_private

            self.token = secrets.token_urlsafe(32)
            self._server = await asyncio.start_server(self._client, host="127.0.0.1", port=0)
            port = self._server.sockets[0].getsockname()[1]
            endpoint = {"host": "127.0.0.1", "port": port, "token": self.token, "pid": os.getpid()}
            write_private(self.path, json.dumps(endpoint))
            log.info("local verdict API listening on 127.0.0.1:%d (endpoint %s)", port, self.path)
            return
        with contextlib.suppress(FileNotFoundError):
            self.path.unlink()  # stale socket from a previous run
        old = os.umask(0o177)  # socket created 0600: only this user's processes may ask
        try:
            self._server = await asyncio.start_unix_server(self._client, path=str(self.path))
        finally:
            os.umask(old)
        log.info("local verdict API listening on %s", self.path)

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
        with contextlib.suppress(FileNotFoundError):
            self.path.unlink()

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while line := await reader.readline():
                writer.write((json.dumps(await self.handle_async(line, reader)) + "\n").encode())
                await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    def _authorized(self, req: object) -> bool:
        if self.token is None:  # unix socket: the 0600 file is the access control
            return True
        import hmac

        given = req.get("auth") if isinstance(req, dict) else None
        return isinstance(given, str) and hmac.compare_digest(given, self.token)

    async def handle_async(self, line: bytes, reader: asyncio.StreamReader | None = None) -> dict[str, Any]:
        """``await_hold`` waits (up to minutes) for security; everything else answers at once. With the
        requester's ``reader``, the hold is cancelled if it closes the connection while waiting."""
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            req = None
        if self.token is not None and not self._authorized(req):
            return {"ok": False, "error": "unauthorized"}
        if isinstance(req, dict) and req.get("op") == "await_hold":
            if self.ctx.holds is None:
                return {"ok": False, "error": "security approval is not available"}
            self.ctx.plugins.touch()
            hold_id = str(req.get("hold_id") or "")
            if reader is None:
                return await self.ctx.holds.wait(self.ctx, hold_id)
            return await self.ctx.holds.wait_while(self.ctx, hold_id, peer_gone(reader))
        return self.handle(line)

    def handle(self, line: bytes) -> dict[str, Any]:
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            return {"ok": False, "error": "invalid json"}
        if not isinstance(req, dict):
            return {"ok": False, "error": "expected an object"}
        op = req.get("op")
        if op == "bye":  # disposed by the gateway (plugin disabled, removed, replaced, or shutdown)
            log.warning("openclaw plugin unloaded: %s (%s)", req.get("plugin"), req.get("reason"))
            self.ctx.plugins.goodbye()
            return {"ok": True}
        transition = self.ctx.plugins.heartbeat() if op == "hello" else self.ctx.plugins.touch()
        if transition == "recovered":
            log.warning("openclaw plugin is back")
            record_health(self.ctx, "recovered", "plugin contacted the sensor again")
        if op == "hello":
            log.info("openclaw plugin connected: %s %s", req.get("plugin"), req.get("version"))
            return {"ok": True}
        if op == "tool_call":
            try:
                return judge(self.ctx, req)
            except Exception as e:  # the plugin falls back on its own; tell it why
                log.exception("plugin request failed")
                return {"ok": False, "error": str(e)}
        if op == "event":  # Claude Code hooks (M6): a full AgentEvent built by the hook
            if not isinstance(req.get("event"), dict):
                return {"ok": False, "error": "event must be an object"}
            try:
                return judge_event(self.ctx, req["event"])
            except Exception as e:  # validation errors included: the hook falls back on its own
                log.exception("hook event failed")
                return {"ok": False, "error": str(e)[:500]}
        if op == "cancel_hold":  # the run was aborted while security had not decided yet
            holds, hold_id = self.ctx.holds, str(req.get("hold_id") or "")
            found = holds is not None and holds.resolve(hold_id, "cancelled")
            return {"ok": True, "found": found}
        if op == "resolution":  # a person's answer to a requireApproval prompt (audit trail)
            try:
                record_resolution(self.ctx, req)
            except ValueError as e:
                return {"ok": False, "error": str(e)}
            return {"ok": True}
        return {"ok": False, "error": f"unknown op {op!r}"}
