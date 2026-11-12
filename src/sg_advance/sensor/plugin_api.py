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
    → ``{"ok": true, "decision": "allow"|"block"|"approve", "action", "rules", "title", "reason"}``

The daemon judges with its stateful engine (sequence/rate rules see every adapter's events) and
records the event with the enforcement the plugin is about to apply. When the daemon is down the
plugin runs ``sga-sensor evaluate`` instead: same request on stdin, stateless judgement from
the signed policy cache, recorded with ``labels.sga_verdict = "degraded"``.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..detect import Verdict
from ..schema import AgentEvent, Enforcement, ResponseAction, SensorType
from .adapters.base import AdapterContext
from .adapters.openclaw_people import OpenClawPeople

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
    who = (people or OpenClawPeople()).attribute(session_key, run_id, user_id)
    return AgentEvent.model_validate(
        {
            "ts": datetime.now(UTC),
            "endpoint": {"device_id": "pending", "hostname": hostname},
            "principal": who.principal,
            "agent": {
                "type": "openclaw",
                "session_id": session_key or str(req.get("sessionId") or "unknown"),
                "run_id": run_id,
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


def plugin_response(verdict: Verdict) -> tuple[dict[str, Any], Enforcement | None]:
    """What the plugin should do, and the enforcement record that matches it."""
    action = verdict.action
    rules = verdict.rule_ids
    titles = [h.rule.title for h in verdict.hits]
    reason = "; ".join(dict.fromkeys(titles)) or "policy"
    sensor = SensorType.OPENCLAW_PLUGIN
    base = {"ok": True, "action": action.value, "rules": rules}
    if severity := max_severity(verdict):
        base["severity"] = severity
    if action in _BLOCKING:
        detail = "pre-exec: openclaw plugin blocked the tool call"
        return base | {"decision": "block", "reason": f"SG-Advance: {reason}"}, Enforcement(
            action=action, enforced=True, enforcer=sensor, detail=detail
        )
    if action is ResponseAction.REQUIRE_APPROVAL:
        detail = "pre-exec: user approval requested through OpenClaw"
        return base | {"decision": "approve", "title": "SG-Advance", "reason": reason}, Enforcement(
            action=action, enforced=True, enforcer=sensor, detail=detail
        )
    return base | {"decision": "allow"}, None


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
    response, enforcement = plugin_response(result.verdict)
    ctx.record(result, enforcement)
    call_id = event.payload.call_id  # type: ignore[union-attr]
    ctx.plugins.mark(call_id)
    if response.get("decision") == "approve":  # keep what asked, to link the person's answer
        ctx.plugins.remember_approval(
            call_id,
            {
                "event_id": result.event.event_id,
                "finding_ids": [f.finding_id for f in result.verdict.findings],
                "rule_ids": result.verdict.rule_ids,
                "max_severity": response.get("severity"),
                "requested_at": result.event.ts,
            },
        )
    return response


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


class LocalApiServer:
    def __init__(self, ctx: AdapterContext, path: Path) -> None:
        self.ctx = ctx
        self.path = path
        self._server: asyncio.base_events.Server | None = None

    async def start(self) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
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
                writer.write((json.dumps(self.handle(line)) + "\n").encode())
                await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

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
        if op == "resolution":  # a person's answer to a requireApproval prompt (audit trail)
            try:
                record_resolution(self.ctx, req)
            except ValueError as e:
                return {"ok": False, "error": str(e)}
            return {"ok": True}
        return {"ok": False, "error": f"unknown op {op!r}"}
