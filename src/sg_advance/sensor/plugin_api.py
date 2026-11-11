"""Local verdict API for in-process enforcement points (OpenClaw plugin, later Claude Code hooks).

The OpenClaw gateway plugin calls this from ``before_tool_call`` *before* a tool runs::

    plugin ──JSON line──▶ unix socket (SENTINEL_HOME/sentinel.sock, 0600) ──▶ daemon engine
           ◀──verdict────

Protocol: one JSON object per line, one response line per request.

``{"op": "hello", "plugin": "agent-sentinel", "version": ...}``
    → ``{"ok": true}``. Marks the plugin as present (enables bypass detection).
``{"op": "tool_call", "agentId", "sessionKey", "sessionId", "runId", "toolCallId", "toolName",
   "toolKind", "params", "requester": {...}}``
    → ``{"ok": true, "decision": "allow"|"block"|"approve", "action", "rules", "title", "reason"}``

The daemon judges with its stateful engine (sequence/rate rules see every adapter's events) and
records the event with the enforcement the plugin is about to apply. When the daemon is down the
plugin runs ``sentinel-sensor evaluate`` instead: same request on stdin, stateless judgement from
the signed policy cache, recorded with ``labels.sentinel_verdict = "degraded"``.
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

log = logging.getLogger(__name__)

SOCKET_NAME = "sentinel.sock"
_BLOCKING = {ResponseAction.BLOCK, ResponseAction.ABORT_SESSION, ResponseAction.QUARANTINE}


# ── request → AgentEvent ────────────────────────────────────────────────────


def plugin_event(
    req: dict[str, Any], *, user_id: str, hostname: str | None, tool_plugins: dict[str, str]
) -> AgentEvent:
    tool = str(req.get("toolName") or "unknown")
    params = req.get("params")
    arguments = params if isinstance(params, dict) else ({} if params is None else {"input": params})
    if tool in tool_plugins:
        provider = {"kind": "plugin", "plugin_id": tool_plugins[tool]}
    else:
        provider = {"kind": "builtin"} if tool_plugins else {"kind": "unknown"}
    labels = {"sentinel_source": "openclaw_plugin"}
    requester = req.get("requester") if isinstance(req.get("requester"), dict) else {}
    for key in ("channel", "senderId"):  # who asked for this run (M5b attributes users from it)
        if isinstance(requester.get(key), str):
            labels[f"requester_{key.lower()}"] = requester[key]
    if isinstance(req.get("toolKind"), str):
        labels["openclaw.tool_kind"] = req["toolKind"]
    return AgentEvent.model_validate(
        {
            "ts": datetime.now(UTC),
            "endpoint": {"device_id": "pending", "hostname": hostname},
            "principal": {"user_id": user_id},
            "agent": {
                "type": "openclaw",
                "session_id": str(req.get("sessionKey") or req.get("sessionId") or "unknown"),
                "run_id": req.get("runId") if isinstance(req.get("runId"), str) else None,
            },
            "source": {"sensor": "openclaw_plugin"},
            "payload": {
                "kind": "tool.call",
                "call_id": str(req.get("toolCallId") or f"plugin:{time.time_ns()}"),
                "tool": tool,
                "provider": provider,
                "arguments": arguments,
            },
            "labels": labels,
        }
    )


def plugin_response(verdict: Verdict) -> tuple[dict[str, Any], Enforcement | None]:
    """What the plugin should do, and the enforcement record that matches it."""
    action = verdict.action
    rules = verdict.rule_ids
    titles = [h.rule.title for h in verdict.hits]
    reason = "; ".join(dict.fromkeys(titles)) or "policy"
    sensor = SensorType.OPENCLAW_PLUGIN
    base = {"ok": True, "action": action.value, "rules": rules}
    if action in _BLOCKING:
        detail = "pre-exec: openclaw plugin blocked the tool call"
        return base | {"decision": "block", "reason": f"Agent Sentinel: {reason}"}, Enforcement(
            action=action, enforced=True, enforcer=sensor, detail=detail
        )
    if action is ResponseAction.REQUIRE_APPROVAL:
        detail = "pre-exec: user approval requested through OpenClaw"
        return base | {"decision": "approve", "title": "Agent Sentinel", "reason": reason}, Enforcement(
            action=action, enforced=True, enforcer=sensor, detail=detail
        )
    return base | {"decision": "allow"}, None


def judge(
    ctx: AdapterContext, req: dict[str, Any], *, labels: dict[str, str] | None = None
) -> dict[str, Any]:
    """Evaluate one plugin request with the sensor's engine and record it."""
    event = plugin_event(
        req, user_id=ctx.user_id, hostname=ctx.hostname, tool_plugins=ctx.plugins.tool_plugins
    )
    if labels:
        event = event.model_copy(update={"labels": event.labels | labels})
    result = ctx.evaluate(event)
    response, enforcement = plugin_response(result.verdict)
    ctx.record(result, enforcement)
    ctx.plugins.mark(event.payload.call_id)  # type: ignore[union-attr]
    return response


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
        if op == "resolution":  # user's answer to a requireApproval (audit in M7)
            log.info(
                "approval %s for %s: %s", req.get("decision"), req.get("toolName"), req.get("toolCallId")
            )
            return {"ok": True}
        return {"ok": False, "error": f"unknown op {op!r}"}
