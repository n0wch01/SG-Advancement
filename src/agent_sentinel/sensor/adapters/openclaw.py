"""OpenClaw adapter: gateway frames → AgentEvent, verdict → ``sessions.abort``.

What the gateway sends (2026.4.15 build), after ``sessions.subscribe``:

- ``session.tool`` — every tool event of every session: ``{runId, sessionKey, seq, ts,
  data: {phase: start|update|result, name, toolCallId, args, meta, isError, result?}}``.
  ``result`` is stripped unless the session's verbose level is ``full``.
- ``session.message`` — transcript updates: ``{sessionKey, message: {role, content, ...}}`` with
  role ``user`` | ``assistant`` | ``toolResult`` (the latter carries the tool output text).
- ``agent`` — non-tool run streams to all clients, e.g. ``stream: lifecycle, data.phase: start|end``.

``tools.catalog`` lists core and plugin tools (with ``pluginId``); it becomes inventory.snapshot.

OpenClaw only lets us see a tool call once it has started, so enforcement is post-hoc: a verdict
of block or worse aborts the run. Shell commands that need OpenClaw's own exec approval could be
gated *before* they run via ``exec.approval.*`` — not used yet.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import UTC, datetime
from typing import Any

from ...schema import AgentEvent, Enforcement, ResponseAction, SensorType
from .base import AdapterContext
from .openclaw_gateway import DEFAULT_URL, DeviceIdentity, GatewayConnection, GatewayError

log = logging.getLogger(__name__)

PREVIEW_CHARS = 4000
_ABORTING = {ResponseAction.BLOCK, ResponseAction.ABORT_SESSION, ResponseAction.QUARANTINE}


def _ts(value: Any) -> datetime:
    if isinstance(value, int | float) and value > 0:
        return datetime.fromtimestamp(value / 1000, UTC)
    return datetime.now(UTC)


def _text(content: Any) -> str:
    """Message content is a string or a list of parts; keep the text parts only."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(
            str(p.get("text", "")) for p in content if isinstance(p, dict) and p.get("type") in (None, "text")
        )
    if isinstance(content, dict):
        return _text(content.get("content") or content.get("text"))
    return ""


def _result_text(result: Any) -> str:
    if result is None:
        return ""
    if isinstance(result, dict) and "content" in result:
        return _text(result["content"])
    if isinstance(result, str):
        return result
    try:
        return json.dumps(result, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(result)


class OpenClawMapper:
    """Stateful translation; one instance per gateway connection lifetime (state survives
    reconnects because the adapter keeps the same mapper)."""

    def __init__(self, user_id: str, hostname: str | None = None) -> None:
        self.user_id = user_id
        self.hostname = hostname
        self.plugin_of: dict[str, str] = {}  # tool name -> plugin id (from tools.catalog)
        self.core_tools: set[str] = set()
        self.unknown_tool_seen = False  # adapter re-reads the catalog when this flips
        self.seen_sessions: set[str] = set()
        self.results_emitted: set[str] = set()  # toolCallIds whose tool.result went out
        self.pending_results: dict[str, dict[str, Any]] = {}  # result frames without output text
        self._seq = 0

    def _event(
        self, session_key: str, payload: dict[str, Any], ts: Any = None, run_id: str | None = None
    ) -> AgentEvent:
        self._seq += 1
        return AgentEvent.model_validate(
            {
                "ts": _ts(ts),
                "endpoint": {"device_id": "pending", "hostname": self.hostname},  # sensor core stamps the id
                "principal": {"user_id": self.user_id},
                "agent": {"type": "openclaw", "session_id": session_key, "run_id": run_id},
                "source": {"sensor": "openclaw_gateway", "seq": self._seq},
                "payload": payload,
            }
        )

    def _provider(self, tool: str) -> dict[str, Any]:
        if tool in self.plugin_of:
            return {"kind": "plugin", "plugin_id": self.plugin_of[tool]}
        if tool in self.core_tools:
            return {"kind": "builtin"}
        # Not in the last catalog: most likely a plugin installed since. Ask for a fresh catalog.
        self.unknown_tool_seen = True
        return {"kind": "unknown"}

    def _session_start(self, key: str, ts: Any, run_id: str | None, reason: str) -> list[AgentEvent]:
        if key in self.seen_sessions:
            return []
        self.seen_sessions.add(key)
        return [self._event(key, {"kind": "session.start", "reason": reason}, ts, run_id)]

    # ── inventory ────────────────────────────────────────────────────────────

    def inventory(self, catalog: dict[str, Any]) -> AgentEvent:
        tools, plugins = [], {}
        for group in catalog.get("groups") or []:
            for t in group.get("tools") or []:
                name = t.get("id")
                if not isinstance(name, str):
                    continue
                pid = t.get("pluginId") or (
                    group.get("pluginId") if group.get("source") == "plugin" else None
                )
                if pid:
                    self.plugin_of[name] = pid
                    plugins[pid] = {"plugin_id": pid, "source": "openclaw"}
                else:
                    self.core_tools.add(name)
                provider = {"kind": "plugin", "plugin_id": pid} if pid else {"kind": "builtin"}
                tools.append({"name": name, "provider": provider, "description": t.get("description")})
        agent_id = catalog.get("agentId") or "main"
        return self._event(
            f"inventory:{agent_id}",
            {"kind": "inventory.snapshot", "tools": tools, "plugins": list(plugins.values())},
        )

    # ── frames ───────────────────────────────────────────────────────────────

    def map_frame(self, frame: dict[str, Any]) -> list[AgentEvent]:
        name = frame.get("event")
        p = frame.get("payload")
        if not isinstance(p, dict):
            return []
        if name == "session.tool":
            return self._tool(p)
        if name == "session.message":
            return self._message(p)
        if name == "agent" and p.get("stream") == "lifecycle":
            return self._lifecycle(p)
        return []

    def _lifecycle(self, p: dict[str, Any]) -> list[AgentEvent]:
        key, run_id = p.get("sessionKey"), p.get("runId")
        if not isinstance(key, str):
            return []
        phase = (p.get("data") or {}).get("phase")
        if phase == "start":
            return self._session_start(key, p.get("ts"), run_id, "run-start")
        if phase in ("end", "error"):
            return self._flush_pending(run_id)
        return []

    def _tool(self, p: dict[str, Any]) -> list[AgentEvent]:
        key, run_id, data = p.get("sessionKey"), p.get("runId"), p.get("data") or {}
        tool, call_id, phase = data.get("name"), data.get("toolCallId"), data.get("phase")
        if not (isinstance(key, str) and isinstance(tool, str) and isinstance(call_id, str)):
            return []
        out = self._session_start(key, p.get("ts"), run_id, "observed")
        if phase == "start":
            args = data.get("args")
            arguments = args if isinstance(args, dict) else ({} if args is None else {"input": args})
            out.append(
                self._event(
                    key,
                    {
                        "kind": "tool.call",
                        "call_id": call_id,
                        "tool": tool,
                        "provider": self._provider(tool),
                        "arguments": arguments,
                    },
                    p.get("ts"),
                    run_id,
                )
            )
        elif phase == "result" and call_id not in self.results_emitted:
            text = _result_text(data.get("result"))
            if text:
                out.append(
                    self._result(key, run_id, call_id, tool, bool(data.get("isError")), text, p.get("ts"))
                )
            else:  # verbose < full: wait for the transcript's toolResult message
                self.pending_results[call_id] = {
                    "key": key,
                    "run_id": run_id,
                    "tool": tool,
                    **data,
                    "ts": p.get("ts"),
                }
        return out

    def _result(
        self, key: str, run_id: Any, call_id: str, tool: str, is_error: bool, text: str, ts: Any
    ) -> AgentEvent:
        self.results_emitted.add(call_id)
        self.pending_results.pop(call_id, None)
        payload: dict[str, Any] = {
            "kind": "tool.result",
            "call_id": call_id,
            "tool": tool,
            "provider": self._provider(tool),
            "ok": not is_error,
        }
        if text:
            payload["output_preview"] = text[:PREVIEW_CHARS]
            payload["output_bytes"] = len(text.encode("utf-8"))
        return self._event(key, payload, ts, run_id if isinstance(run_id, str) else None)

    def _flush_pending(self, run_id: Any) -> list[AgentEvent]:
        done = {c: r for c, r in self.pending_results.items() if r.get("run_id") == run_id}
        return [
            self._result(r["key"], r["run_id"], c, r["tool"], bool(r.get("isError")), "", r.get("ts"))
            for c, r in done.items()
        ]

    def _message(self, p: dict[str, Any]) -> list[AgentEvent]:
        key, msg = p.get("sessionKey"), p.get("message")
        if not (isinstance(key, str) and isinstance(msg, dict)):
            return []
        role, ts = msg.get("role"), msg.get("timestamp")
        out = self._session_start(key, ts, None, "observed")
        if role == "user":
            text = _text(msg.get("content"))
            if text:
                out.append(self._event(key, {"kind": "prompt.user", "text": text}, ts))
        elif role == "assistant":
            text = _text(msg.get("content"))
            if text:
                out.append(self._event(key, {"kind": "message.assistant", "text": text}, ts))
        elif role in ("toolResult", "tool"):
            call_id = msg.get("toolCallId")
            if isinstance(call_id, str) and call_id not in self.results_emitted:
                pend = self.pending_results.get(call_id, {})
                tool = msg.get("toolName") or pend.get("tool") or "unknown"
                is_error = bool(msg.get("isError", pend.get("isError", False)))
                out.append(
                    self._result(
                        key, pend.get("run_id"), call_id, tool, is_error, _text(msg.get("content")), ts
                    )
                )
        return out


class OpenClawAdapter:
    """Watches one OpenClaw gateway. Reconnects with backoff; re-snapshots inventory on connect
    and every ``inventory_interval`` seconds (catches plugins installed while running)."""

    name = "openclaw"

    def __init__(
        self,
        url: str = DEFAULT_URL,
        token: str | None = None,
        *,
        enforce: bool = True,
        identity_path: str | None = None,
        inventory_interval: float = 300.0,
        max_backoff: float = 60.0,
    ) -> None:
        self.url = url
        self.token = token if token is not None else os.environ.get("OPENCLAW_GATEWAY_TOKEN", "")
        self.enforce = enforce
        self.identity_path = identity_path
        self.inventory_interval = inventory_interval
        self.max_backoff = max_backoff
        self.scopes = ["operator.read", "operator.write"] if enforce else ["operator.read"]
        self.aborted_runs: set[tuple[str, str | None]] = set()
        self.connected = asyncio.Event()

    async def run(self, ctx: AdapterContext) -> None:
        mapper = OpenClawMapper(ctx.user_id, ctx.hostname)
        first_delay = min(1.0, self.max_backoff)
        delay = first_delay
        while True:
            try:
                await self._session(ctx, mapper)
            except asyncio.CancelledError:
                raise
            except (OSError, GatewayError, ConnectionError, TimeoutError) as e:
                log.warning("openclaw gateway %s: %s", self.url, e)
            except Exception:  # a bug or an unexpected frame shape: log loudly, keep watching
                log.exception("openclaw adapter error")
            if self.connected.is_set():  # we had a working session: start backing off afresh
                delay = first_delay
            self.connected.clear()
            log.info("reconnecting to %s in %.1fs", self.url, delay)
            await asyncio.sleep(delay)
            delay = min(delay * 2, self.max_backoff)

    async def _session(self, ctx: AdapterContext, mapper: OpenClawMapper) -> None:
        path = DeviceIdentity.find(self.identity_path)
        identity = DeviceIdentity.load(path) if path else None
        conn = await GatewayConnection.open(self.url, self.token, scopes=self.scopes, identity=identity)

        async def on_event(frame: dict[str, Any]) -> None:
            for ev in mapper.map_frame(frame):
                await self._handle(ctx, conn, ev)
            if mapper.unknown_tool_seen:
                mapper.unknown_tool_seen = False
                await self._snapshot(ctx, conn, mapper)

        conn.on_event(on_event)
        try:
            # Catalog first, then subscribe: tool events must never be mapped without knowing
            # which tools belong to plugins (plugin rules would silently miss them).
            await self._snapshot(ctx, conn, mapper)
            res = await conn.request("sessions.subscribe", {})
            if not res.get("ok"):
                raise GatewayError(f"sessions.subscribe failed: {res.get('error')}")
            log.info("openclaw gateway %s connected", self.url)
            self.connected.set()
            while True:
                try:
                    await asyncio.wait_for(conn.closed.wait(), self.inventory_interval)
                    raise ConnectionError("gateway closed the connection")
                except TimeoutError:
                    await self._snapshot(ctx, conn, mapper)
        finally:
            await conn.close()

    async def _snapshot(self, ctx: AdapterContext, conn: GatewayConnection, mapper: OpenClawMapper) -> None:
        res = await conn.request("tools.catalog", {})
        if res.get("ok") and isinstance(res.get("payload"), dict):
            await self._handle(ctx, conn, mapper.inventory(res["payload"]))
        else:
            log.warning("tools.catalog failed: %s", res.get("error"))

    async def _handle(self, ctx: AdapterContext, conn: GatewayConnection, event: AgentEvent) -> None:
        result = ctx.evaluate(event)
        ctx.record(result, await self._enforce(conn, event, result.verdict.action))

    async def _enforce(
        self, conn: GatewayConnection, event: AgentEvent, action: ResponseAction
    ) -> Enforcement | None:
        if action in (ResponseAction.ALLOW, ResponseAction.ALERT):
            return None
        sensor = SensorType.OPENCLAW_GATEWAY
        if action not in _ABORTING:
            return Enforcement(
                action=action, enforced=False, enforcer=sensor, detail="not supported on OpenClaw; alert only"
            )
        if not self.enforce:
            return Enforcement(action=action, enforced=False, enforcer=sensor, detail="observe-only mode")
        key, run_id = event.agent.session_id, event.agent.run_id
        if key.startswith("inventory:"):
            return Enforcement(
                action=action, enforced=False, enforcer=sensor, detail="no run to abort; quarantine is M11"
            )
        if (key, run_id) in self.aborted_runs:
            return Enforcement(action=action, enforced=True, enforcer=sensor, detail="run already aborted")
        try:
            res = await conn.request("sessions.abort", {"key": key, **({"runId": run_id} if run_id else {})})
        except (ConnectionError, TimeoutError) as e:
            return Enforcement(
                action=action, enforced=False, enforcer=sensor, detail=f"sessions.abort failed: {e}"
            )
        if not res.get("ok"):
            return Enforcement(
                action=action,
                enforced=False,
                enforcer=sensor,
                detail=f"sessions.abort refused: {res.get('error')}",
            )
        self.aborted_runs.add((key, run_id))
        return Enforcement(action=action, enforced=True, enforcer=sensor, detail="post-hoc: sessions.abort")
