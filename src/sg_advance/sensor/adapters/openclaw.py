"""OpenClaw adapter: gateway frames → AgentEvent, verdict → ``sessions.abort``.

What the gateway sends (2026.4.15 build), after ``sessions.subscribe``:

- ``session.tool`` — every tool event of every session: ``{runId, sessionKey, seq, ts,
  data: {phase: start|update|result, name, toolCallId, args, meta, isError, result?}}``.
  ``result`` is stripped unless the session's verbose level is ``full``.
- ``session.message`` — transcript updates: ``{sessionKey, message: {role, content, ...}}``. In a live
  capture only ``user`` and ``assistant`` arrived; ``toolResult`` messages are *not* pushed.
- ``agent`` — non-tool run streams to all clients: ``lifecycle`` (start|end|error) and, for shell
  commands, ``command_output`` (``data: {toolCallId, phase: delta|end, output}``).

Tool output therefore comes from, in order: the ``session.tool`` result itself (verbose ``full``),
``command_output`` end (shell commands), or ``chat.history`` — fetched right before the next tool
call / reply / run end of that session. By then the model has already seen the result, so it is in
the transcript, and the ``tool.result`` is still processed before the call that may act on it
(sequence rules depend on that order).

``tools.catalog`` lists core and plugin tools (with ``pluginId``); it becomes inventory.snapshot.

OpenClaw only lets us see a tool call once it has started, so enforcement is post-hoc: a verdict
of block or worse aborts the run.

Exception — shell commands. When OpenClaw's exec policy asks for approval, the gateway emits
``exec.approval.requested`` ``{id, request: {command, commandArgv, cwd, sessionKey, ...}}`` *before*
running anything, and any client with ``operator.approvals`` may answer ``exec.approval.resolve``
``{id, decision: allow-once|allow-always|deny}``. With ``gate_exec`` the adapter evaluates the
pending command and answers ``deny`` for block-or-worse; everything else is left to the human,
which is exactly "the user approves" for ``require_approval``.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
from collections import deque
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ...redact import redact_value
from ...schema import AgentEvent, Enforcement, ResponseAction, SensorType
from .base import AdapterContext
from .openclaw_gateway import DEFAULT_URL, DeviceIdentity, GatewayConnection, GatewayError, PairingRequired
from .openclaw_people import OpenClawPeople

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


def _skills(status: dict[str, Any] | None) -> list[dict[str, Any]]:
    """``skills.status`` rows → SkillDescriptor dicts (description kept for poisoning rules)."""
    out = []
    for sk in (status or {}).get("skills") or []:
        if not isinstance(sk, dict):
            continue
        name = sk.get("skillKey") or sk.get("name")
        if not isinstance(name, str) or not name:
            continue
        source = sk.get("source") if isinstance(sk.get("source"), str) else None
        desc = sk.get("description") if isinstance(sk.get("description"), str) else None
        out.append(
            {
                "name": name,
                "source": source,
                "ref": f"{source or 'unknown'}:{name}",
                "enabled": not sk.get("disabled"),
                "eligible": sk.get("eligible") if isinstance(sk.get("eligible"), bool) else None,
                "model_visible": sk.get("modelVisible") if isinstance(sk.get("modelVisible"), bool) else None,
                "description": desc,
                "description_sha256": hashlib.sha256(desc.encode()).hexdigest() if desc else None,
            }
        )
    return out


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

    def __init__(
        self, user_id: str, hostname: str | None = None, people: OpenClawPeople | None = None
    ) -> None:
        self.user_id = user_id
        self.hostname = hostname
        self.people = people if people is not None else OpenClawPeople()
        self.plugin_of: dict[str, str] = {}  # tool name -> plugin id (from tools.catalog)
        self.core_tools: set[str] = set()
        self.unknown_tool_seen = False  # adapter re-reads the catalog when this flips
        self.seen_sessions: set[str] = set()
        self.results_emitted: set[str] = set()  # toolCallIds whose tool.result went out
        self.pending_results: dict[str, dict[str, Any]] = {}  # result frames without output text
        self.command_outputs: dict[str, str] = {}  # shell output that arrived before its result frame
        self._seq = 0
        self.seen_messages: set[str] = set()
        self._message_order: deque[str] = deque()

    def _event(
        self,
        session_key: str,
        payload: dict[str, Any],
        ts: Any = None,
        run_id: str | None = None,
        labels: dict[str, str] | None = None,
    ) -> AgentEvent:
        self._seq += 1
        who = self.people.attribute(session_key, run_id, self.user_id)
        return AgentEvent.model_validate(
            {
                "labels": who.labels | (labels or {}),
                "ts": _ts(ts),
                "endpoint": {"device_id": "pending", "hostname": self.hostname},  # sensor core stamps the id
                "principal": who.principal,
                "agent": {
                    "type": "openclaw",
                    "session_id": session_key,
                    "run_id": run_id,
                    **self.people.lineage(session_key),  # sub-agent: who delegated to it
                },
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
        if self.people.lineage(key):
            reason = "spawned"
        return [self._event(key, {"kind": "session.start", "reason": reason}, ts, run_id)]

    # ── inventory ────────────────────────────────────────────────────────────

    def inventory(
        self,
        catalog: dict[str, Any],
        agent: dict[str, Any] | None = None,
        skills: dict[str, Any] | None = None,
    ) -> AgentEvent:
        """One agent's inventory: ``tools.catalog`` (+ ``agents.list`` row, ``skills.status``)."""
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
        agent = agent or {}
        agent_id = agent.get("id") or catalog.get("agentId") or "main"
        payload: dict[str, Any] = {
            "kind": "inventory.snapshot",
            "agent_id": agent_id,
            "tools": tools,
            "plugins": list(plugins.values()),
            "skills": _skills(skills),
        }
        model = agent.get("model")
        if isinstance(model, dict) and isinstance(model.get("primary"), str):
            payload["model"] = model["primary"]
        runtime = agent.get("agentRuntime")
        if isinstance(runtime, dict) and isinstance(runtime.get("id"), str):
            payload["runtime"] = runtime["id"]
        if isinstance(agent.get("defaultPermissionMode"), str):
            payload["permission_mode"] = agent["defaultPermissionMode"]
        return self._event(f"inventory:{agent_id}", payload)

    # ── exec approvals ───────────────────────────────────────────────────────

    def approval_request(self, p: dict[str, Any]) -> list[AgentEvent]:
        """A pending shell command, as the tool.call it would become if approved. The last event
        is that call; a session.start may precede it."""
        approval_id, req = p.get("id"), p.get("request")
        if not (isinstance(approval_id, str) and isinstance(req, dict)):
            return []
        command = req.get("command") or " ".join(str(a) for a in req.get("commandArgv") or [])
        if not command:
            return []
        key = req.get("sessionKey") or f"approval:{req.get('agentId') or 'main'}"
        out = self._session_start(key, p.get("createdAtMs"), None, "observed")
        arguments = {"command": command, **({"cwd": req["cwd"]} if req.get("cwd") else {})}
        ev = self._event(
            key,
            {
                "kind": "tool.call",
                "call_id": f"approval:{approval_id}",
                "tool": "exec",
                "provider": {"kind": "builtin"},
                "arguments": arguments,
            },
            p.get("createdAtMs"),
        )
        labels = {"openclaw.phase": "exec-approval", "openclaw.approval_id": approval_id}
        return [*out, ev.model_copy(update={"labels": labels})]

    # ── frames ───────────────────────────────────────────────────────────────

    def map_frame(self, frame: dict[str, Any]) -> list[AgentEvent]:
        name = frame.get("event")
        p = frame.get("payload")
        if not isinstance(p, dict):
            return []
        self.people.observe(frame)  # before mapping: a user message names the run's sender
        if name == "session.tool":
            return self._tool(p)
        if name == "session.message":
            return self._message(p)
        if name == "agent" and p.get("stream") == "lifecycle":
            return self._lifecycle(p)
        if name == "agent" and p.get("stream") == "command_output":
            return self._command_output(p)
        return []

    def _command_output(self, p: dict[str, Any]) -> list[AgentEvent]:
        data = p.get("data") or {}
        call_id, output = data.get("toolCallId"), data.get("output")
        if data.get("phase") != "end" or not isinstance(call_id, str) or not isinstance(output, str):
            return []
        if call_id in self.results_emitted:
            return []
        pend = self.pending_results.get(call_id)
        if pend is None:  # result frame not here yet; use the output when it arrives
            self.command_outputs[call_id] = output
            return []
        return [
            self._result(
                pend["key"],
                pend["run_id"],
                call_id,
                pend["tool"],
                bool(pend.get("isError")),
                output,
                pend.get("ts"),
            )
        ]

    # ── transcript fallback (chat.history) ───────────────────────────────────

    def history_needed(self, frame: dict[str, Any]) -> str | None:
        """Session key whose pending results should be fetched before handling ``frame``."""
        p = frame.get("payload")
        if not isinstance(p, dict) or not self.pending_results:
            return None
        name, key = frame.get("event"), p.get("sessionKey")
        trigger = (
            (name == "session.tool" and (p.get("data") or {}).get("phase") == "start")
            or (name == "session.message" and (p.get("message") or {}).get("role") == "assistant")
            or (
                name == "agent"
                and p.get("stream") == "lifecycle"
                and (p.get("data") or {}).get("phase") in ("end", "error")
            )
        )
        if trigger and any(r["key"] == key for r in self.pending_results.values()):
            return key
        return None

    def results_from_history(self, key: str, messages: list[dict[str, Any]]) -> list[AgentEvent]:
        out = []
        for m in messages:
            call_id = m.get("toolCallId")
            if m.get("role") in ("toolResult", "tool") and call_id in self.pending_results:
                pend = self.pending_results[call_id]
                if pend["key"] != key:
                    continue
                is_error = bool(m.get("isError", pend.get("isError", False)))
                out.append(
                    self._result(
                        key,
                        pend["run_id"],
                        call_id,
                        pend["tool"],
                        is_error,
                        _text(m.get("content")),
                        pend.get("ts"),
                    )
                )
        return out

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
            # v4 Code Mode: the model calls an outer `exec` whose args are JavaScript, which in turn
            # runs inner tool calls (same name, `parentToolCallId` set). The inner call carries the
            # command that really runs — JS can assemble it dynamically — so rules rely on it; the
            # labels keep the link for investigation.
            labels: dict[str, str] = {}
            if isinstance(data.get("parentToolCallId"), str):
                labels["openclaw.parent_call_id"] = data["parentToolCallId"]
            if isinstance(arguments.get("code"), str):
                labels["openclaw.tool_kind"] = "code_mode"
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
                    labels,
                )
            )
        elif phase == "result" and call_id not in self.results_emitted:
            text = _result_text(data.get("result"))
            if text:
                out.append(
                    self._result(key, run_id, call_id, tool, bool(data.get("isError")), text, p.get("ts"))
                )
            elif call_id in self.command_outputs:  # shell output arrived first
                out.append(
                    self._result(
                        key,
                        run_id,
                        call_id,
                        tool,
                        bool(data.get("isError")),
                        self.command_outputs.pop(call_id),
                        p.get("ts"),
                    )
                )
            else:  # verbose < full: get it from command_output or chat.history (see module doc)
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
        # v4 can deliver the same transcript message twice (seen live); its id is stable.
        msg_id = p.get("messageId") or (msg.get("__openclaw") or {}).get("id")
        if isinstance(msg_id, str):
            if msg_id in self.seen_messages:
                return []
            self.seen_messages.add(msg_id)
            self._message_order.append(msg_id)
            if len(self._message_order) > 10_000:  # bounded memory on long-running gateways
                self.seen_messages.discard(self._message_order.popleft())
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
        gate_exec: bool = False,
        capture: Path | None = None,
        identity_path: Path | None = None,
        inventory_interval: float = 300.0,
        max_backoff: float = 60.0,
        plugin_grace: float = 3.0,
        password: str | None = None,
    ) -> None:
        self.url = url
        self.token = token if token is not None else os.environ.get("OPENCLAW_GATEWAY_TOKEN", "")
        self.password = password if password is not None else os.environ.get("OPENCLAW_GATEWAY_PASSWORD", "")
        self.enforce = enforce
        # Default: SGA_HOME/openclaw-device.json, resolved in run() from the sensor's home.
        self.identity_path = identity_path
        self._pairing_hint_shown: str | None = None
        self.inventory_interval = inventory_interval
        self.max_backoff = max_backoff
        self.plugin_grace = plugin_grace  # seconds to wait for the plugin's judgement of a call
        self.gate_exec = gate_exec and enforce
        self.capture = capture
        self.scopes = ["operator.read", "operator.write"] if enforce else ["operator.read"]
        if self.gate_exec:
            # May require approving a scope upgrade once: `openclaw devices list` / `approve`.
            self.scopes.append("operator.approvals")
        self.aborted_runs: set[tuple[str, str | None]] = set()
        self.connected = asyncio.Event()

    async def run(self, ctx: AdapterContext) -> None:
        mapper = OpenClawMapper(ctx.user_id, ctx.hostname, ctx.people)
        first_delay = min(1.0, self.max_backoff)
        delay = first_delay
        while True:
            try:
                await self._session(ctx, mapper)
            except asyncio.CancelledError:
                raise
            except PairingRequired as e:
                if e.request_id != self._pairing_hint_shown:  # say it once per request, not every retry
                    log.warning("openclaw gateway %s: %s", self.url, e)
                    self._pairing_hint_shown = e.request_id
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
        path = self.identity_path or ctx.sensor.home.root / "openclaw-device.json"
        identity = DeviceIdentity.load_or_create(path)
        conn = await GatewayConnection.open(
            self.url, self.token, scopes=self.scopes, identity=identity, password=self.password or None
        )
        if conn.issued_device_token and conn.issued_device_token[0] != identity.device_token:
            identity.with_token(*conn.issued_device_token).save(path)  # later connects use it
            log.info("stored OpenClaw device token for %s…", identity.device_id[:12])

        async def on_event(frame: dict[str, Any]) -> None:
            if self.capture is not None:
                self._capture(frame)
            if frame.get("event") == "exec.approval.requested" and isinstance(frame.get("payload"), dict):
                await self._gate(ctx, conn, mapper, frame["payload"])
                return
            if (key := mapper.history_needed(frame)) is not None:
                await self._fetch_results(ctx, conn, mapper, key)
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

    async def _fetch_results(
        self, ctx: AdapterContext, conn: GatewayConnection, mapper: OpenClawMapper, key: str
    ) -> None:
        try:
            res = await conn.request("chat.history", {"sessionKey": key, "limit": 50})
        except (ConnectionError, TimeoutError) as e:
            log.warning("chat.history failed for %s: %s", key, e)
            return
        messages = (res.get("payload") or {}).get("messages") if res.get("ok") else None
        if not isinstance(messages, list):
            log.warning("chat.history refused for %s: %s", key, res.get("error"))
            return
        for ev in mapper.results_from_history(key, messages):
            await self._handle(ctx, conn, ev)

    def _capture(self, frame: dict[str, Any]) -> None:
        """Debug aid: append raw gateway frames (secrets masked) to a JSONL file."""
        assert self.capture is not None
        with self.capture.open("a", encoding="utf-8") as f:
            f.write(json.dumps(redact_value(frame), ensure_ascii=False) + "\n")

    async def _gate(
        self, ctx: AdapterContext, conn: GatewayConnection, mapper: OpenClawMapper, p: dict[str, Any]
    ) -> None:
        events = mapper.approval_request(p)
        if not events:
            return
        for ev in events[:-1]:
            await self._handle(ctx, conn, ev)
        result = ctx.evaluate(events[-1])
        action = result.verdict.action
        sensor = SensorType.OPENCLAW_GATEWAY
        enforcement: Enforcement | None = None
        if action in _ABORTING and self.gate_exec:
            try:
                res = await conn.request("exec.approval.resolve", {"id": p["id"], "decision": "deny"})
                ok, err = bool(res.get("ok")), res.get("error")
            except (ConnectionError, TimeoutError) as e:
                ok, err = False, str(e)
            detail = "pre-exec: exec.approval denied" if ok else f"exec.approval.resolve failed: {err}"
            enforcement = Enforcement(action=action, enforced=ok, enforcer=sensor, detail=detail)
        elif action is ResponseAction.REQUIRE_APPROVAL:
            enforcement = Enforcement(
                action=action,
                enforced=True,
                enforcer=sensor,
                detail="left to the user: OpenClaw exec approval",
            )
        elif action in _ABORTING:
            enforcement = Enforcement(
                action=action, enforced=False, enforcer=sensor, detail="exec gating off"
            )
        ctx.record(result, enforcement)

    async def _snapshot(self, ctx: AdapterContext, conn: GatewayConnection, mapper: OpenClawMapper) -> None:
        """Per-agent inventory (M5b): every agent on the gateway has its own tools, skills, model.
        Gateways without ``agents.list`` get the single default catalog, as before."""
        await self._people(conn, mapper)
        res = await conn.request("agents.list", {})
        rows = (res.get("payload") or {}).get("agents") if res.get("ok") else None
        agents = [a for a in rows if isinstance(a, dict) and isinstance(a.get("id"), str)] if rows else []
        for agent in agents or [None]:
            params = {"agentId": agent["id"]} if agent else {}
            res = await conn.request("tools.catalog", params)
            if not (res.get("ok") and isinstance(res.get("payload"), dict)):
                log.warning("tools.catalog failed for %s: %s", params or "default agent", res.get("error"))
                continue
            skills = await conn.request("skills.status", params) if agent else {}
            status = skills.get("payload") if skills.get("ok") else None
            await self._handle(ctx, conn, mapper.inventory(res["payload"], agent, status))

    async def _people(self, conn: GatewayConnection, mapper: OpenClawMapper) -> None:
        """Profiles (id → email) and existing session owners, for attribution on team gateways.
        Solo or older gateways may not have these methods; attribution then falls back to --user."""
        for method, learn in (
            ("users.list", mapper.people.learn_profiles),
            ("sessions.list", mapper.people.learn_sessions),
        ):
            res = await conn.request(method, {})
            if res.get("ok"):
                learn(res.get("payload"))
            else:
                log.debug("%s unavailable: %s", method, res.get("error"))
        mapper.people.save()

    async def _handle(self, ctx: AdapterContext, conn: GatewayConnection, event: AgentEvent) -> None:
        if event.kind.value == "inventory.snapshot":
            ctx.plugins.tool_plugins.update(  # lets plugin-judged calls carry the right provider
                {t.name: t.provider.plugin_id for t in event.payload.tools if t.provider.plugin_id}  # type: ignore[union-attr]
            )
        if event.kind.value == "tool.call":
            call_id = event.payload.call_id  # type: ignore[union-attr]
            if ctx.plugins.active and not call_id.startswith("approval:") and not ctx.plugins.seen(call_id):
                # Live gateways can broadcast the tool start before (or while) the plugin's
                # before_tool_call reaches us, so give the plugin a moment. The daemon runs one
                # event loop: while we wait here, the plugin's request is still served.
                deadline = asyncio.get_running_loop().time() + self.plugin_grace
                while not ctx.plugins.seen(call_id) and asyncio.get_running_loop().time() < deadline:
                    await asyncio.sleep(0.05)
            if ctx.plugins.seen(call_id):
                return  # the gateway plugin judged and recorded this call before it ran
            if ctx.plugins.active and not call_id.startswith("approval:"):
                # The plugin is running but never saw this call: it was disabled, failed, or the
                # call took a path it doesn't cover. Rules decide how loud this is.
                event = event.model_copy(update={"labels": event.labels | {"sga_plugin": "missing"}})
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
