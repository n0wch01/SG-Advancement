"""The OpenClaw gateway plugin protocol (optional integration; transport: ``local_api``).

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
    (the security team's pre-approval hold was removed 2026-11-17: four decisions only, allow / approve
    by the person / deny / mask).

Agent-neutral judging, response mapping and the approval audit are in ``decision`` (2026-11-18); this
module only translates the plugin's requests and keeps the plugin's own state (``openclaw(ctx)``).

The daemon judges with its stateful engine (sequence/rate rules see every adapter's events) and
records the event with the enforcement the plugin is about to apply. When the daemon is down the
plugin runs ``sga-sensor evaluate`` instead: same request on stdin, stateless judgement from
the signed policy cache, recorded with ``labels.sga_verdict = "degraded"``.

Windows (M12) has no unix socket server in asyncio: the daemon listens on 127.0.0.1 (a random port)
and writes ``SGA_HOME/sga-api.json`` ``{"host", "port", "token"}`` in the user's profile. Every request
must carry ``"auth": token``; anything else on the PC that can reach loopback but not that file is refused.
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..detect import Verdict
from ..schema import AgentEvent, Enforcement, ResponseAction, SensorType
from .adapters.base import AdapterContext
from .adapters.openclaw_people import OpenClawPeople
from .adapters.openclaw_state import openclaw
from .decision import EnforcementPoint, approval_channel, pending_for, point_response
from .envelope import envelope
from .local_api import LocalApiServer

log = logging.getLogger(__name__)

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
    agent = {
        "type": "openclaw",
        "session_id": session_key or str(req.get("sessionId") or "unknown"),
        "run_id": run_id,
        **people.lineage(session_key),
    }
    return AgentEvent.model_validate(
        envelope(sensor="openclaw_plugin", agent=agent, payload=payload, hostname=hostname,
                 principal=who.principal, labels=who.labels | _plugin_labels(req))  # fmt: skip
    )


OPENCLAW_PLUGIN = EnforcementPoint(SensorType.OPENCLAW_PLUGIN, "openclaw plugin", "OpenClaw")


def plugin_response(
    verdict: Verdict, point: EnforcementPoint = OPENCLAW_PLUGIN, action: ResponseAction | None = None
) -> tuple[dict[str, Any], Enforcement | None]:
    """The plugin's answer (``decision.point_response`` at the OpenClaw plugin by default)."""
    return point_response(verdict, point, action)



def judge(
    ctx: AdapterContext, req: dict[str, Any], *, labels: dict[str, str] | None = None
) -> dict[str, Any]:
    """Evaluate one plugin request with the sensor's engine and record it."""
    event = plugin_event(
        req,
        user_id=ctx.user_id,
        hostname=ctx.hostname,
        tool_plugins=openclaw(ctx).plugins.tool_plugins,
        people=openclaw(ctx).people,
    )
    if labels:
        event = event.model_copy(update={"labels": event.labels | labels})
    result = ctx.evaluate(event)
    action = approval_channel(result.verdict, OPENCLAW_PLUGIN)
    response, enforcement = point_response(result.verdict, OPENCLAW_PLUGIN, action)
    pending = pending_for(result, action, response)
    ctx.record(result, enforcement)
    call_id = event.payload.call_id  # type: ignore[union-attr]
    openclaw(ctx).plugins.mark(call_id)
    if response.get("decision") == "approve":  # keep what asked, to link the person's answer
        ctx.approvals.remember(call_id, pending)
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
        people=openclaw(ctx).people,
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
    pending = ctx.approvals.take(str(req.get("toolCallId") or ""))
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
    event = ctx.local_event(
        agent="openclaw", session_id="sensor:openclaw_plugin", sensor="openclaw_plugin", payload=payload
    )
    ctx.record(ctx.evaluate(event))



# ── plugin ops on the local API ─────────────────────────────────────────────
# Only these touch the plugin's liveness. Before 2026-11-18 every local API request did, so a Claude Code
# hook alone made the sensor expect an OpenClaw plugin and report it "lost" 150 s after the last hook call.


def _contact(ctx: AdapterContext, *, hello: bool = False) -> None:
    plugins = openclaw(ctx).plugins
    if (plugins.heartbeat() if hello else plugins.touch()) == "recovered":
        log.warning("openclaw plugin is back")
        record_health(ctx, "recovered", "plugin contacted the sensor again")


def hello_op(ctx: AdapterContext, req: dict[str, Any]) -> dict[str, Any]:
    _contact(ctx, hello=True)
    log.info("openclaw plugin connected: %s %s", req.get("plugin"), req.get("version"))
    return {"ok": True}


def bye_op(ctx: AdapterContext, req: dict[str, Any]) -> dict[str, Any]:
    """Disposed by the gateway (plugin disabled, removed, replaced, or shutdown)."""
    log.warning("openclaw plugin unloaded: %s (%s)", req.get("plugin"), req.get("reason"))
    openclaw(ctx).plugins.goodbye()
    return {"ok": True}


def tool_call_op(ctx: AdapterContext, req: dict[str, Any]) -> dict[str, Any]:
    _contact(ctx)
    try:
        return judge(ctx, req)
    except Exception as e:  # the plugin falls back on its own; tell it why
        log.exception("plugin request failed")
        return {"ok": False, "error": str(e)}


def resolution_op(ctx: AdapterContext, req: dict[str, Any]) -> dict[str, Any]:
    """A person's answer to a requireApproval prompt (audit trail)."""
    _contact(ctx)
    try:
        record_resolution(ctx, req)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    return {"ok": True}


OPENCLAW_OPS = {"hello": hello_op, "bye": bye_op, "tool_call": tool_call_op, "resolution": resolution_op}


def openclaw_local_api(ctx: AdapterContext, path: Path, *, tcp: bool = False) -> LocalApiServer:
    """The daemon's local API with the OpenClaw plugin protocol enabled (the hook ops are always there)."""
    return LocalApiServer(ctx, path, tcp=tcp, ops=OPENCLAW_OPS)


# ── plugin liveness (the daemon's health tick) ──────────────────────────────


def excuse_host_sleep(ctx: AdapterContext, seconds: float) -> None:
    openclaw(ctx).plugins.excuse(seconds)


def check_plugin_health(ctx: AdapterContext, now: float) -> str | None:
    """Emit a sensor.health event when the gateway plugin's heartbeats stop."""
    plugins = openclaw(ctx).plugins
    said_bye = plugins.bye_at is not None
    if plugins.check(now) != "lost":
        return None
    last = plugins.last_contact
    quiet = now - last - plugins.excused if last is not None else None
    if said_bye:
        detail = f"plugin was unloaded by the gateway and did not return within {plugins.bye_grace:.0f}s"
    elif quiet is not None and plugins.excused:
        detail = (
            f"no heartbeat for {quiet:.0f}s while the host was awake "
            f"({plugins.excused:.0f}s asleep not counted)"
        )
    elif quiet is not None:
        detail = f"no heartbeat for {quiet:.0f}s"
    else:
        detail = "no heartbeat since the sensor started"
    log.warning("openclaw plugin heartbeat lost (%s)", detail)
    record_health(ctx, "lost", detail, last)
    return "lost"
