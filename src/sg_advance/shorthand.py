"""Build AgentEvents from a terse "payload + a few envelope keys" dict.

Used by rule regression cases (tests/rule_cases) and anything else that hand-writes events:

    {at: 3, session: a, kind: tool.call, tool: Bash, arguments: {command: "cat .env"}}

Envelope keys (``at`` seconds from ``t0``, ``session``, ``user``, ``device``, ``agent``,
``sensor``, ``labels``, and for sub-agents ``parent`` / ``root``: the delegating and top session)
are pulled out; everything else is the payload. Missing envelope values come from
``defaults``, then from built-in test defaults.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from .schema import AgentEvent

T0 = datetime(2026, 11, 10, tzinfo=UTC)
ENVELOPE_KEYS = frozenset({"at", "session", "user", "device", "agent", "sensor", "labels", "parent", "root"})
DEFAULT_SENSOR = {
    "openclaw": "openclaw_gateway",
    "claude_code": "claude_code_hook",
    "langgraph": "langgraph_callback",
    "gemini_cli": "gemini_cli_hook",
    "codex_cli": "codex_cli_hook",
}
_BASE = {"session": "s1", "user": "tester", "device": "dev-test", "agent": "claude_code"}


def build_event(
    spec: dict[str, Any],
    *,
    defaults: dict[str, Any] | None = None,
    index: int = 0,
    t0: datetime = T0,
) -> AgentEvent:
    ctx = _BASE | (defaults or {}) | {k: spec[k] for k in ENVELOPE_KEYS - {"at"} if k in spec}
    payload = {k: v for k, v in spec.items() if k not in ENVELOPE_KEYS}
    if payload.get("kind") in ("tool.call", "tool.result"):
        payload.setdefault("call_id", f"call-{index}")
    agent = ctx["agent"]
    return AgentEvent.model_validate(
        {
            # Without ``at``, keep file order with sub-second spacing.
            "ts": t0 + timedelta(seconds=spec.get("at", index * 0.001)),
            "endpoint": {"device_id": ctx["device"]},
            "principal": {"user_id": ctx["user"]},
            "agent": {"type": agent, "session_id": ctx["session"], **_lineage(ctx)},
            "source": {"sensor": ctx.get("sensor") or DEFAULT_SENSOR.get(agent, "mcp_proxy")},
            "payload": payload,
            "labels": spec.get("labels", {}),
        }
    )


def _lineage(ctx: dict[str, Any]) -> dict[str, Any]:
    if not ctx.get("parent"):
        return {}
    return {"parent_session_id": ctx["parent"], "root_session_id": ctx.get("root") or ctx["parent"]}
