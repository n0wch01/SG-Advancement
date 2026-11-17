"""Agent identity (2026-11-16): which configured agent acts, beyond the person and the device.

Identity-only access control is not enough (that is what the four decisions are for), but without it the
same person's Claude Code and its "fixer" subagent, or OpenClaw's "main" and "research" agents, are one
actor in the records. The sensor names the agent from what it observes itself, never from the agent:
- Claude Code: the hook's ``agent_type`` for a subagent (its definition name), otherwise ``main``.
- OpenClaw: the agent id in the session key (``agent:<id>:...``) or inventory subject (``inventory:<id>``).
Standard library only (the hook path imports the sensor core lazily, but keep it light anyway).
"""

from __future__ import annotations

import re

from ..schema import AgentEvent

_OPENCLAW = re.compile(r"^(?:agent|inventory):([^:/]+)")


def agent_id_of(event: AgentEvent) -> str | None:
    kind = event.agent.type.value
    if kind == "claude_code":
        return event.labels.get("claude_code.agent_type") or "main"
    if kind == "openclaw":
        m = _OPENCLAW.match(event.agent.session_id)
        return m.group(1) if m else None
    return None


def identity(event: AgentEvent) -> str:
    """Person, device and agent as one string for the console and the records."""
    aid = event.agent.agent_id or "?"
    return f"{event.principal.user_id}@{event.endpoint.device_id}/{event.agent.type.value}:{aid}"
