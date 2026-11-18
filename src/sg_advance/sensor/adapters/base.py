"""Adapter contract.

An adapter observes one agent (or one interception point), turns what it sees into AgentEvents
and hands each one to the daemon through ``AdapterContext``:

    result = ctx.evaluate(event)        # stamp + local rules → verdict (nothing queued yet)
    enforcement = ...                   # adapter acts on result.verdict.action, if it can
    ctx.record(result, enforcement)     # queue redacted event + findings with the outcome

Observation-only adapters pass ``None`` as enforcement. Blocking adapters (OpenClaw plugin M5c,
Claude Code / Codex hooks, MCP gateway) act before the tool runs
(sensor/decision.py); the OpenClaw WebSocket adapter can only
abort after a tool started (or deny a pending shell approval).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

from ...schema import AgentEvent, Enforcement
from ..approvals import PendingApprovals
from ..envelope import envelope

if TYPE_CHECKING:
    from ..core import ProcessResult, Sensor


# Remote response (M11): action name → async handler(target) → (ok, detail). The core registers
# block/unblock; adapters register what only they can do (abort a run, disable a plugin).
ActionHandler = Callable[[str], Awaitable[tuple[bool, str]]]


@dataclass
class AdapterContext:
    sensor: Sensor
    user_id: str  # the employee this endpoint's agents act for
    hostname: str | None = None
    approvals: PendingApprovals = field(default_factory=PendingApprovals)  # prompts awaiting a person
    actions: dict[str, ActionHandler] = field(default_factory=dict)  # remote response handlers (M11)
    # Agent-specific daemon state, by integration name (OpenClaw: adapters/openclaw_state.py). The generic
    # context names no product: a new agent adds its own entry instead of a field here (2026-11-18).
    extensions: dict[str, Any] = field(default_factory=dict)

    def local_event(
        self,
        *,
        agent: str,
        session_id: str,
        sensor: str,
        payload: dict[str, Any],
        labels: dict[str, str] | None = None,
    ) -> AgentEvent:
        """An event this endpoint observed itself (config, install, health, egress...): the endpoint's
        person, now."""
        return AgentEvent.model_validate(
            envelope(
                sensor=sensor,
                agent={"type": agent, "session_id": session_id},
                payload=payload,
                hostname=self.hostname,
                user_id=self.user_id,
                labels=labels,
            )
        )

    def evaluate(self, event: AgentEvent) -> ProcessResult:
        return self.sensor.evaluate(event)

    def record(self, result: ProcessResult, enforcement: Enforcement | None = None) -> None:
        self.sensor.record(result, enforcement)


class Adapter(Protocol):
    name: str

    async def run(self, ctx: AdapterContext) -> None:
        """Run until cancelled. Reconnect on transient errors; let cancellation propagate."""
        ...
