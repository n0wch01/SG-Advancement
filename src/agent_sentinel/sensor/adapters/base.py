"""Adapter contract.

An adapter observes one agent (or one interception point), turns what it sees into AgentEvents
and hands each one to the daemon through ``AdapterContext``:

    result = ctx.evaluate(event)        # stamp + local rules → verdict (nothing queued yet)
    enforcement = ...                   # adapter acts on result.verdict.action, if it can
    ctx.record(result, enforcement)     # queue redacted event + findings with the outcome

Observation-only adapters pass ``None`` as enforcement. Blocking adapters (OpenClaw plugin M5c,
Claude Code hooks M6, MCP proxy M8) act before the tool runs; the OpenClaw WebSocket adapter can only
abort after a tool started (or deny a pending shell approval).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from ...schema import Enforcement

if TYPE_CHECKING:
    from ...schema import AgentEvent
    from ..core import ProcessResult, Sensor


@dataclass
class AdapterContext:
    sensor: Sensor
    user_id: str  # the employee this endpoint's agents act for
    hostname: str | None = None

    def evaluate(self, event: AgentEvent) -> ProcessResult:
        return self.sensor.evaluate(event)

    def record(self, result: ProcessResult, enforcement: Enforcement | None = None) -> None:
        self.sensor.record(result, enforcement)


class Adapter(Protocol):
    name: str

    async def run(self, ctx: AdapterContext) -> None:
        """Run until cancelled. Reconnect on transient errors; let cancellation propagate."""
        ...
