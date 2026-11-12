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

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

from ...schema import Enforcement
from ..registry import PluginRegistry
from .openclaw_people import OpenClawPeople

if TYPE_CHECKING:
    from ...schema import AgentEvent
    from ..core import ProcessResult, Sensor


# Remote response (M11): action name → async handler(target) → (ok, detail). The core registers
# block/unblock; adapters register what only they can do (abort a run, disable a plugin).
ActionHandler = Callable[[str], Awaitable[tuple[bool, str]]]


@dataclass
class AdapterContext:
    sensor: Sensor
    user_id: str  # the employee this endpoint's agents act for
    hostname: str | None = None
    plugins: PluginRegistry = field(default_factory=PluginRegistry)  # in-gateway plugin's judgements
    people: OpenClawPeople = field(default_factory=OpenClawPeople)  # team gateway: session/run → person
    actions: dict[str, ActionHandler] = field(default_factory=dict)  # remote response handlers (M11)

    def evaluate(self, event: AgentEvent) -> ProcessResult:
        return self.sensor.evaluate(event)

    def record(self, result: ProcessResult, enforcement: Enforcement | None = None) -> None:
        self.sensor.record(result, enforcement)


class Adapter(Protocol):
    name: str

    async def run(self, ctx: AdapterContext) -> None:
        """Run until cancelled. Reconnect on transient errors; let cancellation propagate."""
        ...
