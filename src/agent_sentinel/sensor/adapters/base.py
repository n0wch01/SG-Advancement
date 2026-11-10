"""Adapter contract.

An adapter observes one agent (or one interception point) and yields AgentEvents. The runtime
feeds each one to ``Sensor.process`` and hands the verdict back through ``enforce``.

Observation-only adapters (replay, OpenClaw's post-hoc stream) can leave ``enforce`` as a no-op;
blocking adapters (Claude Code hooks M6, MCP proxy M8) act on ``verdict.action``.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Protocol

from ...detect import Verdict
from ...schema import AgentEvent


class Adapter(Protocol):
    name: str

    def events(self) -> Iterator[AgentEvent]: ...

    def enforce(self, verdict: Verdict) -> None: ...
