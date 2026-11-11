"""Replay adapter: AgentEvent JSONL files as if an agent were producing them live.

Used for the end-to-end demos and as the reference adapter for tests.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from pathlib import Path

from ...detect.cli import load_events
from ...schema import AgentEvent
from .base import AdapterContext


class ReplayAdapter:
    name = "replay"

    def __init__(self, paths: list[Path], delay: float = 0.0) -> None:
        self.paths = paths
        self.delay = delay
        self.done = asyncio.Event()

    def events(self) -> Iterator[AgentEvent]:
        # load_events parses each line once, so every event keeps one event_id (server dedup).
        yield from load_events(self.paths)

    async def run(self, ctx: AdapterContext) -> None:
        for ev in self.events():
            ctx.record(ctx.evaluate(ev))  # observation only
            if self.delay:
                await asyncio.sleep(self.delay)
        self.done.set()
