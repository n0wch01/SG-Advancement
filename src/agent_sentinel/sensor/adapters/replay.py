"""Replay adapter: AgentEvent JSONL files as if an agent were producing them live.

Used for the M4 end-to-end demo and as the reference adapter for tests.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from ...detect import Verdict
from ...detect.cli import load_events
from ...schema import AgentEvent


class ReplayAdapter:
    name = "replay"

    def __init__(self, paths: list[Path]) -> None:
        self.paths = paths

    def events(self) -> Iterator[AgentEvent]:
        # load_events parses each line once, so every event keeps one event_id (server dedup).
        yield from load_events(self.paths)

    def enforce(self, verdict: Verdict) -> None:
        return None  # observation only
