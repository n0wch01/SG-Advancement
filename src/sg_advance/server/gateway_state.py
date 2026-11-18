"""Threat-detection state that lasts across calls at the resource gateways (2026-11-18, user decision).

The resource gateways used to judge every call with a fresh engine, so nothing that needs history ever
fired there: sequence rules (external input, then a risky action), rate limits, session dedup. Each
(device, agent session) now keeps one engine for as long as the policy version stays the same, the same
way the endpoint daemon keeps one engine per PC.

Limits: the state lives in this server process (one worker; several workers would each keep their own,
like the other ``app.state`` caches), is forgotten on restart and after ``idle_seconds``, and starts
over when the policy version changes.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field

from ..detect import Engine, Verdict
from ..policy import PolicyBundle
from ..schema import AgentEvent

MAX_SESSIONS = 2000
IDLE_SECONDS = 3600.0


@dataclass
class _Slot:
    version: str
    engine: Engine
    lock: threading.Lock = field(default_factory=threading.Lock)
    used: float = 0.0


class SessionEngines:
    def __init__(
        self,
        max_sessions: int = MAX_SESSIONS,
        idle_seconds: float = IDLE_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.max_sessions = max_sessions
        self.idle_seconds = idle_seconds
        self.clock = clock
        self._slots: OrderedDict[tuple[str, str], _Slot] = OrderedDict()
        self._lock = threading.Lock()

    def _slot(self, key: tuple[str, str], policy: PolicyBundle, build: Callable[[], Engine]) -> _Slot:
        now = self.clock()
        with self._lock:
            for stale in [k for k, s in self._slots.items() if now - s.used > self.idle_seconds]:
                del self._slots[stale]
            slot = self._slots.get(key)
            if slot is None or slot.version != policy.version:
                slot = _Slot(policy.version, build())
                self._slots[key] = slot
            slot.used = now
            self._slots.move_to_end(key)
            while len(self._slots) > self.max_sessions:
                self._slots.popitem(last=False)
            return slot

    def process(
        self,
        device_id: str,
        session_id: str,
        policy: PolicyBundle,
        build: Callable[[], Engine],
        event: AgentEvent,
    ) -> Verdict:
        """Judge ``event`` with this session's engine; calls of one session are judged one at a time."""
        slot = self._slot((device_id, session_id), policy, build)
        with slot.lock:
            return slot.engine.process(event)

    def __len__(self) -> int:
        return len(self._slots)
