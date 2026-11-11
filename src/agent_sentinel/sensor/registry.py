"""Shared in-daemon state between enforcement points and observers."""

from __future__ import annotations

import json
import time
from collections import OrderedDict
from pathlib import Path


class PluginRegistry:
    """What the in-gateway plugin has already judged, and whether it is still alive.

    - ``seen(call_id)``: the plugin judged this call before it ran, so the WebSocket adapter
      neither judges it twice nor calls it a bypass.
    - ``expected``: once the plugin has said hello, this endpoint is expected to keep it. The flag
      is sticky and persisted (``state_path``): disabling the plugin and waiting, or restarting the
      daemon, must not silently switch bypass detection off.
    - ``check()`` reports ``"lost"`` once when heartbeats stop for ``lost_after`` seconds; the next
      hello reports ``"recovered"``.
    """

    def __init__(self, keep: int = 20_000, lost_after: float = 150.0, state_path: Path | None = None) -> None:
        self._seen: OrderedDict[str, float] = OrderedDict()
        self.keep = keep
        self.lost_after = lost_after
        self.state_path = state_path
        self.tool_plugins: dict[str, str] = {}  # tool name -> plugin id, filled by the WS adapter
        self.expected = False
        self.last_contact: float | None = None  # wall clock (epoch seconds)
        self.lost_reported = False
        self._started = time.time()
        self._load()

    # ── persistence ──────────────────────────────────────────────────────────

    def _load(self) -> None:
        if self.state_path is None or not self.state_path.exists():
            return
        try:
            doc = json.loads(self.state_path.read_text("utf-8"))
        except (OSError, ValueError):
            return
        self.expected = bool(doc.get("expected"))
        last = doc.get("last_contact")
        self.last_contact = float(last) if isinstance(last, int | float) else None
        self.lost_reported = bool(doc.get("lost_reported"))

    def _save(self) -> None:
        if self.state_path is None:
            return
        from .state import write_private

        doc = {
            "expected": self.expected,
            "last_contact": self.last_contact,
            "lost_reported": self.lost_reported,
        }
        write_private(self.state_path, json.dumps(doc))

    # ── liveness ─────────────────────────────────────────────────────────────

    def touch(self, now: float | None = None) -> str | None:
        """Any message from the plugin. Returns ``"recovered"`` after a reported loss."""
        self.last_contact = now if now is not None else time.time()
        transition = None
        if self.lost_reported:
            self.lost_reported = False
            transition = "recovered"
        if not self.expected or transition:
            self.expected = True
            self._save()
        return transition

    def heartbeat(self, now: float | None = None) -> str | None:
        """The plugin's periodic hello; also persisted so a restart remembers the last contact."""
        transition = self.touch(now)
        self._save()
        return transition

    def check(self, now: float | None = None) -> str | None:
        """Called periodically by the daemon. Returns ``"lost"`` once per outage."""
        if not self.expected or self.lost_reported:
            return None
        now = now if now is not None else time.time()
        since = self.last_contact if self.last_contact is not None else self._started
        if now - since > self.lost_after:
            self.lost_reported = True
            self._save()
            return "lost"
        return None

    @property
    def active(self) -> bool:
        """Bypass detection is on: this endpoint is expected to run the plugin."""
        return self.expected

    # ── judged calls ─────────────────────────────────────────────────────────

    def mark(self, call_id: str) -> None:
        self._seen[call_id] = time.monotonic()
        self._seen.move_to_end(call_id)
        while len(self._seen) > self.keep:
            self._seen.popitem(last=False)

    def seen(self, call_id: str) -> bool:
        return call_id in self._seen
