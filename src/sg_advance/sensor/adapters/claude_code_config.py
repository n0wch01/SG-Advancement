"""Claude Code config check (M6): is the SG-Advance hook in place, and where.

Every minute (cheap: a few small JSON files) the sensor reads Claude Code's managed settings and the
user's ``~/.claude/settings.json`` and sends a ``config.snapshot`` (product ``claude-code``) at start
and whenever the result changes: ``guard_plugin`` enabled/missing, ``guard_scope`` managed/user,
``default_mode``, ``bypass_disabled``. Only those fields leave the endpoint (the files also hold
other people's preferences and paths). Nothing is sent when Claude Code is not on this PC.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ...schema import AgentEvent, SensorType
from .. import claude_code_setup as cc
from .base import AdapterContext

log = logging.getLogger(__name__)


def installed(home: Path, path_env: str | None = None) -> bool:
    return shutil.which("claude", path=path_env) is not None or (home / ".claude").is_dir()


def snapshot(home: Path, platform: str = sys.platform) -> dict[str, Any]:
    st = cc.status(platform=platform, home=home)
    return {
        "product": "claude-code",
        "path": str(cc.user_settings(home)),
        "guard_plugin": "enabled" if st["guard"] in ("managed", "user") else "missing",
        "guard_scope": st["guard"] if st["guard"] in ("managed", "user") else None,
        "guard_detail": {
            "managed": "hook in managed settings",
            "user": "hook only in the user's settings (removable)",
            "missing": "no SG-Advance hook in Claude Code settings",
        }[st["guard"]],
        "default_mode": st["default_mode"],
        "bypass_disabled": st["bypass_disabled"],
    }


class ClaudeCodeConfigAdapter:
    name = "claude-code-config"

    def __init__(
        self,
        home: Path | None = None,
        interval: float = 60.0,
        platform: str = sys.platform,
        path_env: str | None = None,
    ) -> None:
        self.home = home or Path.home()
        self.interval = interval
        self.platform = platform
        self.path_env = path_env
        self._last: dict[str, Any] | None = None

    def poll(self, ctx: AdapterContext) -> bool:
        if not installed(self.home, self.path_env):
            return False
        row = snapshot(self.home, self.platform)
        if row == self._last:
            return False
        changed = [] if self._last is None else sorted(k for k in row if self._last.get(k) != row.get(k))
        self._last = row
        event = AgentEvent.model_validate(
            {
                "ts": datetime.now(UTC),
                "endpoint": {"device_id": "pending", "hostname": ctx.hostname},
                "principal": {"user_id": ctx.user_id},
                "agent": {"type": "claude_code", "session_id": "config:claude-code"},
                "source": {"sensor": SensorType.CLAUDE_CODE_CONFIG},
                "payload": {"kind": "config.snapshot", **row, "changed": changed},
            }
        )
        log.info("claude code guard hook: %s", row["guard_detail"])
        ctx.record(ctx.evaluate(event))
        return True

    async def run(self, ctx: AdapterContext) -> None:
        while True:
            try:
                self.poll(ctx)
            except Exception:  # noqa: BLE001 - a bad settings file must not stop the sensor
                log.exception("claude code config check failed")
            await asyncio.sleep(self.interval)
