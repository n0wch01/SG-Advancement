"""OpenClaw's per-daemon state, kept out of the agent-neutral ``AdapterContext`` (2026-11-18).

The OpenClaw integration is optional: the core and the Claude Code / Codex paths never touch it. The
plugin protocol (``plugin_api``) and the WebSocket adapter reach it through ``openclaw(ctx)``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..registry import PluginRegistry
from .openclaw_people import OpenClawPeople

if TYPE_CHECKING:
    from .base import AdapterContext

KEY = "openclaw"


@dataclass
class OpenClawState:
    plugins: PluginRegistry = field(default_factory=PluginRegistry)  # gateway plugin: judged calls, liveness
    people: OpenClawPeople = field(default_factory=OpenClawPeople)  # team gateway: session/run → person


def openclaw(ctx: AdapterContext) -> OpenClawState:
    """This daemon's OpenClaw state (created empty on first use)."""
    state = ctx.extensions.setdefault(KEY, OpenClawState())
    if not isinstance(state, OpenClawState):
        raise TypeError(f"extension {KEY!r} is not OpenClaw state")
    return state


def attach(ctx: AdapterContext, state: OpenClawState) -> OpenClawState:
    """Use persisted state (the daemon) or a prepared one (tests)."""
    ctx.extensions[KEY] = state
    return state
