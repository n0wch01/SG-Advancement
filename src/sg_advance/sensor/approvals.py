"""Approvals waiting for a person's answer, for every enforcement point (2026-11-18).

An agent's own prompt (Claude Code, the OpenClaw plugin's approval card) answers outside the sensor; this
keeps what asked (the call, its findings and rules, the input fingerprint) until the answer, a result or
the end of the turn links back to it (``decision.judge_event``, ``plugin_api.record_resolution``).
In memory only: a daemon restart forgets open prompts, and their answers are recorded without the link.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Any

KEEP = 5_000  # prompts that never resolved (gateway restart, abandoned turn) fall out oldest first


class PendingApprovals:
    def __init__(self, keep: int = KEEP) -> None:
        self.keep = keep
        self._pending: OrderedDict[str, dict[str, Any]] = OrderedDict()

    def remember(self, call_id: str, context: dict[str, Any]) -> None:
        self._pending[call_id] = context
        self._pending.move_to_end(call_id)
        while len(self._pending) > self.keep:
            self._pending.popitem(last=False)

    def take(self, call_id: str) -> dict[str, Any] | None:
        return self._pending.pop(call_id, None)

    def take_session(self, conversation: str) -> list[dict[str, Any]]:
        """Remove and return the approvals still waiting in one conversation (its main session id; a
        subagent's call counts towards its root). Entries without the call (OpenClaw) never match."""

        def of(ctx: dict[str, Any]) -> str | None:
            agent = getattr(ctx.get("call"), "agent", None)
            return (agent.root_session_id or agent.session_id) if agent is not None else None

        ids = [cid for cid, ctx in self._pending.items() if of(ctx) == conversation]
        return [self._pending.pop(cid) for cid in ids]
