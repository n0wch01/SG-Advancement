"""Security approval on the endpoint (M11): hold a tool call until security decides in the console.

    plugin ── tool_call ──▶ daemon: verdict security_approval → {"decision": "hold", "hold_id"}
    plugin ── await_hold ─▶ daemon registers it on the control plane, polls for the decision
           ◀─ allow | block (denied, nobody decided in time, control plane unreachable, cancelled)

Decision 2026-11-12: wait 5 minutes, then deny. The control plane stops taking decisions a little
before the device stops waiting, so an accepted decision always has time to arrive. Every hold ends
in an ``approval.resolved`` event (``via: security``, ``approver`` = who decided) and the actual
outcome is reported back, since the console must not show "approved" for a call that never ran.
The cached-policy CLI path cannot wait for anyone: there the plugin is told to block.

2026-11-13 (CLAUDE.md phase 1): an approval is bound to the exact request. The hold registers a
digest of the call (tool, arguments, call id, session); a decision that comes back with another
digest, or none, is a refusal (``mismatch``). Right before an approved call is released it is judged
again with the latest policy and state (remote blocks, posture, risk, policy freshness, task scope);
a blocking condition that appeared while it waited refuses it (``rechecked``).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from ..redact import redact_text
from .client import ControlPlaneError, Offline

if TYPE_CHECKING:
    from .adapters.base import AdapterContext

log = logging.getLogger(__name__)

WAIT_SECONDS = 300.0
POLL_SECONDS = 1.0
DECISION_MARGIN = 2  # seconds: the control plane closes decisions this much before the device gives up
PREVIEW_MAX = 2000

# outcome → (approval.resolved decision, what the plugin is told)
_OUTCOMES = {
    "allowed": "allow-once",
    "denied": "deny",
    "timeout": "timeout",
    "cancelled": "cancelled",
    "unreachable": "deny",
    "mismatch": "deny",
    "rechecked": "deny",
}


def request_digest(event: Any) -> str:
    """What an approval is bound to: the call exactly as it will run."""
    p = event.payload
    doc = {
        "tool": getattr(p, "tool", None),
        "arguments": getattr(p, "arguments", None),
        "call_id": getattr(p, "call_id", None),
        "session_id": event.agent.session_id,
        "user_id": event.principal.user_id,
    }
    raw = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()


def block_message(outcome: str, by: str | None, reason: str, wait_seconds: float) -> str:
    if outcome == "denied":
        return f"SG-Advance: 보안팀이 거부했습니다 ({by or '보안팀'}: {reason})"
    if outcome == "timeout":
        return f"SG-Advance: 보안팀 승인을 {int(wait_seconds // 60)}분 안에 받지 못해 거부했습니다"
    if outcome == "unreachable":
        return "SG-Advance: 관제 서버에 연결할 수 없어 보안팀 승인을 요청하지 못해 거부했습니다"
    if outcome == "mismatch":
        return "SG-Advance: 승인이 이 요청과 일치하지 않아 거부했습니다"
    if outcome == "rechecked":
        return f"SG-Advance: 승인 후 실행 직전 다시 확인했더니 차단 조건이 생겨 거부했습니다 ({reason})"
    return "SG-Advance: 보안팀 승인 대기 중 실행이 취소됐습니다"


@dataclass
class Hold:
    id: str
    req: dict[str, Any]  # the plugin's tool_call request (for the resolution event)
    pending: dict[str, Any]  # event id, findings, rules, severity, requested_at
    summary: dict[str, Any]  # what the console shows
    deadline: float  # monotonic
    registered: bool = False
    future: asyncio.Future[dict[str, Any]] | None = None
    early: dict[str, Any] | None = None  # resolved before anyone awaited it (cancel)
    call_event: Any = None  # the held tool.call, for enforcement points that send full events (M6)
    digest: str = ""  # request_digest(call_event): what the approval must name


class Holds:
    def __init__(self, wait_seconds: float = WAIT_SECONDS) -> None:
        self.wait_seconds = wait_seconds
        self._open: dict[str, Hold] = {}

    @property
    def waiting(self) -> bool:
        return any(h.registered for h in self._open.values())

    def open(
        self, req: dict[str, Any], pending: dict[str, Any], summary: dict[str, Any], call_event: Any = None
    ) -> Hold:
        hold = Hold(
            id=uuid4().hex,
            req=req,
            pending=pending,
            summary=summary,
            deadline=time.monotonic() + self.wait_seconds,
            call_event=call_event,
            digest=request_digest(call_event) if call_event is not None else "",
        )
        if hold.digest:
            hold.summary = hold.summary | {"request_digest": hold.digest}
        self._open[hold.id] = hold
        return hold

    def discard(self, hold_id: str) -> None:
        """A hold nobody will wait for (monitor mode)."""
        self._open.pop(hold_id, None)

    def resolve(self, hold_id: str, outcome: str, by: str | None = None, reason: str = "") -> bool:
        hold = self._open.get(hold_id)
        if hold is None:
            return False
        result = {"outcome": outcome, "by": by, "reason": reason}
        if hold.future is None:
            hold.early = hold.early or result
        elif not hold.future.done():
            hold.future.set_result(result)
        return True

    async def poll(self, ctx: AdapterContext) -> int:
        """Fetch decisions for the holds waiting here. Returns how many it applied."""
        if not self.waiting:
            return 0
        try:
            decisions = await asyncio.to_thread(ctx.sensor.client.get_security_decisions)
        except (Offline, ControlPlaneError) as e:
            log.debug("security decisions unavailable: %s", e)
            return 0
        applied = 0
        for d in decisions:
            outcome = "allowed" if d.get("decision") == "approved" else "denied"
            hold = self._open.get(str(d.get("id")))
            if (
                outcome == "allowed"
                and hold is not None
                and hold.digest
                and d.get("request_digest") != hold.digest
            ):
                # The approval names another request (or none): never run this one on it.
                log.warning("security approval %s does not match the held request: refused", hold.id)
                outcome = "mismatch"
            applied += self.resolve(str(d.get("id")), outcome, d.get("by"), str(d.get("reason") or ""))
        return applied

    async def wait(self, ctx: AdapterContext, hold_id: str) -> dict[str, Any]:
        """Block until security decides (or the wait ends); the plugin's answer."""
        hold = self._open.get(hold_id)
        if hold is None:
            return {"ok": True, "decision": "block", "reason": "SG-Advance: 알 수 없는 승인 요청입니다"}
        hold.future = asyncio.get_running_loop().create_future()
        result: dict[str, Any] = hold.early or {"outcome": "timeout", "by": None, "reason": ""}
        try:
            if hold.early is None:
                body = hold.summary | {
                    "id": hold.id,
                    "wait_seconds": max(1, int(hold.deadline - time.monotonic()) - DECISION_MARGIN),
                }
                try:
                    await asyncio.to_thread(ctx.sensor.client.create_security_approval, body)
                    hold.registered = True
                except (Offline, ControlPlaneError) as e:
                    log.warning("could not ask security for %s: %s", hold.req.get("toolName"), e)
                    result = {"outcome": "unreachable", "by": None, "reason": str(e)}
                else:
                    log.warning("holding %s for security approval (%s)", hold.req.get("toolName"), hold.id)
                    try:
                        remaining = max(hold.deadline - time.monotonic(), 0)
                        result = await asyncio.wait_for(asyncio.shield(hold.future), remaining)
                    except TimeoutError:
                        pass
        finally:
            self._open.pop(hold_id, None)
        if result["outcome"] == "allowed" and hold.call_event is not None:
            # Right before release: judge the same call again with the latest policy and state.
            blocking = ctx.sensor.recheck(hold.call_event)
            if blocking:
                titles = "; ".join(dict.fromkeys(h.rule.title for h in blocking))
                log.warning("security approval %s: re-check blocks it now (%s)", hold.id, titles)
                result = {"outcome": "rechecked", "by": result["by"], "reason": titles}
        await self._finish(ctx, hold, result)
        if result["outcome"] == "allowed":
            return {"ok": True, "decision": "allow", "approver": result["by"]}
        msg = block_message(result["outcome"], result["by"], result["reason"], self.wait_seconds)
        return {"ok": True, "decision": "block", "reason": msg, "outcome": result["outcome"]}

    async def _finish(self, ctx: AdapterContext, hold: Hold, result: dict[str, Any]) -> None:
        from .plugin_api import resolution_event, resolution_from_call  # plugin_api imports this module

        outcome = result["outcome"]
        labels = {"sga_security_hold": hold.id, "sga_security_outcome": outcome}
        if hold.call_event is not None:
            event = resolution_from_call(
                hold.call_event,
                _OUTCOMES[outcome],
                hold.pending,
                approver=result["by"],
                via="security",
                labels=labels,
            )
        else:
            req = hold.req | {"decision": _OUTCOMES[outcome], "source": "daemon"}
            event = resolution_event(ctx, req, hold.pending)
            payload = event.payload.model_copy(update={"via": "security", "approver": result["by"]})
            event = event.model_copy(update={"payload": payload, "labels": event.labels | labels})
        ctx.record(ctx.evaluate(event))
        log.warning("security approval %s: %s for %s", hold.id, outcome, hold.req.get("toolName"))
        if hold.registered:
            try:
                await asyncio.to_thread(ctx.sensor.client.report_security_outcome, hold.id, outcome)
            except (Offline, ControlPlaneError) as e:
                log.warning("could not report security approval outcome %s: %s", hold.id, e)


def summary_for(event: Any, response: dict[str, Any], pending: dict[str, Any]) -> dict[str, Any]:
    """What security sees in the console: who, which tool, redacted arguments, why it was held."""
    args = getattr(event.payload, "arguments", {}) or {}
    preview = redact_text(json.dumps(args, ensure_ascii=False, default=str))[:PREVIEW_MAX]
    return {
        "tool": str(getattr(event.payload, "tool", "unknown"))[:200],
        "arguments_preview": preview,
        "reason": str(response.get("reason") or "")[:1000],
        "rule_ids": list(pending.get("rule_ids") or [])[:50],
        "severity": pending.get("max_severity"),
        "user_id": event.principal.user_id[:200],
        "session_id": event.agent.session_id[:200],
        "event_id": pending.get("event_id"),
        "finding_ids": list(pending.get("finding_ids") or [])[:50],
    }
