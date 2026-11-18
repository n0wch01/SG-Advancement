"""Agent-neutral decisions at enforcement points (2026-11-18).

See docs/architecture.md "새 집행 지점 붙이기".

Every point that stands between a coding agent and a side effect follows the same contract:

    event = AgentEvent(...)                      # the point builds it (hook, gateway, plugin)
    result = ctx.evaluate(event)                 # stamp + signed rules
    action = approval_channel(result.verdict, point)
    response, enforcement = point_response(result.verdict, point, action)
    ctx.record(result, enforcement)              # the outcome, recorded apart from the verdict

``judge_event`` does all of it for points that hand over a full event (Claude Code and Codex hooks, the
MCP gateway), including the approval audit: approval binding (verification layer 2b) and "no result
before the next prompt" as a refusal. A point is described by what it can do (``EnforcementPoint``:
ask a person, sit in the path, rewrite a result), never by which product it is. Agent-specific
protocols live with their adapters (OpenClaw: ``plugin_api``); the local API that carries requests is
``local_api``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from ..detect import Verdict, rule_titles
from ..redact import redact_text
from ..schema import AgentEvent, Enforcement, EventKind, ResponseAction, SensorType
from ..schema.events import ApprovalResolution
from ..schema.labels import DECISION_OWNED
from .adapters.base import AdapterContext
from .response import BLOCKED_SESSIONS

_BLOCKING = {ResponseAction.BLOCK, ResponseAction.ABORT_SESSION, ResponseAction.QUARANTINE}
DIGEST_LABEL = "sga_input_digest"  # the hook's fingerprint of a tool's input (hook.input_digest)
MISMATCH_LABEL = "sga_approval_mismatch"  # set only by judge_event: the approved input is not what ran




_SEVERITY_RANK = ["info", "low", "medium", "high", "critical"]


def max_severity(verdict: Verdict) -> str | None:
    sev = [str(h.rule.severity) for h in verdict.hits]
    return max(sev, key=_SEVERITY_RANK.index) if sev else None


@dataclass(frozen=True)
class EnforcementPoint:
    """Who applies the verdict before the tool runs, for the enforcement record."""

    sensor: SensorType
    name: str  # "claude code hook", "codex cli hook", "mcp gateway", "openclaw plugin"
    asks: str  # where a require_approval verdict is answered
    # The point itself sits between the agent and the side effect (it does not forward what it
    # refuses), so a refusal is confirmed on the spot. Hooks and plugins hand the decision to the agent:
    # unconfirmed until evidence arrives (a result for a refused call contradicts it).
    in_path: bool = False
    supports_approval: bool = True

    @property
    def awaits_answer(self) -> bool:
        """The agent asks the person itself and runs the call right after: the answer arrives later."""
        return self.supports_approval and not self.in_path

    def outcome(self, in_path_evidence: str) -> dict[str, str]:
        if self.in_path:
            return {"confirmation": "confirmed", "evidence": in_path_evidence}
        return {"confirmation": "unconfirmed", "evidence": f"{self.asks} applies the decision"}
CLAUDE_CODE_HOOK = EnforcementPoint(SensorType.CLAUDE_CODE_HOOK, "claude code hook", "Claude Code")
CODEX_CLI_HOOK = EnforcementPoint(
    SensorType.CODEX_CLI_HOOK, "codex cli hook", "Codex", supports_approval=False
)


def hook_point(event: AgentEvent) -> EnforcementPoint:
    return CODEX_CLI_HOOK if event.source.sensor is SensorType.CODEX_CLI_HOOK else CLAUDE_CODE_HOOK


MCP_GATEWAY = EnforcementPoint(
    SensorType.MCP_PROXY, "mcp gateway", "the agent's own approval prompt", in_path=True
)


# Input PEP (KISA agentic AI ZT guide 2.4, P6-7): tool results with injection findings this severe never
# reach the model at the points that can rewrite a result (MCP gateway, Claude Code PostToolUse).
INPUT_GUARD_SEVERITIES = frozenset({"high", "critical"})


def input_guard_hits(verdict: Verdict) -> list[Any]:
    return [
        h for h in verdict.hits
        if str(h.rule.category) == "prompt_injection" and str(h.rule.severity) in INPUT_GUARD_SEVERITIES
    ]  # fmt: skip


def withheld_response(point: EnforcementPoint, hits: list[Any]) -> tuple[dict[str, Any], Enforcement]:
    titles = rule_titles(hits)
    return {
        "ok": True,
        "decision": "withhold",
        "reason": f"SG-Advance: tool result withheld, it looks like a prompt injection ({titles})",
        "rules": [h.rule.id for h in hits],
    }, Enforcement(
        action=ResponseAction.BLOCK,
        enforced=True,
        enforcer=point.sensor,
        detail=f"input pep: {point.name} withheld the tool result from the model",
        stage="result_withheld",
        **(
            point.outcome("the result was replaced before it was sent to the agent")
            if point.in_path
            else {
                "confirmation": "unconfirmed",
                "evidence": (
                    "Codex applies the output replacement; hook errors may leave the original output visible"
                    if point.sensor is SensorType.CODEX_CLI_HOOK
                    else "Claude Code keeps the original result if the replacement does not fit the "
                    "tool's output shape; the block reason still reaches the model"
                ),
            }
        ),
    )


def approval_channel(verdict: Verdict, point: EnforcementPoint) -> ResponseAction:
    """Grades decide *how* approval happens, never whether (CLAUDE.md). Decision 2026-11-14: the person
    approves in the agent's own prompt, including grade 3-1, and security reviews those approvals
    afterwards (review queue, ``user-approved-high-risk``). Only very high risk is denied outright.
    A point that cannot ask anyone (the MCP gateway) denies instead: an approval nobody can give is no
    approval (fail closed). Decision 2026-11-17: the security team's pre-approval hold was removed.
    Limitation: the agent's own prompt runs the call the moment the person clicks, with no re-check."""
    if verdict.action is ResponseAction.REQUIRE_APPROVAL and (point.in_path or not point.supports_approval):
        return ResponseAction.BLOCK
    return verdict.action


# Irreversible (grade 3-1) calls the person approves get their own prompt (2026-11-14, KISA guide
# scenario 4: approval fatigue; the user chose "warning text only", the flow stays one click). The
# same text reaches Claude Code's ask dialog (permissionDecisionReason) and OpenClaw's approval card,
# where the plugin also raises the severity to critical. What will run is shown clipped and masked:
# the prompt is local, but a secret in a command has no business in an approval dialog either.
IRREVERSIBLE_TAG = "grade:3-1"
IRREVERSIBLE_TITLE = "SG-Advance: 되돌릴 수 없는 작업 확인"
_WHAT_KEYS = ("command", "cmd", "sql", "query", "statement", "url", "file_path", "path", "prompt")
_WHAT_MAX = 160


def _what_runs(event: AgentEvent) -> str:
    p = event.payload
    args: dict[str, Any] = getattr(p, "arguments", None) or {}
    text = next((str(args[k]) for k in _WHAT_KEYS if isinstance(args.get(k), str) and args[k]), None)
    if text is None:
        text = json.dumps(args, ensure_ascii=False, default=str) if args else ""
    text = " ".join(redact_text(text).split())
    tool = getattr(p, "tool", "") or "tool"
    clipped = text if len(text) <= _WHAT_MAX else text[: _WHAT_MAX - 1] + "…"
    return f"{tool}: {clipped}" if clipped else tool


def irreversible_prompt(verdict: Verdict, titles: str) -> str:
    return (
        f"[되돌릴 수 없음 · 3-1] {titles}. 실행할 것: {_what_runs(verdict.event)}. "
        "한 번 실행하면 되돌릴 수 없습니다. 승인하면 보안팀이 사후 검토합니다."
    )


def point_response(
    verdict: Verdict, point: EnforcementPoint, action: ResponseAction | None = None
) -> tuple[dict[str, Any], Enforcement | None]:
    """What an enforcement point should do, and the enforcement record that matches it. ``action``:
    the channel chosen by ``approval_channel`` when it differs from the verdict's."""
    action = action or verdict.action
    rules = verdict.rule_ids
    reason = rule_titles(verdict.hits)
    sensor = point.sensor
    base = {"ok": True, "action": action.value, "rules": rules}
    if severity := max_severity(verdict):
        base["severity"] = severity
    if action in _BLOCKING:
        detail = f"pre-exec: {point.name} blocked the tool call"
        why = f"SG-Advance: {reason}"
        if verdict.action is ResponseAction.REQUIRE_APPROVAL:  # nobody to ask on this path
            detail = f"pre-exec: {point.name} cannot ask a person; denied instead of approval (fail closed)"
            why = f"SG-Advance: 사람에게 물을 수 없는 경로라 승인 대신 거부했습니다 ({reason})"
        return base | {"decision": "block", "reason": why}, Enforcement(
            action=action, enforced=True, enforcer=sensor, detail=detail,
            stage="blocked", **point.outcome("the request was not forwarded upstream"),
        )  # fmt: skip
    if action is ResponseAction.REQUIRE_APPROVAL:
        detail = f"pre-exec: user approval requested through {point.asks}"
        if any(IRREVERSIBLE_TAG in h.rule.tags for h in verdict.hits):
            base |= {"grade": "3-1"}  # the plugin raises its approval card to critical
            prompt = {"title": IRREVERSIBLE_TITLE, "reason": irreversible_prompt(verdict, reason)}
        else:
            prompt = {"title": "SG-Advance", "reason": reason}
        return base | {"decision": "approve"} | prompt, Enforcement(
            action=action, enforced=True, enforcer=sensor, detail=detail
        )
    return base | {"decision": "allow"}, None


def finding_ids_for(verdict: Any, action: ResponseAction) -> list[str]:
    """The findings an approval or block record points at. A block also reports the hits dedup suppressed
    (``Sensor._enforced_repeats``); the agent's own prompt does not, so it doesn't list them."""
    if action is ResponseAction.REQUIRE_APPROVAL:
        return [f.finding_id for f in verdict.findings]
    return verdict.enforced_ids


def pending_for(result: Any, action: ResponseAction, response: dict[str, Any]) -> dict[str, Any]:
    """What a prompt keeps about the call, to link the person's answer back to it."""
    return {
        "event_id": result.event.event_id,
        "finding_ids": finding_ids_for(result.verdict, action),
        "rule_ids": result.verdict.rule_ids,
        "max_severity": response.get("severity"),
        "requested_at": result.event.ts,
    }


def resolution_from_call(
    call: AgentEvent,
    decision: str,
    pending: dict[str, Any],
    *,
    approver: str | None = None,
    via: str = "user",
    labels: dict[str, str] | None = None,
) -> AgentEvent:
    """``approval.resolved`` in the same envelope (who, which agent, which conversation) as the
    tool call that was held. For enforcement points that hand over a full event (Claude Code)."""
    requested_at = pending.get("requested_at")
    now = datetime.now(UTC)
    wait_ms = int((now - requested_at).total_seconds() * 1000) if requested_at else None
    p = call.payload
    return call.model_copy(
        update={
            "event_id": AgentEvent.model_fields["event_id"].default_factory(),  # type: ignore[misc]
            "ts": now,
            "payload": ApprovalResolution(
                call_id=p.call_id,  # type: ignore[union-attr]
                tool=p.tool,  # type: ignore[union-attr]
                decision=decision,  # type: ignore[arg-type]
                approved=decision in ("allow-once", "allow-always"),
                rule_ids=tuple(pending.get("rule_ids") or ()),
                max_severity=pending.get("max_severity"),
                request_event_id=pending.get("event_id"),
                finding_ids=tuple(pending.get("finding_ids") or ()),
                requested_at=requested_at,
                wait_ms=max(wait_ms, 0) if wait_ms is not None else None,
                approver=approver,
                via=via,  # type: ignore[arg-type]
            ),
            "labels": call.labels | (labels or {}),
        }
    )


def judge_event(
    ctx: AdapterContext, doc: dict[str, Any], point: EnforcementPoint | None = None
) -> dict[str, Any]:
    """Judge and record an event an enforcement point built itself (Claude Code hooks, M6).

    ``tool.call``: the same verdicts as the OpenClaw plugin (block / approve → the agent's own
    prompt / allow). ``prompt.user``: blocked only by a blocking verdict.
    Anything else is recorded. A ``tool.result`` for a call that was sent to the person's own
    prompt means they approved it: recorded as ``approval.resolved``. A refusal leaves no result: when
    the person's next prompt (or the session's end) arrives first, it is recorded as a denial
    (``sga_approval_inferred=no_result``; a "No" and an interrupted call look the same).

    Approval binding (verification layer 2b, 2026-11-17): the person approves one input; the result
    carries the input that ran (``sga_input_digest`` from the hook). When they differ the resolution is
    marked ``sga_approval_mismatch`` and the rules decide (``approval-execution-mismatch``: the rest of
    the conversation is blocked). This is detection right after the call, not prevention: the agent
    runs its own prompt, so nothing can check in between."""
    event = AgentEvent.model_validate(doc)
    point = point or hook_point(event)
    if DECISION_OWNED & event.labels.keys():  # only this daemon writes them, never the hook's input
        event = event.model_copy(
            update={"labels": {k: v for k, v in event.labels.items() if k not in DECISION_OWNED}}
        )
    result = ctx.evaluate(event)
    kind = result.event.kind
    if kind is EventKind.TOOL_CALL:
        action = approval_channel(result.verdict, point)
        response, enforcement = point_response(result.verdict, point, action)
        pending = pending_for(result, action, response) | {
            "call": result.event,
            "input_digest": result.event.labels.get(DIGEST_LABEL),
        }
        ctx.record(result, enforcement)
        if response.get("decision") == "approve" and point.awaits_answer:
            # The agent asked the person in its own prompt: a later result means they approved. Points that
            # cannot ask (the MCP gateway, Codex) never reach here with "approve".
            ctx.approvals.remember(result.event.payload.call_id, pending)  # type: ignore[union-attr]
        return response
    withheld: dict[str, Any] | None = None
    if kind is EventKind.TOOL_RESULT and (hits := input_guard_hits(result.verdict)):
        withheld, enforcement = withheld_response(point, hits)
        ctx.record(result, enforcement)
    else:
        ctx.record(result)
    if kind is EventKind.TOOL_RESULT:
        asked = ctx.approvals.take(result.event.payload.call_id)  # type: ignore[union-attr]
        if asked and isinstance(asked.get("call"), AgentEvent):
            labels = {"sga_approval_inferred": "tool_result"}
            approved, ran = asked.get("input_digest"), result.event.labels.get(DIGEST_LABEL)
            if approved and ran and approved != ran:
                labels[MISMATCH_LABEL] = "true"
            inferred = ctx.evaluate(resolution_from_call(asked["call"], "allow-once", asked, labels=labels))
            ctx.record(inferred, _abort_if_blocking(ctx, inferred, point))
    elif kind in (EventKind.PROMPT_USER, EventKind.SESSION_END):
        # The turn is over: an asked call with no result was refused (or interrupted) by the person.
        for asked in ctx.approvals.take_session(_conversation(result.event)):
            if isinstance(asked.get("call"), AgentEvent):
                denied = resolution_from_call(
                    asked["call"], "deny", asked, labels={"sga_approval_inferred": "no_result"}
                )
                ctx.record(ctx.evaluate(denied))
    if withheld is not None:
        return withheld
    if kind is EventKind.PROMPT_USER and result.verdict.action in _BLOCKING:
        reason = rule_titles(result.verdict.hits)
        return {
            "ok": True,
            "decision": "block",
            "reason": f"SG-Advance: {reason}",
            "rules": result.verdict.rule_ids,
        }
    return {"ok": True, "decision": "allow"}


def _conversation(event: AgentEvent) -> str:
    """The main conversation a (sub)agent's event belongs to."""
    return event.agent.root_session_id or event.agent.session_id


def _abort_if_blocking(ctx: AdapterContext, result: Any, point: EnforcementPoint) -> Enforcement | None:
    """A blocking verdict on something that already ran (an approval that does not match what ran):
    block the rest of the conversation through the same set security's remote block uses, so every
    later tool call is refused before it runs (``remote-blocked-session``)."""
    if result.verdict.action not in _BLOCKING:
        return None
    current = set(ctx.sensor.trusted.get(BLOCKED_SESSIONS, set()))
    ctx.sensor.set_trusted(BLOCKED_SESSIONS, current | {_conversation(result.event)})
    return Enforcement(
        action=ResponseAction.ABORT_SESSION,
        enforced=True,
        enforcer=point.sensor,
        stage="session_aborted",
        detail="conversation blocked from now on: what ran is not what the person approved",
    )
