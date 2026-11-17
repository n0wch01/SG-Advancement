"""Approval binding (verification layer 2b, 2026-11-17): what ran must be what the person approved.

Claude Code runs its own permission prompt, so nothing can check between the person's "Yes" and the
call. The hook fingerprints the tool input before and after; the daemon compares them when the result
arrives. A mismatch blocks the rest of the conversation. A turn that ends with no result records the
person's "No" (it used to be missing from the approval audit)."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from sg_advance.sensor import Sensor, hook
from sg_advance.sensor.adapters import AdapterContext
from sg_advance.sensor.plugin_api import judge_event
from sg_advance.sensor.response import BLOCKED_SESSIONS

BASE = {"session_id": "cc-9", "cwd": "/work/repo", "permission_mode": "default"}
SQL = {"command": "psql -c 'DELETE FROM users;'"}


def send(ctx: AdapterContext, **inp: Any) -> dict[str, Any]:
    ev = hook.hook_event(BASE | inp, user_id="bob", hostname="bob-pc")
    assert ev is not None
    return judge_event(ctx, ev)


def ask(ctx: AdapterContext, call: str, tool_input: dict[str, Any]) -> None:
    r = send(ctx, hook_event_name="PreToolUse", tool_name="Bash", tool_use_id=call, tool_input=tool_input)
    assert r["decision"] == "approve"  # destructive SQL goes to the person's prompt


def ran(ctx: AdapterContext, call: str, tool_input: dict[str, Any] | None) -> dict[str, Any]:
    inp: dict[str, Any] = {"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_use_id": call,
                           "tool_response": "DELETE 3"}  # fmt: skip
    if tool_input is not None:
        inp["tool_input"] = tool_input
    return send(ctx, **inp)


def spooled(sensor: Sensor, kind: str) -> list[dict[str, Any]]:
    with sqlite3.connect(sensor.spool.path) as db:
        rows = db.execute("SELECT doc FROM outbox WHERE kind = ? ORDER BY rowid", (kind,))
        return [json.loads(d) for (d,) in rows]


def resolutions(sensor: Sensor) -> list[dict[str, Any]]:
    return [e for e in spooled(sensor, "event") if e["payload"]["kind"] == "approval.resolved"]


def test_the_digest_is_the_same_before_and_after_and_ignores_key_order() -> None:
    assert hook.input_digest({"a": 1, "b": "x"}) == hook.input_digest({"b": "x", "a": 1})
    assert hook.input_digest(SQL) != hook.input_digest({"command": "psql -c 'DROP TABLE users;'"})
    pre = hook.hook_event(BASE | {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": SQL},
                          user_id="bob", hostname=None)  # fmt: skip
    assert pre is not None and pre["labels"]["sga_input_digest"] == hook.input_digest(SQL)


def test_what_ran_is_what_was_approved(enrolled: Sensor) -> None:
    ctx = AdapterContext(enrolled, "bob", "bob-pc")
    ask(ctx, "t1", SQL)
    ran(ctx, "t1", SQL)
    [r] = resolutions(enrolled)
    assert r["payload"]["decision"] == "allow-once" and "sga_approval_mismatch" not in r["labels"]
    assert "approval-execution-mismatch" not in {f["rule_id"] for f in spooled(enrolled, "finding")}
    assert "cc-9" not in enrolled.trusted.get(BLOCKED_SESSIONS, set())


def test_a_different_call_ran_blocks_the_conversation(enrolled: Sensor) -> None:
    ctx = AdapterContext(enrolled, "bob", "bob-pc")
    ask(ctx, "t1", SQL)
    ran(ctx, "t1", {"command": "psql -c 'DROP TABLE users;'"})  # changed between the prompt and the run
    [r] = resolutions(enrolled)
    assert r["labels"]["sga_approval_mismatch"] == "true"
    finding = {f["rule_id"]: f for f in spooled(enrolled, "finding")}["approval-execution-mismatch"]
    assert finding["severity"] == "critical"
    assert finding["response"]["stage"] == "session_aborted" and finding["response"]["decision"] == "deny"
    assert "cc-9" in enrolled.trusted[BLOCKED_SESSIONS]
    # Every later call in that conversation, and its subagents, is refused before it runs.
    later = send(ctx, hook_event_name="PreToolUse", tool_name="Read", tool_use_id="t2",
                 tool_input={"file_path": "README.md"})  # fmt: skip
    assert later["decision"] == "block"
    sub = send(ctx, hook_event_name="PreToolUse", tool_name="Read", tool_use_id="t3", agent_id="a1",
               tool_input={"file_path": "README.md"})  # fmt: skip
    assert sub["decision"] == "block"


def test_no_digest_means_no_comparison(enrolled: Sensor) -> None:
    """An older hook sends no fingerprint: nothing to compare, recorded as before (not a mismatch)."""
    ctx = AdapterContext(enrolled, "bob", "bob-pc")
    ask(ctx, "t1", SQL)
    ran(ctx, "t1", None)
    [r] = resolutions(enrolled)
    assert "sga_approval_mismatch" not in r["labels"]


def test_the_hook_cannot_claim_a_mismatch(enrolled: Sensor) -> None:
    ctx = AdapterContext(enrolled, "bob", "bob-pc")
    ev = hook.hook_event(BASE | {"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_use_id": "t1",
                                 "tool_input": {"file_path": "a"}}, user_id="bob", hostname=None)  # fmt: skip
    assert ev is not None
    ev["labels"]["sga_approval_mismatch"] = "true"
    judge_event(ctx, ev | {"payload": {"kind": "approval.resolved", "call_id": "t1", "tool": "Read",
                                       "decision": "allow-once", "approved": True}})  # fmt: skip
    assert "approval-execution-mismatch" not in {f["rule_id"] for f in spooled(enrolled, "finding")}
    assert "cc-9" not in enrolled.trusted.get(BLOCKED_SESSIONS, set())


def test_no_result_before_the_next_prompt_is_a_no(enrolled: Sensor) -> None:
    ctx = AdapterContext(enrolled, "bob", "bob-pc")
    ask(ctx, "t1", SQL)
    send(ctx, hook_event_name="UserPromptSubmit", prompt="never mind")
    [r] = resolutions(enrolled)
    assert r["payload"]["decision"] == "deny" and r["payload"]["approved"] is False
    assert r["labels"]["sga_approval_inferred"] == "no_result"
    ran(ctx, "t1", SQL)  # a late result no longer resolves it twice
    assert len(resolutions(enrolled)) == 1


def test_another_conversation_keeps_its_open_prompt(enrolled: Sensor) -> None:
    ctx = AdapterContext(enrolled, "bob", "bob-pc")
    ask(ctx, "t1", SQL)
    ev = hook.hook_event({**BASE, "session_id": "cc-other", "hook_event_name": "SessionEnd"},
                         user_id="bob", hostname=None)  # fmt: skip
    judge_event(ctx, ev)  # type: ignore[arg-type]
    assert resolutions(enrolled) == []
    ran(ctx, "t1", SQL)
    assert [r["payload"]["decision"] for r in resolutions(enrolled)] == ["allow-once"]
