"""Agent identity (2026-11-16): the person, the device and *which agent*. The sensor names the agent from
what it observes; findings carry it, rules can match it (``agent.agent_id``)."""

from __future__ import annotations

import uuid

from sg_advance.sensor import Sensor, hook
from sg_advance.sensor.adapters import AdapterContext
from sg_advance.sensor.identity import identity
from sg_advance.shorthand import build_event


def stamped(sensor: Sensor, doc: dict) -> object:
    from sg_advance.schema import AgentEvent

    return sensor.stamp(AgentEvent.model_validate(doc | {"event_id": uuid.uuid4().hex}))


def claude(inp: dict) -> dict:
    doc = hook.hook_event({"session_id": "cc-1", "hook_event_name": "PreToolUse", "tool_name": "Bash",
                           "tool_use_id": "t1", "tool_input": {"command": "ls"}, **inp},
                          user_id="bob", hostname="pc")  # fmt: skip
    assert doc is not None
    return doc


def test_claude_codes_main_agent_and_a_subagent_are_two_agents(enrolled: Sensor) -> None:
    main = stamped(enrolled, claude({}))
    sub = stamped(enrolled, claude({"agent_id": "a1", "agent_type": "fixer"}))
    assert main.agent.agent_id == "main" and sub.agent.agent_id == "fixer"  # type: ignore[attr-defined]
    assert identity(sub) == "bob@dev-alice/claude_code:fixer"  # type: ignore[arg-type]


def test_openclaw_agents_come_from_the_session_key(enrolled: Sensor) -> None:
    cases = (("agent:research:web:x", "research"), ("inventory:main", "main"), ("config:openclaw", None))
    for session, want in cases:
        ev = build_event({"kind": "tool.call", "tool": "exec", "arguments": {"command": "ls"}},
                         defaults={"agent": "openclaw"})  # fmt: skip
        ev = ev.model_copy(update={"agent": ev.agent.model_copy(update={"session_id": session})})
        assert enrolled.stamp(ev).agent.agent_id == want


def test_findings_carry_the_agent(enrolled: Sensor) -> None:
    ctx = AdapterContext(enrolled, "bob", "pc")
    doc = claude({"agent_id": "a1", "agent_type": "fixer", "tool_input": {"command": "rm -rf ~/projects"}})
    result = ctx.evaluate(stamped(enrolled, doc))  # type: ignore[arg-type]
    f = next(f for f in result.verdict.findings if f.rule_id == "destructive-shell-command")
    assert f.agent.agent_id == "fixer"
