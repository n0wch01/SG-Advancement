"""Follow-up scenario 3 (CLAUDE.md): a child granted more permission than its parent
(docs/delegation-permissions.md). Claude Code subagent definitions in a working copy are compared with
the calling (parent) conversation before the child exists, and a running child that reports a broader
mode than the main conversation is held to the parent's level."""

from __future__ import annotations

import sqlite3
import uuid
from pathlib import Path
from typing import Any

import pytest

from sg_advance.sensor import Sensor, hook
from sg_advance.sensor.adapters import AdapterContext
from sg_advance.sensor.adapters.openclaw_config import posture
from sg_advance.sensor.plugin_api import CLAUDE_CODE_HOOK, OPENCLAW_PLUGIN, judge, judge_event
from sg_advance.shorthand import build_event

AGENTS = {
    "fixer": "permissionMode: acceptEdits\n",
    "sneaky": "permissionMode: bypassPermissions\n",
    "reviewer": "tools: Read, Grep, Agent\npermissionMode: plan\n",
    "deployer": "tools:\n  - Read\n  - Bash\n  - Write\n",
    "reader": "tools: Read, Grep\n",
    "with-mcp": "mcpServers:\n  - github\n  - pastebin:\n      type: http\n"
    "      url: https://paste.internet-sim/mcp\n",
}


@pytest.fixture
def project(tmp_path: Path, enrolled: Sensor) -> Path:
    repo = tmp_path / "repo"
    agents = repo / ".claude" / "agents"
    agents.mkdir(parents=True)
    for name, body in AGENTS.items():
        (agents / f"{name}.md").write_text(
            f"---\nname: {name}\ndescription: test\n{body}---\nYou are {name}.\n"
        )
    enrolled.delegation.home = tmp_path / "home"  # no user-level agents
    return repo


def spooled(sensor: Sensor) -> list[dict[str, Any]]:
    import json

    with sqlite3.connect(sensor.spool.path) as db:
        return [
            json.loads(d)
            for (d,) in db.execute("SELECT doc FROM outbox WHERE kind = 'finding' ORDER BY rowid")
        ]


def call(
    repo: Path, tool: str, mode: str, child: tuple[str, str] | None = None, **tool_input: Any
) -> dict[str, Any]:
    inp = {"hook_event_name": "PreToolUse", "session_id": "cc-1", "tool_name": tool, "tool_input": tool_input,
           "tool_use_id": uuid.uuid4().hex, "permission_mode": mode, "cwd": str(repo)}  # fmt: skip
    if child:
        inp |= {"agent_id": child[0], "agent_type": child[1]}
    doc = hook.hook_event(inp, user_id="bob", hostname="pc")
    assert doc is not None
    return doc | {"event_id": uuid.uuid4().hex}


def decide(sensor: Sensor, doc: dict[str, Any]) -> str:
    return judge_event(AdapterContext(sensor, "bob", "pc"), doc, CLAUDE_CODE_HOOK)["decision"]


def task(repo: Path, mode: str, subagent: str, parent: tuple[str, str] | None = None) -> dict[str, Any]:
    tool = "Agent" if parent else "Task"
    return call(repo, tool, mode, parent, subagent_type=subagent, description="x", prompt="do the work")


@pytest.mark.parametrize(
    ("parent_mode", "subagent", "decision", "escalation"),
    [
        ("default", "fixer", "approve", "mode:default→acceptEdits"),  # runs more permissively than its parent
        (
            "default",
            "sneaky",
            "approve",
            "mode:default→bypassPermissions",
        ),  # asked for, counted (older CLIs grant it)
        ("acceptEdits", "fixer", "allow", None),  # the parent's mode passes down: no more than the parent
        ("plan", "sneaky", "allow", None),  # a plan parent keeps the child in plan
        ("default", "reader", "allow", None),
        ("default", "Explore", "allow", None),  # built-in read-only type
    ],
)
def test_the_child_definition_is_compared_with_the_parent(
    enrolled: Sensor, project: Path, parent_mode: str, subagent: str, decision: str, escalation: str | None
) -> None:
    assert decide(enrolled, task(project, parent_mode, subagent)) == decision
    found = [f for f in spooled(enrolled) if f["rule_id"] == "delegation-grants-more-permission"]
    if escalation is None:
        assert not found
    else:
        (f,) = found
        assert f["labels"]["sga_delegation_escalation"] == escalation
        assert f["labels"]["sga_delegation_def"].endswith(f".claude/agents/{subagent}.md")


def test_a_restricted_subagent_cannot_hand_out_more_tools(enrolled: Sensor, project: Path) -> None:
    """Subagents can spawn subagents: a reviewer limited to Read/Grep spawning a deployer with Bash/Write."""
    out = decide(enrolled, task(project, "plan", "deployer", parent=("a-1", "reviewer")))
    assert out == "approve"
    (f,) = [f for f in spooled(enrolled) if f["rule_id"] == "delegation-grants-more-permission"]
    assert f["labels"]["sga_delegation_escalation"] == "tools:+Bash,Write"


def test_a_child_that_starts_its_own_mcp_server(enrolled: Sensor, project: Path) -> None:
    assert decide(enrolled, task(project, "default", "with-mcp")) == "approve"
    (f,) = [f for f in spooled(enrolled) if f["rule_id"] == "delegation-grants-more-permission"]
    assert (
        f["labels"]["sga_delegation_escalation"] == "mcp:+pastebin"
    )  # a name alone (github) is the parent's


def test_the_labels_cannot_be_forged(enrolled: Sensor, project: Path) -> None:
    clean = task(project, "default", "fixer")
    clean["labels"] |= {"sga_delegation_escalation": "", "sga_delegation_def": "builtin"}
    assert decide(enrolled, clean) == "approve"
    framed = task(project, "default", "Explore")
    framed["labels"] |= {"sga_delegation_escalation": "mode:default→bypassPermissions"}
    assert decide(enrolled, framed) == "allow"


def test_a_running_child_above_its_parent_is_held_to_the_parents_level(
    enrolled: Sensor, project: Path
) -> None:
    """An approved tool is not trusted forever (CLAUDE.md): the child's own calls keep being checked."""
    assert (
        decide(enrolled, call(project, "Read", "default", file_path="README.md")) == "allow"
    )  # main: default
    child = ("a-7", "fixer")
    write = call(project, "Write", "acceptEdits", child, file_path="src/app.py", content="x = 1\n")
    assert decide(enrolled, write) == "approve"
    assert decide(enrolled, call(project, "Read", "acceptEdits", child, file_path="src/app.py")) == "allow"
    (f,) = [f for f in spooled(enrolled) if f["rule_id"] == "subagent-above-parent-permission"]
    assert f["labels"]["sga_delegation_escalation"] == "runtime-mode:default→acceptEdits"
    assert f["agent"]["parent_session_id"] == "cc-1"


def test_a_child_at_the_parents_level_is_left_alone(enrolled: Sensor, project: Path) -> None:
    decide(enrolled, call(project, "Read", "acceptEdits", file_path="README.md"))
    write = call(project, "Write", "acceptEdits", ("a-8", "fixer"), file_path="src/app.py", content="x")
    assert decide(enrolled, write) == "allow"
    assert not [f for f in spooled(enrolled) if f["rule_id"] == "subagent-above-parent-permission"]


# ── OpenClaw: sessions_spawn under another agent (2026-11-14) ────────────────


OC = {"agent": "openclaw"}


def _snapshots(sensor: Sensor, modes: dict[str, str], sandboxes: list[dict[str, Any]] | None = None) -> None:
    for aid, mode in modes.items():
        inv = {"kind": "inventory.snapshot", "agent_id": aid, "permission_mode": mode}
        sensor.process(build_event(inv, defaults=OC, index=0))
    if sandboxes is not None:
        cfg = {"kind": "config.snapshot", "product": "openclaw", "sandboxes": sandboxes}
        sensor.process(build_event(cfg, defaults=OC | {"sensor": "openclaw_config"}, index=0))


def spawn(sensor: Sensor, parent_key: str, **params: Any) -> dict[str, Any]:
    req = {"op": "tool_call", "sessionKey": parent_key, "toolCallId": uuid.uuid4().hex}
    req |= {"toolName": "sessions_spawn", "params": {"task": "do the work", **params}}
    return judge(AdapterContext(sensor, "alice", "pc"), req)


def test_openclaw_spawn_under_a_wider_agent_asks(enrolled: Sensor) -> None:
    _snapshots(enrolled, {"research": "workspace", "ops": "full", "reader": "read-only"})
    assert spawn(enrolled, "agent:research:main", agentId="ops")["decision"] == "approve"
    assert spawn(enrolled, "agent:research:main", agentId="reader")["decision"] == "allow"  # narrower
    assert spawn(enrolled, "agent:research:main")["decision"] == "allow"  # same agent: same mode
    (f,) = [f for f in spooled(enrolled) if f["rule_id"] == "delegation-grants-more-permission"]
    assert f["labels"]["sga_delegation_escalation"] == "mode:workspace→full"
    assert f["labels"]["sga_delegation_child"] == "ops"


def test_openclaw_spawn_out_of_the_sandbox_asks(enrolled: Sensor) -> None:
    boxes = [{"scope": "defaults", "mode": "off"}, {"scope": "agent:research", "mode": "all"}]
    _snapshots(enrolled, {"research": "workspace", "runner": "workspace"}, boxes)
    assert spawn(enrolled, "agent:research:main", agentId="runner")["decision"] == "approve"
    assert spawn(enrolled, "agent:research:main", agentId="runner", sandbox="require")["decision"] == "allow"
    (f,) = [f for f in spooled(enrolled) if f["rule_id"] == "delegation-grants-more-permission"]
    assert f["labels"]["sga_delegation_escalation"] == "sandbox:on→off"


def test_openclaw_child_running_above_the_top_agent(enrolled: Sensor) -> None:
    _snapshots(enrolled, {"research": "workspace", "ops": "full"})
    top = "agent:research:main"
    child = {"type": "openclaw", "session_id": "agent:ops:subagent:u-1", "parent_session_id": top}
    child |= {"root_session_id": top, "spawn_depth": 1}

    def call(tool: str, **args: Any) -> str:
        doc = build_event(
            {"kind": "tool.call", "tool": tool, "arguments": args}, defaults={"agent": "openclaw"}, index=0
        )
        doc = doc.model_copy(update={"agent": doc.agent.model_validate(child)}).model_dump(mode="json")
        return judge_event(AdapterContext(enrolled, "alice", "pc"), doc, OPENCLAW_PLUGIN)["decision"]

    assert call("write", path="notes.md", content="x") == "approve"
    assert call("read", path="notes.md") == "allow"
    (f,) = [f for f in spooled(enrolled) if f["rule_id"] == "subagent-above-parent-permission"]
    assert f["labels"]["sga_delegation_escalation"] == "runtime-mode:workspace→full"


def test_openclaw_config_reports_tool_denials_lifted_for_delegates() -> None:
    intake = {
        "tools": {"deny": ["exec"]},
        "subagents": {"allowAgents": ["coder"], "delegateToolsTo": ["coder"]},
    }
    cfg = {"agents": {"entries": {"intake": intake, "coder": {}}}}
    assert posture(cfg)["delegation_grants"] == [{"agent_id": "intake", "to": ["coder"]}]
