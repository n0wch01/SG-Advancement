"""Four decisions and the order they win in (docs/detection.md "판정 4종과 평가 순서", 2026-11-16).

People read every outcome as allow / deny / approve / mask; the seven actions stay as how it is done.
When several rules hit one call, the strongest action decides, so an approval can never undo a deny
(the same guarantee Microsoft's agent Authorization Fabric gets from "hard deny first")."""

from __future__ import annotations

import yaml

from sg_advance.detect import Engine, RuleSet
from sg_advance.detect.rules import Rule
from sg_advance.schema import DECISION_OF_ACTION, Enforcement, ResponseAction
from sg_advance.shorthand import build_event


def rule(rid: str, response: str) -> Rule:
    return Rule.model_validate(yaml.safe_load(f"""
id: {rid}
severity: high
category: tool_misuse
title: {rid}
response: {response}
when: {{payload.kind: tool.call}}
match: {{type: regex, fields: [payload.arguments], pattern: 'x'}}
"""))


def decided(*responses: str) -> ResponseAction:
    rules = RuleSet([rule(f"r{i}", r) for i, r in enumerate(responses)])
    ev = build_event({"kind": "tool.call", "tool": "Bash", "arguments": {"command": "x"}})
    return Engine(rules).process(ev).action


def test_every_action_is_one_of_four_decisions() -> None:
    live = {a.value for a in ResponseAction if a is not ResponseAction.SECURITY_APPROVAL}  # minus legacy
    assert set(DECISION_OF_ACTION) >= live
    assert set(DECISION_OF_ACTION.values()) == {"allow", "deny", "approve"}  # mask comes from the input PEP


def test_a_deny_always_wins_over_an_approval() -> None:
    assert decided("require_approval", "block") is ResponseAction.BLOCK
    assert decided("security_approval", "block") is ResponseAction.BLOCK
    assert decided("alert", "require_approval", "abort_session") is ResponseAction.ABORT_SESSION


def test_a_rule_still_asking_for_security_approval_is_a_deny() -> None:
    """The security pre-approval hold was removed (2026-11-17): an old rule asking for it reads as block."""
    assert decided("require_approval", "security_approval") is ResponseAction.BLOCK


def test_an_alert_is_allow() -> None:
    assert decided("alert") is ResponseAction.ALERT and DECISION_OF_ACTION["alert"] == "allow"


def test_recorded_outcomes_carry_the_decision() -> None:
    def d(action: ResponseAction, stage: str | None = None) -> str | None:
        return Enforcement(action=action, enforced=True, enforcer="claude_code_hook", stage=stage).decision

    assert d(ResponseAction.BLOCK) == "deny"
    assert d(ResponseAction.BLOCK, "result_withheld") == "mask"  # the input PEP kept a result from the model
    assert d(ResponseAction.REQUIRE_APPROVAL) == "approve"
    assert d(ResponseAction.SECURITY_APPROVAL) == "approve"
    assert d(ResponseAction.QUARANTINE) == "deny"
    assert d(ResponseAction.ALERT) == "allow"
