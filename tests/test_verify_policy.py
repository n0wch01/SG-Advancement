"""scripts/verify_policy.py (docs/verification.md, layer 4): a rule change that weakens enforcement is never
silent. Removed, disabled, weaker response, lower severity, or changed under the same version: a person
reads it before it ships."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import yaml

from sg_advance.detect.rules import Rule

ROOT = Path(__file__).resolve().parents[1]


def _script():
    spec = importlib.util.spec_from_file_location("sga_verify_policy", ROOT / "scripts" / "verify_policy.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look their module up while the script runs
    spec.loader.exec_module(module)
    return module


vp = _script()


def rule(rid: str = "r", response: str = "block", severity: str = "high", version: str = "1",
         enabled: bool = True, pattern: str = "x") -> Rule:  # fmt: skip
    return Rule.model_validate(yaml.safe_load(f"""
id: {rid}
version: "{version}"
enabled: {str(enabled).lower()}
severity: {severity}
category: tool_misuse
title: {rid}
response: {response}
when: {{payload.kind: tool.call}}
match: {{type: regex, fields: [payload.arguments], pattern: '{pattern}'}}
"""))


def changes(base: list[Rule], cur: list[Rule]) -> dict[str, tuple[str, bool]]:
    return {f"{c.rule_id}:{c.what}": (c.detail, c.review) for c in vp.compare(base, cur)}


def test_nothing_changed() -> None:
    assert vp.compare([rule()], [rule()]) == []


def test_a_weaker_response_is_for_review_a_stronger_one_is_not() -> None:
    weaker = changes([rule()], [rule(response="require_approval", version="2")])
    assert weaker["r:weaker response"] == ("block → require_approval", True)
    stronger = changes([rule(response="alert")], [rule(response="block", version="2")])
    assert stronger["r:stronger response"][1] is False


def test_removed_disabled_and_lower_severity_are_for_review() -> None:
    assert changes([rule()], [])["r:removed"][1]
    assert changes([rule()], [rule(enabled=False, version="2")])["r:disabled"][1]
    assert changes([rule()], [rule(severity="medium", version="2")])["r:lower severity"][1]


def test_a_change_under_the_same_version_is_for_review() -> None:
    c = changes([rule()], [rule(pattern="y")])
    assert c["r:changed without a new version"][1]
    assert changes([rule()], [rule(pattern="y", version="2")]) == {"r:changed": ("version 1 → 2", False)}


def test_an_added_rule_is_listed() -> None:
    assert changes([], [rule("new", response="abort_session", severity="critical")]) == {
        "new:added": ("critical · abort_session", False)
    }
