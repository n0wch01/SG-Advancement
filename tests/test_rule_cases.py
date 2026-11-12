"""Regression cases for rules/*.yaml (see docs/detection.md).

Each file in tests/rule_cases/ lists cases: a short event stream plus the rule ids that must
(``expect``) and must not (``expect_not``) hit. Events are written as payload dicts; envelope
fields are filled in by sg_advance.shorthand. Optional per-event keys: ``at`` (seconds from
start), ``session``, ``user``, ``device``, ``sensor``. Optional per-case keys: ``agent``, ``sensor``,
``sets`` (sensor-maintained sets for ``allow_trusted`` / ``in_set`` rules, name → values).

When you find a false positive / negative, add it here first, watch it fail, then tune the rule.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from sg_advance.detect import Engine, RuleSet
from sg_advance.shorthand import build_event

ROOT = Path(__file__).resolve().parents[1]
RULES = RuleSet.load(ROOT / "rules")
CASE_DIR = Path(__file__).parent / "rule_cases"


def _load_cases() -> list[tuple[str, dict[str, Any]]]:
    out = []
    for f in sorted(CASE_DIR.glob("*.yaml")):
        for case in yaml.safe_load(f.read_text(encoding="utf-8"))["cases"]:
            out.append((f"{f.stem}: {case['name']}", case))
    return out


CASES = _load_cases()


def hit_rule_ids(case: dict[str, Any]) -> set[str]:
    defaults = {k: case[k] for k in ("agent", "sensor") if k in case}
    events = [build_event(s, defaults=defaults, index=i) for i, s in enumerate(case["events"])]
    events.sort(key=lambda e: e.ts)
    sets = {name: set(values) for name, values in (case.get("sets") or {}).items()}
    return {rid for v in Engine(RULES, sets).replay(events) for rid in v.rule_ids}


@pytest.mark.parametrize("case", [c for _, c in CASES], ids=[n for n, _ in CASES])
def test_rule_case(case: dict[str, Any]) -> None:
    known = {r.id for r in RULES.rules}
    referenced = set(case.get("expect", [])) | set(case.get("expect_not", []))
    assert referenced <= known, f"unknown rule ids: {referenced - known}"

    hits = hit_rule_ids(case)
    missing = set(case.get("expect", [])) - hits
    unexpected = set(case.get("expect_not", [])) & hits
    assert not missing, f"false negative — expected to hit: {sorted(missing)} (hits: {sorted(hits)})"
    assert not unexpected, f"false positive — must not hit: {sorted(unexpected)}"


def test_every_enabled_rule_has_positive_and_negative_case() -> None:
    positive = {rid for _, c in CASES for rid in c.get("expect", [])}
    negative = {rid for _, c in CASES for rid in c.get("expect_not", [])}
    enabled = {r.id for r in RULES.enabled}
    assert not enabled - positive, f"rules without a positive case: {sorted(enabled - positive)}"
    assert not enabled - negative, f"rules without a negative case: {sorted(enabled - negative)}"


def test_bundled_rules_load() -> None:
    assert len(RULES.enabled) >= 20
