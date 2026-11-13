"""Regression cases for rules/*.yaml (see docs/detection.md).

Each file in tests/rule_cases/ lists cases: a short event stream plus the rule ids that must
(``expect``) and must not (``expect_not``) hit. Events are written as payload dicts; envelope
fields are filled in by sg_advance.shorthand. Optional per-event keys: ``at`` (seconds from
start), ``session``, ``user``, ``device``, ``sensor``. Optional per-case keys: ``agent``, ``sensor``,
``sets`` (sensor-maintained sets for ``allow_trusted`` / ``in_set`` rules, name → values),
``indicators`` (rule id → the campaign indicator its finding must carry, or null for none; M11).

When you find a false positive / negative, add it here first, watch it fail, then tune the rule.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from sg_advance.detect import Engine, RuleSet
from sg_advance.detect.engine import INDICATOR, Verdict
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


def run_case(case: dict[str, Any]) -> list[Verdict]:
    defaults = {k: case[k] for k in ("agent", "sensor") if k in case}
    events = [build_event(s, defaults=defaults, index=i) for i, s in enumerate(case["events"])]
    events.sort(key=lambda e: e.ts)
    sets = {name: set(values) for name, values in (case.get("sets") or {}).items()}
    return Engine(RULES, sets).replay(events)


@pytest.mark.parametrize("case", [c for _, c in CASES], ids=[n for n, _ in CASES])
def test_rule_case(case: dict[str, Any]) -> None:
    known = {r.id for r in RULES.rules}
    referenced = set(case.get("expect", [])) | set(case.get("expect_not", []))
    assert referenced <= known, f"unknown rule ids: {referenced - known}"

    verdicts = run_case(case)
    hits = {rid for v in verdicts for rid in v.rule_ids}
    missing = set(case.get("expect", [])) - hits
    unexpected = set(case.get("expect_not", [])) & hits
    assert not missing, f"false negative — expected to hit: {sorted(missing)} (hits: {sorted(hits)})"
    assert not unexpected, f"false positive — must not hit: {sorted(unexpected)}"
    for rid, want in (case.get("indicators") or {}).items():
        got = {f.labels.get(INDICATOR) for v in verdicts for f in v.findings if f.rule_id == rid}
        assert got == {want}, f"{rid}: campaign indicator {sorted(map(str, got))}, expected {want!r}"


def test_every_enabled_rule_has_positive_and_negative_case() -> None:
    positive = {rid for _, c in CASES for rid in c.get("expect", [])}
    negative = {rid for _, c in CASES for rid in c.get("expect_not", [])}
    enabled = {r.id for r in RULES.enabled}
    assert not enabled - positive, f"rules without a positive case: {sorted(enabled - positive)}"
    assert not enabled - negative, f"rules without a negative case: {sorted(enabled - negative)}"


def test_bundled_rules_load() -> None:
    assert len(RULES.enabled) >= 20


# ── 가역성·실시간성 등급 (KISA 「에이전틱 AI 제로트러스트 안내서」 표 2-5, 2026-11-13 결정) ──
# 행동(tool.call)을 판정하는 룰은 등급 태그 grade:<0|1|2-1|2-2|3-1|3-2>를 단다. 상태·주체 기준 룰은
# action-independent. 응답은 사용자가 정하고, 등급과 어긋나면 이 시험이 알려 준다(자동으로 바꾸지 않음).
GRADES = {"0", "1", "2-1", "2-2", "3-1", "3-2"}
# 2-x·3-x: 사람의 명시 승인(require_approval·security_approval) 이상.
# 3-1의 사람 승인에는 사후 감사가 붙어야 한다(user-approved-high-risk는 high 이상 승인만 본다).
# 2-2·3-2(실시간, 사전 승인 정책 내 자동 실행)는 아직 쓰지 않는다.
HUMAN_OR_STRICTER = {"require_approval", "security_approval", "block", "abort_session", "quarantine"}


def _kinds(rule: Any) -> set[str]:
    k = rule.when.get("payload.kind") if rule.when else None
    if k is None:  # sequence rules end on a tool.call step
        return {"tool.call"} if getattr(rule.match, "steps", None) else set()
    return set(k) if isinstance(k, (list, tuple)) else {k}


def test_action_rules_carry_a_grade_that_matches_their_response() -> None:
    problems = []
    for r in RULES.rules:
        grades = [t.split(":", 1)[1] for t in r.tags if t.startswith("grade:")]
        if "tool.call" in _kinds(r) and not grades and "action-independent" not in r.tags:
            problems.append(f"{r.id}: tool.call rule without grade:<…> or action-independent")
        for g in grades:
            if g not in GRADES:
                problems.append(f"{r.id}: unknown grade {g}")
            elif g in {"2-1", "3-1"} and r.response.value not in HUMAN_OR_STRICTER:
                problems.append(f"{r.id}: grade {g} needs human approval or stricter, has {r.response.value}")
            elif (
                g == "3-1"
                and r.response.value in {"require_approval"}
                and str(r.severity) not in {"high", "critical"}
            ):
                problems.append(
                    f"{r.id}: 3-1 approved by a person must be audited afterwards (severity high+)"
                )
    assert not problems, "\n".join(problems)
