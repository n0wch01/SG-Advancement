"""Regression cases for rules/*.yaml (see docs/detection.md).

Each file in tests/rule_cases/ lists cases: a short event stream plus the rule ids that must
(``expect``) and must not (``expect_not``) hit. Events are written as payload dicts; envelope
fields are filled in. Optional per-event keys: ``at`` (seconds from start), ``session``,
``user``, ``device``. Optional per-case keys: ``agent``, ``sensor``.

When you find a false positive / negative, add it here first, watch it fail, then tune the rule.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml

from agent_sentinel.detect import Engine, RuleSet
from agent_sentinel.schema import AgentEvent

ROOT = Path(__file__).resolve().parents[1]
RULES = RuleSet.load(ROOT / "rules")
CASE_DIR = Path(__file__).parent / "rule_cases"
T0 = datetime(2026, 11, 10, tzinfo=UTC)
_ENVELOPE_KEYS = {"at", "session", "user", "device"}
_DEFAULT_SENSOR = {
    "openclaw": "openclaw_gateway",
    "claude_code": "claude_code_hook",
    "langgraph": "langgraph_callback",
    "gemini_cli": "gemini_cli_hook",
    "codex_cli": "codex_cli_hook",
}


def _load_cases() -> list[tuple[str, dict[str, Any]]]:
    out = []
    for f in sorted(CASE_DIR.glob("*.yaml")):
        for case in yaml.safe_load(f.read_text(encoding="utf-8"))["cases"]:
            out.append((f"{f.stem}: {case['name']}", case))
    return out


CASES = _load_cases()


def build_event(spec: dict[str, Any], case: dict[str, Any], index: int) -> AgentEvent:
    payload = {k: v for k, v in spec.items() if k not in _ENVELOPE_KEYS}
    if payload.get("kind") in ("tool.call", "tool.result"):
        payload.setdefault("call_id", f"call-{index}")
    agent = case.get("agent", "claude_code")
    return AgentEvent.model_validate(
        {
            "ts": T0 + timedelta(seconds=spec.get("at", index * 0.001)),
            "endpoint": {"device_id": spec.get("device", "dev-test")},
            "principal": {"user_id": spec.get("user", "tester")},
            "agent": {"type": agent, "session_id": spec.get("session", "s1")},
            "source": {"sensor": case.get("sensor", _DEFAULT_SENSOR.get(agent, "mcp_proxy"))},
            "payload": payload,
        }
    )


def hit_rule_ids(case: dict[str, Any]) -> set[str]:
    events = [build_event(s, case, i) for i, s in enumerate(case["events"])]
    events.sort(key=lambda e: e.ts)
    return {rid for v in Engine(RULES).replay(events) for rid in v.rule_ids}


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
