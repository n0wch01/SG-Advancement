"""``match: {type: number}`` (2026-11-16): numeric thresholds in the signed policy instead of in code."""

from __future__ import annotations

import pytest
import yaml
from pydantic import ValidationError

from sg_advance.detect import Engine, RuleSet
from sg_advance.detect.rules import Rule
from sg_advance.shorthand import build_event


def engine(match: str) -> Engine:
    return Engine(RuleSet([Rule.model_validate(yaml.safe_load(f"""
id: n
severity: medium
category: other
title: n
when: {{payload.kind: tool.result}}
match: {match}
"""))]))


def hits(e: Engine, labels: dict[str, str]) -> list[str]:
    ev = build_event({"kind": "tool.result", "tool": "X", "output_preview": "x", "labels": labels})
    return [h.explanation for h in e.process(ev).hits]


def test_a_label_read_as_a_number_against_the_bounds() -> None:
    e = engine("{type: number, fields: [labels.sga_judge_score], at_least: 0.85}")
    assert hits(e, {"sga_judge_score": "0.970"}) == ["labels.sga_judge_score = 0.970 (≥ 0.85)"]
    assert hits(e, {"sga_judge_score": "0.850"}) != []  # at_least includes the bound
    assert hits(e, {"sga_judge_score": "0.849"}) == []


def test_a_band_with_two_bounds() -> None:
    e = engine("{type: number, fields: [labels.sga_judge_score], at_least: 0.5, below: 0.85}")
    got = [bool(hits(e, {"sga_judge_score": s})) for s in ("0.49", "0.5", "0.7", "0.85")]
    assert got == [False, True, True, False]


def test_missing_or_non_numeric_values_never_match() -> None:
    e = engine("{type: number, fields: [labels.sga_judge_score], above: 0}")
    for labels in ({}, {"sga_judge_score": "high"}, {"sga_judge_score": "nan"}):
        assert hits(e, labels) == []


def test_a_number_match_needs_a_bound() -> None:
    with pytest.raises(ValidationError, match="at least one of"):
        engine("{type: number, fields: [labels.sga_judge_score]}")
