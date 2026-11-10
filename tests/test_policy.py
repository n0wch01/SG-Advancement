"""Policy bundle v0: rules/ → bundle → sensor-side RuleSet round trip."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from agent_sentinel.detect import Engine, RuleSet
from agent_sentinel.detect.cli import load_events
from agent_sentinel.policy import PolicyBundle

ROOT = Path(__file__).resolve().parents[1]


def test_bundle_round_trip_detects_the_same() -> None:
    original = RuleSet.load(ROOT / "rules")
    bundle = PolicyBundle.from_ruleset(original)
    rebuilt = PolicyBundle.model_validate_json(bundle.model_dump_json()).to_ruleset()

    assert [r.id for r in rebuilt.rules] == [r.id for r in original.rules]
    events = load_events(sorted((ROOT / "examples" / "events").glob("*.jsonl")))
    want = [v.rule_ids for v in Engine(original).replay(events)]
    got = [v.rule_ids for v in Engine(rebuilt).replay(events)]
    assert got == want
    assert any(want)


def test_version_is_stable_and_tracks_content(tmp_path: Path) -> None:
    rules = tmp_path / "rules"
    shutil.copytree(ROOT / "rules", rules)
    v1 = PolicyBundle.load(rules).version
    assert PolicyBundle.load(rules).version == v1

    f = rules / "tool_misuse.yaml"
    text = f.read_text(encoding="utf-8")
    assert "severity: high" in text
    f.write_text(text.replace("severity: high", "severity: critical", 1), "utf-8")
    assert PolicyBundle.load(rules).version != v1


def test_tampered_bundle_is_rejected() -> None:
    bundle = PolicyBundle.load(ROOT / "rules")
    doc = bundle.model_dump(mode="json")
    doc["rules"][0]["enabled"] = not doc["rules"][0].get("enabled", True)
    with pytest.raises(ValueError, match="hash mismatch"):
        PolicyBundle.model_validate(doc).to_ruleset()
