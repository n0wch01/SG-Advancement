"""Every scenario under demo/scenarios must PASS against the bundled rules."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import demo_runner as dr

SCENARIOS = dr.load_all()
ROOT = dr.DEMO_DIR.parent


@pytest.mark.parametrize("sc", SCENARIOS, ids=[s.id for s in SCENARIOS])
def test_scenario_passes(sc: dr.Scenario) -> None:
    results = dr.run(sc, dr.RuleSet.load(dr.RULES_DIR))
    problems = [f"step {i}: {p}" for i, r in enumerate(results, 1) for p in r.problems]
    assert not problems, "\n".join(problems)


def test_scenario_ids_unique() -> None:
    ids = [s.id for s in SCENARIOS]
    assert len(ids) == len(set(ids))


def test_cli_lists_and_runs(capsys: pytest.CaptureFixture[str]) -> None:
    assert dr.main(["--list"]) == 0
    assert dr.main(["all", "--pause", "0", "--no-color"]) == 0
    assert "PASS" in capsys.readouterr().out


def test_core_does_not_depend_on_demo() -> None:
    """Keeps `rm -rf demo/` a complete removal."""
    pattern = re.compile(r"\bdemo_runner\b|\bdemo/")
    offenders = [
        str(p.relative_to(ROOT))
        for d in ("src", "tests", "scripts")
        for p in Path(ROOT, d).rglob("*.py")
        if pattern.search(p.read_text(encoding="utf-8"))
    ]
    assert not offenders, f"core files reference demo/: {offenders}"


def test_live_story_is_valid_and_its_steps_hit_what_docs_demo_md_says() -> None:
    """docs/demo.md promises these verdicts. Steps 2-4 need the sensor's lineage labels (checked by
    hand there, and by tests/test_lineage.py); the engine alone covers the rest."""
    import live_story
    from sg_advance.detect import Engine, RuleSet
    from sg_advance.schema import AgentEvent

    events = [AgentEvent.model_validate(d) for d in live_story.story()]
    verdicts = Engine(RuleSet.load(ROOT / "rules")).replay(events)
    by_step = {(v.event.agent.session_id, getattr(v.event.payload, "call_id", "")): v for v in verdicts}
    hits = lambda call: set(by_step[call].rule_ids)  # noqa: E731
    assert "vigil-instruction-bypass" in {r for v in verdicts for r in v.rule_ids}  # step 5
    assert "injection-then-destructive-action" in hits(("demo-bob-1", "demo-bob-1-t6"))
    assert "known-malicious-package-run" in hits(("demo-bob-1", "demo-bob-1-t7"))
    assert "known-malicious-domain" in hits(("demo-bob-1", "demo-bob-1-t8"))
    alice = by_step[("demo-alice-1", "demo-alice-1-t1")]
    assert alice.action.value == "require_approval" and "destructive-shell-command" in alice.rule_ids
