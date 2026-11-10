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
