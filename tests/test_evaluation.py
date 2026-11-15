"""The evaluation (scripts/evaluate.py, eval/corpus.yaml) as a regression: every attack and evasion is
handled as the design says at every point, and no normal work is stopped."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _evaluate():
    spec = importlib.util.spec_from_file_location("sga_evaluate", ROOT / "scripts" / "evaluate.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look their module up
    spec.loader.exec_module(module)
    return module


def test_the_evaluation_matches_the_design() -> None:
    ev = _evaluate()
    results = ev.run()
    assert ev.mismatches(results) == []
    assert len(results["attacks"]) >= 15 and len(results["benign"]) >= 40
    assert "## 지점별 탐지율" in ev.markdown(results)


# Known Windows gaps (2026-11-15, docs/windows-test.md step 1), waiting for the user's decision on the rules.
# W10 (download tracking) closed the same day: PowerShell is a shell tool (sensor/tools.py).
# When one is fixed, remove it here: the evaluation must then match the design for it too.
WINDOWS_GAPS = [
    "W04 claude_code: allow (기대 block)",  # credential paths with backslashes (.aws\credentials)
    "W04 openclaw: allow (기대 block)",
]


def test_the_windows_evaluation_has_only_the_known_gaps() -> None:
    ev = _evaluate()
    results = ev.run(ev.WINDOWS_CORPUS)
    assert ev.mismatches(results) == WINDOWS_GAPS
    assert len(results["attacks"]) >= 14 and len(results["benign"]) >= 20
