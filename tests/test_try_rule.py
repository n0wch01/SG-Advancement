"""scripts/try_rule.py: try a command against the rules (hand tuning)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _try():
    spec = importlib.util.spec_from_file_location("sga_try_rule", ROOT / "scripts" / "try_rule.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_a_command_shows_its_rules(capsys) -> None:
    assert _try().main(["rm -rf ~/projects"]) == 0
    out = capsys.readouterr().out
    assert "destructive-shell-command (require_approval)" in out and "REQUIRE_APPROVAL" in out


def test_external_input_before_the_command(capsys) -> None:
    _try().main(["--read-from", "docs.internet-sim", "Cleanup guide", "rm -rf ~/projects"])
    assert "destructive-after-external-input" in capsys.readouterr().out


def test_no_hit_says_it_runs(capsys) -> None:
    _try().main(["--tool", "PowerShell", "Get-ChildItem C:\\lab"])
    assert "no rule hit" in capsys.readouterr().out
