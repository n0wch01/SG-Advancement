"""examples/events (per-sensor fixtures) replayed through the bundled rules, plus the CLI."""

from __future__ import annotations

from pathlib import Path

import pytest

from sg_advance.detect import Engine, RuleSet
from sg_advance.detect.cli import load_events, main
from sg_advance.schema import ResponseAction

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples" / "events"


def replay(name: str):
    return Engine(RuleSet.load(ROOT / "rules")).replay(load_events([EXAMPLES / name]))


def hit_ids(name: str) -> set[str]:
    return {rid for v in replay(name) for rid in v.rule_ids}


def test_s1_malicious_plugin_openclaw() -> None:
    hits = hit_ids("openclaw.jsonl")
    assert {"unapproved-plugin-installed", "unapproved-plugin-tool-call", "egress-unapproved-host"} <= hits


def test_s2_readme_injection_claude_code_is_blocked_at_tool_call() -> None:
    verdicts = replay("claude_code.jsonl")
    exfil = verdicts[-1]
    assert exfil.event.kind.value == "tool.call"
    assert "injection-then-sensitive-action" in exfil.rule_ids
    assert exfil.action is ResponseAction.BLOCK


def test_s2_variants_on_other_sensors() -> None:
    assert {"mcp-tool-description-poisoning", "secret-in-tool-arguments"} <= hit_ids("mcp_proxy.jsonl")
    assert "sensitive-file-access" in hit_ids("gemini_cli.jsonl")
    assert "destructive-shell-command" in hit_ids("codex_cli.jsonl")


def test_s3_exhaustion_prompt_langgraph() -> None:
    assert "exhaustion-keyword-prompt" in hit_ids("langgraph.jsonl")


def test_benign_events_are_allowed() -> None:
    verdicts = replay("claude_code.jsonl")
    assert verdicts[0].action is ResponseAction.ALLOW  # session.start
    assert verdicts[1].action is ResponseAction.ALLOW  # Read README.md


@pytest.mark.parametrize("extra", [[], ["--json"]])
def test_cli_runs(capsys: pytest.CaptureFixture[str], extra: list[str]) -> None:
    files = [str(p) for p in sorted(EXAMPLES.glob("*.jsonl"))]
    assert main([*files, "--rules", str(ROOT / "rules"), *extra]) == 0
    out = capsys.readouterr().out
    assert "injection-then-sensitive-action" in out


def test_t18_injection_read_by_a_sub_agent_then_acted_on_by_its_parent() -> None:
    """Team gateway: the sub-agent read the poisoned page, the delegating agent ran the exfil."""
    verdicts = replay("openclaw_team.jsonl")
    exfil = verdicts[-1]
    assert exfil.event.agent.session_id != verdicts[-2].event.agent.session_id
    assert "cross-agent-injection-propagation" in exfil.rule_ids
    assert "injection-then-sensitive-action" not in exfil.rule_ids  # not one session
    assert exfil.action is ResponseAction.BLOCK


def test_shadow_openclaw_install_on_an_employee_pc() -> None:
    verdicts = replay("openclaw_shadow.jsonl")
    carol, alice = (set(v.rule_ids) for v in verdicts)
    assert carol == {"openclaw-unmanaged-install", "openclaw-gateway-network-exposed"}
    assert alice == set()
