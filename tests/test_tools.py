"""Tool kinds live in sg_advance.sensor.tools; the lists that cannot import it are held to it here."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from sg_advance.sensor import delegation, downloads, hook, lineage, tools

ROOT = Path(__file__).resolve().parents[1]


def _rule(rule_id: str) -> dict:
    for f in (ROOT / "rules").glob("*.yaml"):
        for r in yaml.safe_load(f.read_text(encoding="utf-8"))["rules"]:
            if r["id"] == rule_id:
                return r
    raise KeyError(rule_id)


def test_modules_use_the_shared_sets_unchanged() -> None:
    """The refactor kept every decision as it was: the same sets as the old copies."""
    assert {"Read", "Glob", "Grep", "LS", "NotebookRead", "TodoRead", "TodoWrite"} == hook.READ_ONLY_TOOLS
    assert hook.READ_ONLY_TOOLS | {"read"} == lineage.LOCAL_TOOLS
    assert hook.READ_ONLY_TOOLS | {"WebFetch", "WebSearch"} == delegation.READ_ONLY
    assert downloads.SHELL_TOOLS is tools.SHELL is lineage.SHELL_TOOLS


def test_the_openclaw_plugin_keeps_the_same_read_only_list() -> None:
    src = (ROOT / "integrations/openclaw-plugin/policy.ts").read_text(encoding="utf-8")
    m = re.search(r"DEFAULT_READ_ONLY = \[([^\]]*)\]", src)
    assert m is not None
    assert set(re.findall(r'"([^"]+)"', m.group(1))) == tools.OPENCLAW_READ_ONLY


def test_the_subagent_rule_skips_read_only_tools_of_both_agents() -> None:
    """subagent-above-parent-permission asks only about changing actions: its skip list must cover the
    read-only tools (a tool missing from it would be asked about needlessly)."""
    skipped = set(_rule("subagent-above-parent-permission")["unless"]["payload.tool"])
    assert tools.CLAUDE_READ_ONLY | {"WebSearch"} <= skipped
    assert {"read", "web_search", "memory_search"} <= skipped
    assert not (skipped & (tools.SHELL | tools.FILE_WRITE))  # never skips a changing tool
