"""Lists that several rules must share (refactor 2026-11-15). Rule options cannot reference a shared
list (old sensors refuse unknown fields), so the copies are held together here instead of by a comment."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _rules() -> dict[str, dict]:
    out: dict[str, dict] = {}
    for f in (ROOT / "rules").glob("*.yaml"):
        for r in yaml.safe_load(f.read_text(encoding="utf-8"))["rules"]:
            out[r["id"]] = r
    return out


RULES = _rules()


def test_approved_destinations_match_between_the_lineage_sink_rules() -> None:
    """Same approved destinations, with one intended difference: when the lineage record cannot be read,
    a destination the call does not show ("unknown") is blocked too (fail closed, docs/lineage.md)."""
    linked = set(RULES["protected-data-to-unapproved-destination"]["match"]["allow"])
    unreadable = set(RULES["transfer-with-lineage-unavailable"]["match"]["allow"])
    assert unreadable == linked - {"unknown"}


def _alternatives(pattern: str, after: str) -> set[str]:
    """The ``(?:a|b|c)`` group that directly follows ``after`` in a regex, as plain names."""
    i = pattern.index(after) + len(after)
    assert pattern[i : i + 3] == "(?:", f"no group after {after!r}"
    j = pattern.index(")", i)
    return {a.replace("\\.", ".") for a in pattern[i + 3 : j].split("|")}


def test_threat_intel_lists_are_the_same_in_every_rule() -> None:
    server = RULES["known-malicious-mcp-server"]["match"]["pattern"]
    run = RULES["known-malicious-package-run"]["match"]["pattern"]
    domain = RULES["known-malicious-domain"]["match"]["pattern"]
    packages_in_config = _alternatives(server, "^(?:")
    packages_run = _alternatives(run, "(?<![\\w@/.-])")
    domains_in_config = _alternatives(server, "https?://(?:[\\w-]+\\.)*")
    domains_called = _alternatives(domain, "(?<![\\w.-])(?:[\\w-]+\\.)*")
    assert packages_in_config == packages_run, "rules/threat_intel.yaml: package lists differ"
    assert domains_in_config == domains_called, "rules/threat_intel.yaml: domain lists differ"
    assert packages_run and domains_called
    for name in packages_run | domains_called:  # plain names only, no regex slipped into a list
        assert re.fullmatch(r"[\w.@/-]+", name), name
