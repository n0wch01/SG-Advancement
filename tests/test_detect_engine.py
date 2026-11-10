from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from agent_sentinel.detect import Engine, Rule, RuleLoadError, RuleSet
from agent_sentinel.detect.fields import resolve
from agent_sentinel.schema import AgentEvent, ResponseAction

T0 = datetime(2026, 11, 10, tzinfo=UTC)


def ev(payload: dict, *, at: float = 0, session: str = "s1", sensor: str = "claude_code_hook") -> AgentEvent:
    if payload.get("kind") in ("tool.call", "tool.result"):
        payload = {"call_id": "c", **payload}
    return AgentEvent.model_validate(
        {
            "ts": T0 + timedelta(seconds=at),
            "endpoint": {"device_id": "d1"},
            "principal": {"user_id": "u1"},
            "agent": {"type": "claude_code", "session_id": session},
            "source": {"sensor": sensor},
            "payload": payload,
        }
    )


def rule(**kw) -> Rule:
    base = {"id": "r", "severity": "high", "category": "other", "title": "t"}
    return Rule.model_validate(base | kw)


def bash(cmd: str, **kw) -> AgentEvent:
    return ev({"kind": "tool.call", "tool": "Bash", "arguments": {"command": cmd}}, **kw)


def test_resolve_fans_out_over_lists() -> None:
    doc = {"payload": {"tools": [{"p": {"u": "a"}}, {"p": {}}, {"p": {"u": "b"}}]}}
    assert resolve(doc, "payload.tools[].p.u") == ["a", "b"]
    assert resolve(doc, "payload.missing") == []


def test_when_filter_and_regex_on_nested_list_args() -> None:
    r = rule(
        when={"payload.kind": "tool.call"},
        match={"type": "regex", "pattern": "rm -rf", "fields": ["payload.arguments"]},
    )
    eng = Engine(RuleSet([r]))
    assert eng.process(
        ev({"kind": "tool.call", "tool": "shell", "arguments": {"cmd": ["bash", "rm -rf /"]}})
    ).hits
    assert not eng.process(ev({"kind": "prompt.user", "text": "rm -rf"})).hits


def test_explanation_marks_match_and_is_redacted() -> None:
    r = rule(match={"type": "regex", "pattern": "cat", "fields": ["payload.arguments"]})
    v = Engine(RuleSet([r])).process(bash("cat x && export TOKEN=abcd1234secret"))
    assert "«cat»" in v.hits[0].explanation
    assert "abcd1234secret" not in v.findings[0].explanation


def test_dedup_reports_once_but_verdict_applies_every_time() -> None:
    r = rule(response="block", match={"type": "regex", "pattern": r"\.env"})
    eng = Engine(RuleSet([r]))
    v1, v2 = eng.process(bash("cat .env")), eng.process(bash("cat .env"))
    assert v1.action is v2.action is ResponseAction.BLOCK
    assert len(v1.findings) == 1 and not v2.findings
    assert not v2.hits[0].reported


def test_dedup_none_reports_every_time_and_dedup_is_per_session() -> None:
    eng = Engine(RuleSet([rule(dedup="none", match={"type": "regex", "pattern": "x"})]))
    assert eng.process(bash("x")).findings and eng.process(bash("x")).findings
    eng = Engine(RuleSet([rule(match={"type": "regex", "pattern": "x"})]))
    assert eng.process(bash("x", session="a")).findings
    assert eng.process(bash("x", session="b")).findings


def test_session_end_resets_dedup() -> None:
    eng = Engine(RuleSet([rule(match={"type": "regex", "pattern": "x"})]))
    assert eng.process(bash("x")).findings
    eng.process(ev({"kind": "session.end"}))
    assert eng.process(bash("x")).findings


def test_verdict_takes_strongest_response() -> None:
    rules = [
        rule(id="a", response="alert", match={"type": "regex", "pattern": "x"}),
        rule(id="b", response="abort_session", match={"type": "regex", "pattern": "x"}),
    ]
    assert Engine(RuleSet(rules)).process(bash("x")).action is ResponseAction.ABORT_SESSION
    assert Engine(RuleSet(rules)).process(bash("y")).action is ResponseAction.ALLOW


def test_allowlist_glob_case_insensitive_and_key_per_value() -> None:
    r = rule(match={"type": "allowlist", "field": "payload.host", "allow": ["*.corp"]})
    eng = Engine(RuleSet([r]))

    def egress(host: str) -> AgentEvent:
        return ev({"kind": "net.egress", "url": f"http://{host}/", "host": host}, sensor="egress_proxy")

    assert not eng.process(egress("WIKI.corp")).hits
    assert eng.process(egress("evil.example")).findings
    assert eng.process(egress("other.example")).findings  # different value → new finding


def test_rate_window_slides_and_evidence_lists_window() -> None:
    r = rule(match={"type": "rate", "window_seconds": 10, "threshold": 3})
    eng = Engine(RuleSet([r]))
    vs = [eng.process(bash(f"q{i}", at=t)) for i, t in enumerate([0, 4, 11, 12])]
    assert [bool(v.hits) for v in vs] == [False, False, False, True]
    assert len(vs[3].hits[0].evidence_event_ids) == 3


def test_rate_groups_by_tool() -> None:
    r = rule(match={"type": "rate", "window_seconds": 10, "threshold": 2})
    eng = Engine(RuleSet([r]))
    eng.process(bash("a"))
    assert not eng.process(ev({"kind": "tool.call", "tool": "Read", "arguments": {}})).hits


def test_sequence_requires_order_session_and_window() -> None:
    r = rule(
        match={
            "type": "sequence",
            "within_seconds": 60,
            "steps": [
                {
                    "when": {"payload.kind": "tool.result"},
                    "pattern": "INJECT",
                    "fields": ["payload.output_preview"],
                },
                {"when": {"payload.kind": "tool.call"}, "pattern": "curl"},
            ],
        }
    )
    res = ev({"kind": "tool.result", "tool": "Read", "output_preview": "INJECT"})

    eng = Engine(RuleSet([r]))
    eng.process(res)
    v = eng.process(bash("curl x", at=5))
    assert v.hits and len(v.hits[0].evidence_event_ids) == 2

    eng = Engine(RuleSet([r]))
    eng.process(res)
    assert not eng.process(bash("curl x", at=61)).hits


def test_disabled_rules_are_skipped() -> None:
    r = rule(enabled=False, match={"type": "regex", "pattern": "x"})
    assert not Engine(RuleSet([r])).process(bash("x")).hits


def test_finding_carries_rule_metadata_unenforced() -> None:
    r = rule(
        category="tool_misuse",
        response="block",
        tags=["owasp-llm:LLM06"],
        match={"type": "regex", "pattern": "x"},
    )
    f = Engine(RuleSet([r])).process(bash("x")).findings[0]
    assert f.category.value == "tool_misuse" and f.tags == ("owasp-llm:LLM06",)
    assert f.response is not None and f.response.action is ResponseAction.BLOCK and not f.response.enforced
    assert f.principal.user_id == "u1"


@pytest.mark.parametrize(
    "bad",
    [
        {"match": {"type": "regex", "pattern": "("}},
        {"match": {"type": "nope"}},
        {"match": {"type": "rate", "window_seconds": 0, "threshold": 1}},
        {"match": {"type": "regex", "pattern": "x"}, "severity": "huge"},
        {"match": {"type": "regex", "pattern": "x"}, "typo_field": 1},
    ],
)
def test_invalid_rules_are_rejected(bad: dict) -> None:
    with pytest.raises(ValueError):
        rule(**bad)


def test_duplicate_ids_rejected(tmp_path: Path) -> None:
    body = (
        "version: 1\nrules:\n"
        "  - {id: dup, severity: low, category: other, title: t, match: {type: regex, pattern: x}}\n"
    )
    (tmp_path / "a.yaml").write_text(body)
    (tmp_path / "b.yaml").write_text(body)
    with pytest.raises(RuleLoadError, match="duplicate"):
        RuleSet.load(tmp_path)


def test_bundled_rules_load() -> None:
    rs = RuleSet.load(Path(__file__).resolve().parents[1] / "rules")
    assert len(rs.enabled) >= 20
