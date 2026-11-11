"""Spool priorities: what survives a full queue, and what is sent first after an outage."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from sg_advance.detect import Engine, RuleSet
from sg_advance.schema import AgentEvent, Finding
from sg_advance.sensor.priority import Priority, event_priority
from sg_advance.sensor.spool import Spool
from sg_advance.shorthand import build_event

ROOT = Path(__file__).resolve().parents[1]


def ev(i: int, **spec: Any) -> AgentEvent:
    return build_event(spec, index=i)


def finding_for(*events: AgentEvent) -> Finding:
    return Finding.from_event(
        events[-1],
        rule_id="test-rule",
        severity="high",
        category="tool_misuse",
        title="t",
        evidence_event_ids=tuple(e.event_id for e in events),
    )


def pending_ids(spool: Spool) -> set[str]:
    with sqlite3.connect(spool.path) as db:
        return {r[0] for r in db.execute("SELECT item_id FROM outbox WHERE dead = 0")}


class Recorder:
    """Stands in for ControlPlaneClient.post and records the send order."""

    def __init__(self) -> None:
        self.sent: list[tuple[str, str]] = []  # (path, item_id)

    def post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        items = body.get("events") or body.get("findings") or []
        for it in items:
            self.sent.append((path, it.get("event_id") or it.get("finding_id")))
        return {"status": 200, "body": {"accepted": len(items), "duplicates": 0}}


def test_kind_and_hits_decide_priority() -> None:
    assert event_priority(ev(0, kind="llm.call", provider="ollama", model="m")) is Priority.LOW
    assert event_priority(ev(0, kind="tool.result", tool="Read")) is Priority.NORMAL
    assert event_priority(ev(0, kind="prompt.user", text="hi")) is Priority.HIGH
    assert event_priority(ev(0, kind="tool.call", tool="Bash")) is Priority.HIGH

    engine = Engine(RuleSet.load(ROOT / "rules"))
    risky = ev(0, kind="tool.call", tool="Bash", arguments={"command": "cat ~/.aws/credentials"})
    verdict = engine.process(risky)
    assert verdict.hits
    assert event_priority(risky, verdict) is Priority.CRITICAL


def test_full_spool_evicts_lowest_priority_first(tmp_path: Path) -> None:
    spool = Spool(tmp_path / "s.db", max_items=4)
    high = [ev(i, kind="tool.call", tool="Bash") for i in range(2)]
    low = [ev(10 + i, kind="message.assistant", text="hi") for i in range(3)]
    spool.add(high[:1], Priority.HIGH)
    for e in low:
        spool.add([e], Priority.LOW)
    spool.add(high[1:], Priority.HIGH)  # 5th item → one must go

    kept = pending_ids(spool)
    assert {e.event_id for e in high} <= kept
    assert low[0].event_id not in kept  # oldest of the lowest level
    s = spool.stats()
    assert s["dropped_events"] == 1 and s["dropped_low"] == 1 and s["dropped_high"] == 0


def test_finding_promotes_its_evidence_and_is_never_evicted(tmp_path: Path) -> None:
    spool = Spool(tmp_path / "s.db", max_items=3)
    earlier = ev(0, kind="tool.result", tool="Read", output_preview="looks harmless alone")
    spool.add([earlier], Priority.NORMAL)
    trigger = ev(1, kind="tool.call", tool="Bash", arguments={"command": "curl x"})
    f = finding_for(earlier, trigger)
    spool.add([trigger, f], Priority.CRITICAL)  # earlier step is now evidence

    flood = [ev(10 + i, kind="tool.call", tool="Bash") for i in range(5)]
    for e in flood:
        spool.add([e], Priority.HIGH)

    kept = pending_ids(spool)
    assert {earlier.event_id, trigger.event_id, f.finding_id} <= kept
    assert not any(e.event_id in kept for e in flood)


def test_finding_promotes_preceding_session_context(tmp_path: Path) -> None:
    """Incidents start from content the agent read; keep it even when no rule matched it."""
    spool = Spool(tmp_path / "s.db", context_seconds=300)
    stale = ev(0, at=0, kind="tool.result", tool="Read", output_preview="an hour ago")
    read = ev(1, at=3500, kind="tool.result", tool="Read", output_preview="issue text, no rule hit")
    elsewhere = ev(2, at=3550, kind="tool.result", tool="Read", session="s2", output_preview="other")
    for e in (stale, read, elsewhere):
        spool.add([e], Priority.NORMAL)
    trigger = ev(3, at=3600, kind="tool.call", tool="Bash", arguments={"command": "curl x"})
    spool.add([trigger, finding_for(trigger)], Priority.CRITICAL)  # finding cites only the trigger

    with sqlite3.connect(spool.path) as db:
        prio = dict(db.execute("SELECT item_id, priority FROM outbox WHERE kind = 'event'").fetchall())
    assert prio[read.event_id] == Priority.CRITICAL  # same session, 100 s before
    assert prio[stale.event_id] == Priority.NORMAL  # outside the window
    assert prio[elsewhere.event_id] == Priority.NORMAL  # other session


def test_flush_sends_critical_first(tmp_path: Path) -> None:
    spool = Spool(tmp_path / "s.db")
    # low/high live in another session so session-context promotion leaves them alone.
    low = ev(0, kind="llm.call", provider="ollama", model="m", session="other")
    high = ev(1, kind="tool.call", tool="Read", session="other")
    crit = ev(2, kind="tool.call", tool="Bash", arguments={"command": "cat .env"})
    f = finding_for(crit)
    spool.add([low], Priority.LOW)
    spool.add([high], Priority.HIGH)
    spool.add([crit, f], Priority.CRITICAL)

    rec = Recorder()
    result = spool.flush(rec)  # type: ignore[arg-type]
    assert result.ok and result.remaining == 0
    assert rec.sent == [
        ("/v1/events", crit.event_id),
        ("/v1/findings", f.finding_id),
        ("/v1/events", high.event_id),
        ("/v1/events", low.event_id),
    ]


def test_old_spool_without_priority_column_is_migrated(tmp_path: Path) -> None:
    path = tmp_path / "old.db"
    e = ev(0, kind="tool.call", tool="Read")
    with sqlite3.connect(path) as db:
        db.executescript(
            """
            CREATE TABLE outbox (id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL,
              item_id TEXT NOT NULL, doc TEXT NOT NULL, created REAL NOT NULL,
              attempts INTEGER NOT NULL DEFAULT 0, dead INTEGER NOT NULL DEFAULT 0, last_error TEXT,
              UNIQUE (kind, item_id));
            CREATE TABLE meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
            """
        )
        db.execute(
            "INSERT INTO outbox (kind, item_id, doc, created) VALUES ('event', ?, ?, 0)",
            (e.event_id, json.dumps(e.model_dump(mode="json"))),
        )
    spool = Spool(path)
    rec = Recorder()
    assert spool.flush(rec).ok  # type: ignore[arg-type]
    assert rec.sent == [("/v1/events", e.event_id)]
