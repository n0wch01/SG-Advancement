"""Standing state findings (rule tuning, 2026-11-15): a snapshot describes a state, not an action.

Production showed ~450 of 695 findings were the same unchanged state reported again after each sensor
restart (agent permission "full", unapproved plugins, sandbox off, unmanaged installs). The engine's
dedup lives in memory, so a restart forgot it. Now a snapshot finding that was not enforced is
recorded once per device/subject/state per 24 hours, across restarts; when the state clears it is
forgotten, so it alerts again as soon as it comes back. Enforced records are never suppressed."""

from __future__ import annotations

import json
import sqlite3
from datetime import timedelta
from typing import Any

from sg_advance.schema import Enforcement, ResponseAction
from sg_advance.sensor import Sensor, core
from sg_advance.sensor.adapters import AdapterContext
from sg_advance.shorthand import build_event

FULL = {"kind": "inventory.snapshot", "agent_id": "main", "permission_mode": "full"}
SAFE = {"kind": "inventory.snapshot", "agent_id": "main", "permission_mode": "workspace"}


def findings(sensor: Sensor, rule: str = "openclaw-agent-permission-full") -> list[dict[str, Any]]:
    with sqlite3.connect(sensor.spool.path) as db:
        rows = db.execute("SELECT doc FROM outbox WHERE kind = 'finding' ORDER BY rowid")
        return [d for (doc,) in rows if (d := json.loads(doc))["rule_id"] == rule]


def inventory(spec: dict[str, Any], n: int) -> Any:
    event = build_event(spec, defaults={"agent": "openclaw", "sensor": "openclaw_gateway"}, index=n)
    agent = event.agent.model_copy(update={"session_id": "inventory:main"})  # the WS adapter's subject
    return event.model_copy(update={"agent": agent})


def snapshot(sensor: Sensor, spec: dict[str, Any], n: int = 0) -> None:
    ctx = AdapterContext(sensor, "team-gateway", "gw")
    ctx.record(ctx.evaluate(inventory(spec, n)))


def restarted(sensor: Sensor, transport: Any) -> Sensor:
    """A new sensor process on the same home (daemon restart, deploy): a fresh engine."""
    fresh = Sensor(sensor.home, transport=transport)
    assert fresh.load_cached_policy()
    return fresh


def test_the_same_state_is_not_reported_again_after_a_restart(
    enrolled: Sensor, cp_transport: Any
) -> None:
    snapshot(enrolled, FULL)
    assert len(findings(enrolled)) == 1
    again = restarted(enrolled, cp_transport)
    snapshot(again, FULL, 1)
    assert len(findings(again)) == 1  # before: one more finding per restart


def test_a_cleared_state_alerts_again_when_it_returns(enrolled: Sensor, cp_transport: Any) -> None:
    snapshot(enrolled, FULL)
    snapshot(enrolled, SAFE, 1)  # lowered: the state cleared
    again = restarted(enrolled, cp_transport)
    snapshot(again, FULL, 2)  # raised again: a change, reported at once
    assert len(findings(again)) == 2


def test_a_standing_state_is_reported_again_after_a_day(
    enrolled: Sensor, cp_transport: Any, monkeypatch
) -> None:
    snapshot(enrolled, FULL)
    later = core.now_utc() + timedelta(hours=25)
    monkeypatch.setattr(core, "now_utc", lambda: later)
    snapshot(restarted(enrolled, cp_transport), FULL, 1)
    assert len(findings(enrolled)) == 2


def test_an_enforced_snapshot_finding_is_always_recorded(enrolled: Sensor, cp_transport: Any) -> None:
    snapshot(enrolled, FULL)
    again = restarted(enrolled, cp_transport)
    ctx = AdapterContext(again, "team-gateway", "gw")
    event = inventory(FULL, 1)
    done = Enforcement(action=ResponseAction.QUARANTINE, enforced=True, enforcer="openclaw_gateway",
                       detail="agent permission lowered", stage="quarantined")  # fmt: skip
    ctx.record(ctx.evaluate(event), done)
    assert [f["response"]["enforced"] for f in findings(again)] == [False, True]


def test_actions_are_untouched(enrolled: Sensor) -> None:
    """Only snapshots: tool calls keep the engine's per-session rule (and enforced repeats)."""
    ctx = AdapterContext(enrolled, "bob", "pc")
    for n in range(2):
        ev = build_event({"kind": "tool.call", "tool": "Bash", "arguments": {"command": "rm -rf ~/x"}},
                         defaults={"agent": "claude_code"}, index=n)  # fmt: skip
        ev = ev.model_copy(update={"agent": ev.agent.model_copy(update={"session_id": f"s{n}"})})
        ctx.record(ctx.evaluate(ev))
    assert len(findings(enrolled, "destructive-shell-command")) == 2
