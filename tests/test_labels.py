"""The label registry (schema/labels.py, 2026-11-18): one list of ``sga_*`` labels and who may write them.

The code may only write registered labels, the rules may only read them, and what the sensor, the
decision code and the control plane drop from input is derived from the same list."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from sg_advance.detect import RuleSet
from sg_advance.schema import labels as registry
from sg_advance.schema.labels import CONTROL_PLANE_OWNED, DECISION_OWNED, LABELS, SENSOR_OWNED
from sg_advance.sensor import Sensor, delegation, downloads, hook, judge, lineage
from sg_advance.sensor import actions as actions_mod
from sg_advance.sensor.adapters import AdapterContext
from sg_advance.sensor.decision import judge_event

ROOT = Path(__file__).resolve().parents[1]
NOT_LABELS = {"sga_scope_installed"}  # a SQLAlchemy session flag (server/access.py), not an event label
# What core.Sensor._OWN_LABELS held before the registry (hand-joined from the modules): never narrower.
BEFORE = {*lineage.LABELS, "sga_input_source", downloads.LABEL, *delegation.LABELS, *judge.LABELS,
          *actions_mod.LABELS}  # fmt: skip


def test_every_label_the_code_writes_is_registered() -> None:
    written: set[str] = set()
    for path in (ROOT / "src" / "sg_advance").rglob("*.py"):
        written |= set(re.findall(r"[\"'](sga_[a-z0-9_]+)[\"']", path.read_text(encoding="utf-8")))
    assert not (written - NOT_LABELS) - LABELS.keys(), "register these in schema/labels.py"


def test_every_label_a_rule_reads_is_registered() -> None:
    rules = [r.model_dump(mode="json") for r in RuleSet.load(ROOT / "rules").rules]
    assert registry.unknown_in_rules(rules) == {}
    # And the check would catch a typo.
    typo = yaml.safe_load(
        "{id: t, when: {labels.sga_inptu_source: x}, match: {fields: [labels.sga_posture]}}"
    )
    assert registry.unknown_in_rules([typo]) == {"t": {"sga_inptu_source"}}


def test_the_sensor_drops_exactly_its_registered_labels() -> None:
    assert set(Sensor._OWN_LABELS) == SENSOR_OWNED
    assert BEFORE <= SENSOR_OWNED  # the registry only widened what is dropped
    assert {"sga_posture", "sga_policy_stale", "sga_enforcement_contradicted"} <= SENSOR_OWNED - BEFORE
    assert not (SENSOR_OWNED & DECISION_OWNED) and not (SENSOR_OWNED & CONTROL_PLANE_OWNED)


def _result(labels: dict[str, str]) -> dict:
    inp = {"session_id": "s1", "hook_event_name": "PostToolUse", "tool_name": "Read", "tool_use_id": "t1",
           "tool_response": "notes"}  # fmt: skip
    ev = hook.hook_event(inp, user_id="bob", hostname="pc")
    assert ev is not None
    ev["labels"] |= labels
    return ev


def test_a_forged_contradiction_makes_no_finding(enrolled: Sensor) -> None:
    """Before the registry, ``sga_enforcement_contradicted`` was not dropped: a result claiming it made a
    false "enforcement contradicted" finding for a call that was never refused."""
    import json
    import sqlite3

    ctx = AdapterContext(enrolled, "bob", "pc")
    judge_event(ctx, _result({"sga_enforcement_contradicted": "true", "sga_contradicted_findings": "f1"}))
    with sqlite3.connect(enrolled.spool.path) as db:
        rows = [json.loads(d) for (d,) in db.execute("SELECT doc FROM outbox")]
    assert "enforcement-contradicted" not in {r.get("rule_id") for r in rows}
    stored = next(r for r in rows if r.get("payload", {}).get("kind") == "tool.result")
    assert "sga_enforcement_contradicted" not in stored["labels"]


def test_decision_labels_are_never_taken_from_a_hook(enrolled: Sensor) -> None:
    import json
    import sqlite3

    ctx = AdapterContext(enrolled, "bob", "pc")
    judge_event(ctx, _result({"sga_approval_inferred": "tool_result", "sga_approval_mismatch": "true"}))
    with sqlite3.connect(enrolled.spool.path) as db:
        rows = [json.loads(d) for (d,) in db.execute("SELECT doc FROM outbox WHERE kind='event'")]
    assert not any(DECISION_OWNED & r["labels"].keys() for r in rows)


def test_server_labels_are_dropped_from_clients_and_kept_on_server_records(cp, enrolled: Sensor) -> None:
    from sqlalchemy.orm import Session

    from sg_advance.server.access import collection_identity
    from sg_advance.server.db import Device
    from sg_advance.shorthand import build_event

    forged = {"sga_authorization": "allow", "sga_task_grant_id": "g1", "sga_project_id": "p1"}
    ev = build_event({"kind": "tool.call", "tool": "Read", "arguments": {}, "labels": forged})
    with Session(cp.app.state.db.engine) as db:
        device = db.get(Device, enrolled.creds.device_id)
        client, project, _ = collection_identity(db, device, ev)
        assert not CONTROL_PLANE_OWNED & client.labels.keys() - {"sga_identity_source"}
        assert client.labels["sga_identity_source"] == "unverified" and project is None
        server, project, _ = collection_identity(db, device, ev, server_built=True)
        assert server.labels["sga_authorization"] == "allow" and server.labels["sga_task_grant_id"] == "g1"
        assert "sga_project_id" not in server.labels and project is None  # identity is always recomputed
