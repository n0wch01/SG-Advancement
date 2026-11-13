"""Tamper-evident audit chain (2026-11-13, KISA ZT guide C1-6; 금융보안원 ⑰)."""

from __future__ import annotations

from sqlalchemy import delete, update

from conftest import CP_ADMIN
from sg_advance.sensor import Sensor
from sg_advance.server.db import AuditEntry, FindingRow
from sg_advance.shorthand import build_event


def _seed(enrolled: Sensor, cp) -> None:
    enrolled.process(
        build_event({"kind": "tool.call", "tool": "exec", "arguments": {"command": "rm -rf /srv"}})
    )
    enrolled.process(
        build_event({"kind": "tool.call", "tool": "exec", "arguments": {"command": "cat ~/.ssh/id_rsa"}})
    )
    enrolled.flush()
    r = cp.post("/v1/admin/actions", headers=CP_ADMIN,
                json={"device_id": "dev-alice", "action": "block_user", "target": "alice",
                      "by": "soc", "reason": "test"})  # fmt: skip
    assert r.status_code == 201


def _verify(cp, **q) -> dict:
    return cp.get("/v1/admin/audit/chain/verify", headers=CP_ADMIN, params=q).json()


def _db(cp):
    return cp.app.state.db._sessions()


def test_records_are_chained_and_verify(enrolled: Sensor, cp) -> None:
    _seed(enrolled, cp)
    v = _verify(cp)
    assert v["ok"] and v["entries"] >= 3 and v["problems"] == []
    with _db(cp) as db:
        kinds = {e.kind for e in db.query(AuditEntry)}
    assert {"finding", "remote_action"} <= kinds
    head = cp.get("/v1/admin/audit/chain", headers=CP_ADMIN).json()
    assert head["head"] == v["head"] and head["entries"] == v["entries"]


def test_changing_a_finding_is_detected(enrolled: Sensor, cp) -> None:
    _seed(enrolled, cp)
    with _db(cp) as db:
        row = db.query(FindingRow).first()
        doc = dict(row.doc) | {"severity": "low"}  # someone softens a finding
        db.execute(update(FindingRow).where(FindingRow.finding_id == row.finding_id).values(doc=doc))
        db.commit()
    v = _verify(cp)
    assert not v["ok"] and any(p["problem"] == "finding changed" for p in v["problems"])


def test_removing_an_entry_or_cutting_the_tail_is_detected(enrolled: Sensor, cp) -> None:
    _seed(enrolled, cp)
    kept_head = _verify(cp)["head"]
    with _db(cp) as db:
        first = db.query(AuditEntry).order_by(AuditEntry.seq).first().seq
        db.execute(delete(AuditEntry).where(AuditEntry.seq == first + 1))
        db.commit()
    assert any("chain broken" in p["problem"] for p in _verify(cp)["problems"])

    with _db(cp) as db:  # a clean cut at the end leaves a valid but shorter chain
        db.execute(delete(AuditEntry))
        db.commit()
    assert _verify(cp)["ok"]
    assert not _verify(cp, expect_head=kept_head)["ok"]  # the head kept outside tells
