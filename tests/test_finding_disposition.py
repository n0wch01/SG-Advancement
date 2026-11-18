"""Marking findings as false positives (2026-11-18, user decision).

Found in the real Claude Code task scenario: one false positive left four high findings, the person's risk
was elevated for 24 hours and every new task grant was refused. A reviewer with ``findings.triage`` in the
finding's project can mark it a false positive; the finding stays, it stops counting toward risk."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from conftest import CP_ADMIN
from sg_advance.server.db import AuditEntry
from test_rbac import bind, ingest, person, scoped  # noqa: F401  # scoped is a fixture


def risk_of(cp, user: str) -> dict | None:
    return next((r for r in cp.get("/v1/admin/risk", headers=CP_ADMIN).json() if r["user_id"] == user), None)


def mark(cp, headers, finding_id: str, reason: str = "rate rule on normal work", **extra):
    body = {"status": "false_positive", "reason": reason, **extra}
    return cp.post(f"/v1/admin/findings/{finding_id}/disposition", headers=headers, json=body)


def test_a_false_positive_stops_counting_toward_risk_and_is_audited(cp, scoped):  # noqa: F811
    alice, _, sensor_a, _ = scoped
    soc, _ = person(cp, "sam", "soc", "alpha")
    findings = [ingest(cp, sensor_a, "device-a")[1] for _ in range(3)]  # three high: elevated
    assert risk_of(cp, "alice")["elevated"] is True

    for f in findings[:2]:
        assert mark(cp, soc, f["finding_id"]).status_code == 200
    assert risk_of(cp, "alice") is not None and risk_of(cp, "alice")["elevated"] is False
    assert mark(cp, soc, findings[2]["finding_id"]).status_code == 200
    assert risk_of(cp, "alice") is None  # nothing left that counts

    detail = cp.get("/v1/admin/findings/" + findings[0]["finding_id"], headers=soc).json()
    assert detail["finding"]["finding_id"] == findings[0]["finding_id"]  # the finding itself stays
    assert detail["disposition"]["status"] == "false_positive"
    assert detail["disposition"]["decided_by"] == "sam"  # the authenticated reviewer
    with Session(cp.app.state.db.engine) as db:
        rows = db.scalars(select(AuditEntry).where(AuditEntry.kind == "finding_disposition"))
        entries = [a.doc for a in rows]
    assert len(entries) == 3 and {e["by"] for e in entries} == {"sam"}
    assert {e["user_id"] for e in entries} == {"alice"}


def test_who_may_mark_a_finding(cp, scoped):  # noqa: F811
    alice, bob, sensor_a, _ = scoped
    finding = ingest(cp, sensor_a, "device-a")[1]
    fid = finding["finding_id"]
    other_soc, _ = person(cp, "olga", "soc", "beta")
    assert mark(cp, other_soc, fid).status_code == 404  # another project's finding is not even visible
    assert mark(cp, alice, fid).status_code == 403  # reading findings is not triage
    bind(cp, "alice", "soc", "alpha")
    response = mark(cp, alice, fid)  # a reviewer cannot clear a finding about themselves
    assert response.status_code == 403 and "another reviewer" in response.text
    soc, _ = person(cp, "sam", "soc", "alpha")
    assert mark(cp, soc, fid, by="someone-else").status_code == 422  # the actor is never taken from the body
    assert mark(cp, soc, fid, reason="").status_code == 422  # a reason is required
    assert mark(cp, soc, fid).status_code == 200
    assert mark(cp, soc, fid).status_code == 409  # one verdict per finding
    assert risk_of(cp, "alice") is None
