"""Approval audit view (server/audit.py): answers joined with the held call and its findings."""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from conftest import CP_ADMIN
from sg_advance.sensor import Sensor
from sg_advance.sensor.adapters import AdapterContext
from sg_advance.sensor.plugin_api import judge, record_resolution


def call(call_id: str, command: str, session: str = "agent:main:main") -> dict[str, Any]:
    return {
        "op": "tool_call",
        "sessionKey": session,
        "toolCallId": call_id,
        "toolName": "exec",
        "params": {"command": command},
        "requester": {"channel": "webchat", "senderId": "alice-id"},
    }


def answer(call_id: str, decision: str, session: str = "agent:main:main") -> dict[str, Any]:
    return call(call_id, "", session) | {"op": "resolution", "decision": decision, "source": "daemon"}


def approvals(cp: TestClient, **query: Any) -> list[dict[str, Any]]:
    r = cp.get("/v1/admin/approvals", params=query, headers=CP_ADMIN)
    assert r.status_code == 200, r.text
    return r.json()


def test_audit_view_joins_answer_call_and_findings(enrolled: Sensor, cp: TestClient) -> None:
    ctx = AdapterContext(enrolled, user_id="alice", hostname="alice-pc")
    assert judge(ctx, call("c1", "psql -c 'DELETE FROM users;'"))["decision"] == "approve"
    assert judge(ctx, call("c2", "psql -c 'DELETE FROM orders;'"))["decision"] == "approve"
    record_resolution(ctx, answer("c1", "allow-once"))
    record_resolution(ctx, answer("c2", "deny"))
    assert enrolled.flush().ok

    [row] = approvals(cp, approved="true")  # the usual audit view: what was allowed
    assert row["call_id"] == "c1" and row["decision"] == "allow-once" and row["user_id"] == "alice"
    assert row["held_call"]["arguments"] == {"command": "psql -c 'DELETE FROM users;'"}
    assert [f["rule_id"] for f in row["asked_by"]] == ["destructive-sql"]
    assert [f["rule_id"] for f in row["flagged"]] == ["user-approved-high-risk"]
    assert row["requester"] == {"channel": "webchat", "senderid": "alice-id"}
    assert row["approver"] is None  # OpenClaw does not say who pressed the button

    everything = approvals(cp)
    assert {r["decision"] for r in everything} == {"allow-once", "deny"}
    denied = next(r for r in everything if r["decision"] == "deny")
    assert denied["flagged"] == []  # denials are recorded, not flagged
    assert approvals(cp, user_id="bob") == []


def test_approval_fatigue_is_flagged(enrolled: Sensor, cp: TestClient) -> None:
    ctx = AdapterContext(enrolled, user_id="alice", hostname="alice-pc")
    for i in range(
        5
    ):  # separate sessions: fatigue counts per user (and stays under the per-session rate limit)
        session = f"agent:main:s{i}"
        assert judge(ctx, call(f"c{i}", f"psql -c 'DELETE FROM t{i};'", session))["decision"] == "approve"
        record_resolution(ctx, answer(f"c{i}", "allow-once", session))
    assert enrolled.flush().ok
    rows = approvals(cp)
    fatigue = {f["finding_id"] for r in rows for f in r["flagged"] if f["rule_id"] == "approval-fatigue"}
    assert len(fatigue) == 1  # one finding ...
    assert all(
        any(f["rule_id"] == "approval-fatigue" for f in r["flagged"]) for r in rows
    )  # ... citing all 5
    assert sum(f["rule_id"] == "user-approved-high-risk" for r in rows for f in r["flagged"]) == 5


def test_audit_proxy_names_who_actually_approved(enrolled: Sensor, cp: TestClient) -> None:
    """Team gateway: alice's agent asked, secops pressed allow (seen by the audit proxy)."""
    from datetime import UTC, datetime

    from sg_advance.schema import AgentEvent

    ctx = AdapterContext(enrolled, user_id="alice", hostname="gw")
    judge(ctx, call("c1", "psql -c 'DELETE FROM users;'"))
    pressed = AgentEvent.model_validate(
        {
            "ts": datetime.now(UTC),
            "endpoint": {"device_id": "pending"},
            "principal": {"user_id": "secops@corp.test"},
            "agent": {"type": "openclaw", "session_id": "agent:main:main"},
            "source": {"sensor": "openclaw_audit_proxy"},
            "payload": {
                "kind": "operator.action",
                "action": "approval.resolve",
                "method": "plugin.approval.resolve",
                "decision": "allow-once",
                "ok": True,
                "approval_id": "ap1",
                "call_id": "c1",
            },
        }
    )
    enrolled.process(pressed)
    record_resolution(ctx, answer("c1", "allow-once"))
    assert enrolled.flush().ok

    [row] = approvals(cp)
    assert row["user_id"] == "alice"  # whose agent wanted to run it
    assert row["approver"] == "secops@corp.test" and row["approver_source"] == "audit_proxy"
