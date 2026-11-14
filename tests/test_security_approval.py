"""Security approval queue (M11): a tool call waits on the device until security decides in the
console; nobody decides in time → denied. Uses the real policy with a common override that turns
``destructive-sql`` into ``security_approval``."""

from __future__ import annotations

import asyncio
import dataclasses
import json
import sqlite3
from typing import Any

import pytest
from fastapi.testclient import TestClient

from conftest import CP_ADMIN, CpTransport
from sg_advance.sensor import Sensor
from sg_advance.sensor.adapters import AdapterContext
from sg_advance.sensor.plugin_api import LocalApiServer, judge
from sg_advance.sensor.security_hold import Holds
from sg_advance.server.policy_layers import COMMON

VIEWER = {"Authorization": "Bearer view-test"}
WHO = {"by": "secops@corp.test", "reason": "test"}


def sql_call(call_id: str) -> dict[str, Any]:
    return {
        "op": "tool_call",
        "agentId": "main",
        "sessionKey": "agent:main:dashboard:aaa",
        "runId": "r1",
        "toolCallId": call_id,
        "toolName": "exec",
        "params": {"command": "psql -c 'DELETE FROM users;'"},
    }


def spooled(sensor: Sensor, kind: str = "event") -> list[dict[str, Any]]:
    with sqlite3.connect(sensor.spool.path) as db:
        return [json.loads(d) for (d,) in db.execute("SELECT doc FROM outbox WHERE kind = ?", (kind,))]


def resolutions(sensor: Sensor) -> list[dict[str, Any]]:
    return [e for e in spooled(sensor) if e["payload"]["kind"] == "approval.resolved"]


@pytest.fixture
def ctx(cp: TestClient, enrolled: Sensor) -> AdapterContext:
    cp.app.state.settings = dataclasses.replace(cp.app.state.settings, dashboard_token="view-test")
    r = cp.put(
        "/v1/admin/policy/overrides",
        json={"scope": COMMON, "rule_id": "destructive-sql", "response": "security_approval", **WHO},
        headers=CP_ADMIN,
    )
    assert r.status_code == 200, r.text
    assert enrolled.sync_policy().value == "updated"
    return AdapterContext(enrolled, user_id="alice@corp.test", hostname="gw", holds=Holds(wait_seconds=30))


def queue(cp: TestClient, **params: str) -> list[dict[str, Any]]:
    return cp.get("/v1/admin/security-approvals", params=params, headers=CP_ADMIN).json()


async def registered(cp: TestClient) -> dict[str, Any]:
    for _ in range(200):
        rows = await asyncio.to_thread(queue, cp, status="pending")
        if rows:
            return rows[0]
        await asyncio.sleep(0.01)
    raise AssertionError("hold never reached the control plane")


async def test_security_approves_and_the_call_runs(cp: TestClient, ctx: AdapterContext) -> None:
    held = judge(ctx, sql_call("c1"))
    assert held["decision"] == "hold" and held["action"] == "security_approval" and held["wait_ms"] == 30_000
    waiting = asyncio.create_task(ctx.holds.wait(ctx, held["hold_id"]))  # type: ignore[union-attr]

    row = await registered(cp)
    assert row["id"] == held["hold_id"] and row["user_id"] == "alice@corp.test" and row["tool"] == "exec"
    assert "DELETE FROM users" in row["arguments_preview"] and row["rule_ids"] == ["destructive-sql"]
    assert row["severity"] == "high" and row["event_id"] and row["finding_ids"]

    body = {"decision": "approve", "by": "lead@corp.test", "reason": "planned migration"}
    assert (
        cp.post(f"/v1/admin/security-approvals/{row['id']}/decision", json=body, headers=VIEWER).status_code
        == 403
    )
    r = cp.post(f"/v1/admin/security-approvals/{row['id']}/decision", json=body, headers=CP_ADMIN)
    assert r.status_code == 200 and r.json()["status"] == "approved"
    assert (
        cp.post(f"/v1/admin/security-approvals/{row['id']}/decision", json=body, headers=CP_ADMIN).status_code
        == 409
    )

    assert await ctx.holds.poll(ctx) == 1  # type: ignore[union-attr]
    assert await waiting == {"ok": True, "decision": "allow", "approver": "lead@corp.test"}

    [done] = queue(cp)
    assert done["status"] == "approved" and done["outcome"] == "allowed" and done["delivered_at"]
    [ev] = resolutions(ctx.sensor)
    p = ev["payload"]
    assert p["via"] == "security" and p["approver"] == "lead@corp.test" and p["decision"] == "allow-once"
    assert p["request_event_id"] == row["event_id"] and p["rule_ids"] == ["destructive-sql"]
    held_call = next(e for e in spooled(ctx.sensor) if e["event_id"] == row["event_id"])
    assert held_call["payload"]["kind"] == "tool.call"
    # A security approval is not the user approving something risky (rules/approvals.yaml: via user).
    assert "user-approved-high-risk" not in {f["rule_id"] for f in spooled(ctx.sensor, "finding")}


async def test_denied_timed_out_and_unreachable_calls_are_blocked(
    cp: TestClient, cp_transport: CpTransport, ctx: AdapterContext
) -> None:
    held = judge(ctx, sql_call("c1"))
    waiting = asyncio.create_task(ctx.holds.wait(ctx, held["hold_id"]))  # type: ignore[union-attr]
    row = await registered(cp)
    cp.post(
        f"/v1/admin/security-approvals/{row['id']}/decision",
        json={"decision": "deny", "by": "lead@corp.test", "reason": "not during business hours"},
        headers=CP_ADMIN,
    )
    await ctx.holds.poll(ctx)  # type: ignore[union-attr]
    out = await waiting
    assert out["decision"] == "block" and "lead@corp.test: not during business hours" in out["reason"]
    assert queue(cp)[0]["outcome"] == "denied"

    # Nobody decides: denied when the wait ends; the console shows it expired and refuses a late answer.
    ctx.holds.wait_seconds = 3  # type: ignore[union-attr]
    held = judge(ctx, sql_call("c2"))
    out = await ctx.holds.wait(ctx, held["hold_id"])  # type: ignore[union-attr]
    assert out["decision"] == "block" and out["outcome"] == "timeout"
    late = cp.post(
        f"/v1/admin/security-approvals/{held['hold_id']}/decision",
        json={"decision": "approve", **WHO},
        headers=CP_ADMIN,
    )
    assert late.status_code == 409 and "expired" in late.text
    assert queue(cp, status="expired")[0]["outcome"] == "timeout"
    assert queue(cp, status="pending") == []

    # The control plane is down: nobody can be asked, so the call is denied at once.
    cp_transport.down = True
    held = judge(ctx, sql_call("c3"))
    out = await ctx.holds.wait(ctx, held["hold_id"])  # type: ignore[union-attr]
    assert out["decision"] == "block" and out["outcome"] == "unreachable"
    cp_transport.down = False

    decisions = [
        (r["payload"]["decision"], r["labels"]["sga_security_outcome"]) for r in resolutions(ctx.sensor)
    ]
    assert sorted(decisions) == [("deny", "denied"), ("deny", "unreachable"), ("timeout", "timeout")]


async def test_plugin_protocol_and_cached_policy_path(cp: TestClient, ctx: AdapterContext, tmp_path) -> None:
    server = LocalApiServer(ctx, tmp_path / "unused.sock")
    held = await server.handle_async(json.dumps(sql_call("c1")).encode())
    assert held["decision"] == "hold"
    # The run was aborted before the plugin started waiting: cancelled, never sent to security.
    assert server.handle(json.dumps({"op": "cancel_hold", "hold_id": held["hold_id"]}).encode())["found"]
    out = await server.handle_async(json.dumps({"op": "await_hold", "hold_id": held["hold_id"]}).encode())
    assert out["decision"] == "block" and out["outcome"] == "cancelled"
    assert queue(cp) == []
    unknown = await server.handle_async(json.dumps({"op": "await_hold", "hold_id": "nope"}).encode())
    assert unknown["decision"] == "block"

    # No daemon to wait with (sga-sensor evaluate): blocked, with the reason said.
    cli = AdapterContext(ctx.sensor, user_id="alice@corp.test")
    out = judge(cli, sql_call("c2"))
    assert out["decision"] == "block" and "센서 데몬이 없어" in out["reason"]


def test_security_approval_sits_between_user_approval_and_block(cp: TestClient) -> None:
    cp.post("/v1/admin/policy/groups", json={"name": "data", **WHO}, headers=CP_ADMIN)
    tighten = {"scope": "data", "rule_id": "destructive-sql", "response": "security_approval", **WHO}
    assert cp.put("/v1/admin/policy/overrides", json=tighten, headers=CP_ADMIN).status_code == 200
    loosen = {
        "scope": "data",
        "rule_id": "sensitive-file-exfil-command",
        "response": "security_approval",
        **WHO,
    }
    r = cp.put("/v1/admin/policy/overrides", json=loosen, headers=CP_ADMIN)
    assert r.status_code == 422 and "cannot lower" in r.text  # block → security_approval is weaker


def test_devices_see_only_their_own_holds(cp: TestClient, enrolled: Sensor) -> None:
    hold = {
        "id": "a" * 32,
        "tool": "exec",
        "user_id": "alice@corp.test",
        "session_id": "s",
        "wait_seconds": 60,
        "arguments_preview": "export OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwx",
    }
    alice = {"Authorization": f"Bearer {enrolled.creds.device_token}"}
    assert cp.post("/v1/security-approvals", json=hold, headers=alice).status_code == 201
    assert cp.post("/v1/security-approvals", json=hold, headers=alice).status_code == 201  # retry: same
    [row] = queue(cp)
    assert "sk-proj-abcdefghij" not in row["arguments_preview"]  # redacted again on the server
    token = cp.post("/v1/admin/enrollment-tokens", json={}, headers=CP_ADMIN).json()["token"]
    dev = cp.post("/v1/enroll", json={"device_id": "dev-bob"}, headers={"Authorization": f"Bearer {token}"})
    bob = {"Authorization": f"Bearer {dev.json()['device_token']}"}
    assert cp.post("/v1/security-approvals", json=hold, headers=bob).status_code == 409
    cp.post(
        f"/v1/admin/security-approvals/{'a' * 32}/decision",
        json={"decision": "deny", **WHO},
        headers=CP_ADMIN,
    )
    assert cp.get("/v1/security-approvals/decisions", headers=bob).json() == []
    assert (
        cp.post(
            f"/v1/security-approvals/{'a' * 32}/outcome", json={"outcome": "denied"}, headers=bob
        ).status_code
        == 404
    )
    assert [d["decision"] for d in cp.get("/v1/security-approvals/decisions", headers=alice).json()] == [
        "denied"
    ]
    assert cp.get("/v1/security-approvals/decisions", headers=alice).json() == []  # handed out once


def test_a_decision_is_handed_out_again_until_the_device_reports_an_outcome(
    cp: TestClient, enrolled: Sensor, monkeypatch
) -> None:
    """Review 2026-11-15: a decision was marked delivered before the device had it; a lost response lost
    the decision for good (the hold then timed out although security approved in time). It is now
    handed out again after a short lease until the device reports what happened, like remote actions."""
    from datetime import timedelta

    from sg_advance.server import security_approvals as sa

    hold = {"id": "b" * 32, "tool": "exec", "user_id": "alice@corp.test", "session_id": "s",
            "wait_seconds": 120}  # fmt: skip
    alice = {"Authorization": f"Bearer {enrolled.creds.device_token}"}
    assert cp.post("/v1/security-approvals", json=hold, headers=alice).status_code == 201
    cp.post(f"/v1/admin/security-approvals/{'b' * 32}/decision", json={"decision": "approve", **WHO},
            headers=CP_ADMIN)  # fmt: skip

    def decisions() -> list[str]:
        return [d["decision"] for d in cp.get("/v1/security-approvals/decisions", headers=alice).json()]

    assert decisions() == ["approved"]
    assert decisions() == []  # within the lease: not again (the device is applying it)
    real = sa.utcnow
    monkeypatch.setattr(sa, "utcnow", lambda: real() + sa.DECISION_LEASE + timedelta(seconds=1))
    assert decisions() == ["approved"]  # the first answer was lost: handed out again
    assert cp.post(f"/v1/security-approvals/{'b' * 32}/outcome", json={"outcome": "allowed"},
                   headers=alice).status_code == 204  # fmt: skip
    monkeypatch.setattr(sa, "utcnow", lambda: real() + 3 * sa.DECISION_LEASE)
    assert decisions() == []  # the device said what happened: done
    # And never once the hold has expired: the device stopped waiting by then.
    late = {"id": "c" * 32, "tool": "exec", "user_id": "alice@corp.test", "session_id": "s",
            "wait_seconds": 1}  # fmt: skip
    monkeypatch.setattr(sa, "utcnow", real)
    assert cp.post("/v1/security-approvals", json=late, headers=alice).status_code == 201
    cp.post(f"/v1/admin/security-approvals/{'c' * 32}/decision", json={"decision": "deny", **WHO},
            headers=CP_ADMIN)  # fmt: skip
    assert decisions() == ["denied"]
    monkeypatch.setattr(sa, "utcnow", lambda: real() + timedelta(minutes=5))
    assert decisions() == []
