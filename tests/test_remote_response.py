"""Remote response (M11): security queues an action, the sensor runs it, the plugin enforces it."""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest
from fastapi.testclient import TestClient

from conftest import CP_ADMIN
from sg_advance.sensor import Sensor
from sg_advance.sensor.adapters import AdapterContext
from sg_advance.sensor.adapters.openclaw import OpenClawAdapter
from sg_advance.sensor.plugin_api import judge
from sg_advance.sensor.response import BLOCKED_SESSIONS, BLOCKED_USERS, install_core_handlers, run_pending

VIEWER = {"Authorization": "Bearer view-test"}
WHO = {"by": "secops@corp.test", "reason": "suspected injection"}


def call(call_id: str, session: str = "agent:main:dashboard:aaa", **extra: Any) -> dict[str, Any]:
    return {
        "op": "tool_call",
        "agentId": "main",
        "sessionKey": session,
        "runId": "r1",
        "toolCallId": call_id,
        "toolName": "read",
        "params": {"path": "README.md"},
        **extra,
    }


@pytest.fixture
def ctx(enrolled: Sensor) -> AdapterContext:
    c = AdapterContext(enrolled, user_id="alice@corp.test", hostname="gw")
    install_core_handlers(c)
    return c


def queue(cp: TestClient, action: str, target: str, device: str = "dev-alice") -> str:
    r = cp.post(
        "/v1/admin/actions",
        json={"device_id": device, "action": action, "target": target, **WHO},
        headers=CP_ADMIN,
    )
    assert r.status_code == 201, r.text
    return r.json()["id"]


def status_of(cp: TestClient, action_id: str) -> dict[str, Any]:
    return next(a for a in cp.get("/v1/admin/actions", headers=CP_ADMIN).json() if a["id"] == action_id)


async def test_blocking_a_conversation_blocks_its_next_tool_calls(
    cp: TestClient, ctx: AdapterContext
) -> None:
    assert judge(ctx, call("c0"))["decision"] == "allow"
    aid = queue(cp, "block_session", "agent:main:dashboard:aaa")
    assert status_of(cp, aid)["status"] == "pending"

    assert await run_pending(ctx) == 1
    assert ctx.sensor.trusted[BLOCKED_SESSIONS] == {"agent:main:dashboard:aaa"}
    done = status_of(cp, aid)
    assert (
        done["status"] == "done" and done["delivered_at"] and done["result_detail"] == "conversation blocked"
    )
    assert await run_pending(ctx) == 0  # delivered once

    blocked = judge(ctx, call("c1"))
    assert blocked["decision"] == "block"
    assert judge(ctx, call("c2", session="agent:main:dashboard:other"))["decision"] == "allow"

    queue(cp, "unblock_session", "agent:main:dashboard:aaa")
    await run_pending(ctx)
    assert ctx.sensor.trusted[BLOCKED_SESSIONS] == set()
    assert judge(ctx, call("c3"))["decision"] == "allow"


async def test_blocking_a_person_survives_a_sensor_restart(cp: TestClient, ctx: AdapterContext) -> None:
    queue(cp, "block_user", "alice@corp.test")
    await run_pending(ctx)
    assert judge(ctx, call("c1"))["decision"] == "block"  # attributed to alice (--user)
    again = Sensor(ctx.sensor.home, transport=ctx.sensor.client._send)  # noqa: SLF001
    again.start()
    assert again.trusted[BLOCKED_USERS] == {"alice@corp.test"}


async def test_unsupported_and_failing_actions_are_reported(cp: TestClient, ctx: AdapterContext) -> None:
    aid = queue(cp, "disable_plugin", "evil")  # no OpenClaw adapter registered here
    await run_pending(ctx)
    row = status_of(cp, aid)
    assert row["status"] == "failed" and "not supported" in row["result_detail"]

    adapter = OpenClawAdapter("ws://unused", "t", plugin_disabler=lambda pid: (False, f"no plugin {pid}"))
    adapter._register_actions(ctx)  # noqa: SLF001
    aid = queue(cp, "abort_session", "agent:main:dashboard:aaa")
    await run_pending(ctx)
    assert status_of(cp, aid)["result_detail"] == "not connected to the gateway"

    class Refusing:
        async def request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
            assert method == "sessions.abort" and params == {"key": "agent:main:dashboard:aaa"}
            return {"ok": False, "error": {"code": "UNAUTHORIZED"}}

    adapter._conn = Refusing()  # type: ignore[assignment]  # noqa: SLF001
    aid = queue(cp, "abort_session", "agent:main:dashboard:aaa")
    await run_pending(ctx)
    row = status_of(cp, aid)
    assert row["status"] == "failed" and "refused" in row["result_detail"]  # decision B: no admin
    aid = queue(cp, "disable_plugin", "evil")
    await run_pending(ctx)
    assert status_of(cp, aid)["result_detail"] == "no plugin evil"


def test_only_admins_queue_and_devices_report_only_their_own(cp: TestClient, enrolled: Sensor) -> None:
    cp.app.state.settings = dataclasses.replace(cp.app.state.settings, dashboard_token="view-test")
    body = {"device_id": "dev-alice", "action": "block_session", "target": "s", **WHO}
    assert cp.post("/v1/admin/actions", json=body, headers=VIEWER).status_code == 403
    assert (
        cp.post("/v1/admin/actions", json={**body, "device_id": "nope"}, headers=CP_ADMIN).status_code == 404
    )
    assert cp.post("/v1/admin/actions", json={**body, "action": "rm_rf"}, headers=CP_ADMIN).status_code == 422
    assert cp.post("/v1/admin/actions", json={**body, "reason": ""}, headers=CP_ADMIN).status_code == 422
    assert cp.get("/v1/admin/actions", headers=VIEWER).status_code == 200
    aid = cp.post("/v1/admin/actions", json=body, headers=CP_ADMIN).json()["id"]
    other = cp.post("/v1/admin/enrollment-tokens", json={}, headers=CP_ADMIN).json()["token"]
    dev = cp.post(
        "/v1/enroll", json={"device_id": "dev-bob"}, headers={"Authorization": f"Bearer {other}"}
    ).json()
    bob = {"Authorization": f"Bearer {dev['device_token']}"}
    assert cp.get("/v1/actions", headers=bob).json() == []
    assert cp.post(f"/v1/actions/{aid}/result", json={"ok": True}, headers=bob).status_code == 404
