"""Audit proxy (M5b): who answered an approval or stopped a run, from the identity proxy's header.

Frame shapes follow OpenClaw 2026.11.3 (approval-shared, chat-abort-handler); the gateway is fake.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from collections.abc import AsyncIterator
from typing import Any

import pytest
from websockets.asyncio.client import connect
from websockets.asyncio.server import ServerConnection, serve
from websockets.exceptions import InvalidStatus

from sg_advance.sensor import Sensor
from sg_advance.sensor.adapters import AdapterContext
from sg_advance.sensor.adapters.openclaw_audit_proxy import OpenClawAuditProxyAdapter

PROMPT = {
    "type": "event",
    "event": "plugin.approval.requested",
    "payload": {
        "id": "ap1",
        "request": {
            "title": "SG-Advance",
            "toolName": "exec",
            "toolCallId": "c1",
            "sessionKey": "agent:main:dashboard:alice1",
            "runId": "r1",
        },
    },
}


class FakeGateway:
    def __init__(self) -> None:
        self.headers: list[dict[str, str]] = []
        self.received: list[str] = []

    async def handler(self, ws: ServerConnection) -> None:
        assert ws.request is not None
        self.headers.append({k.lower(): v for k, v in ws.request.headers.raw_items()})
        await ws.send(json.dumps(PROMPT))
        async for raw in ws:
            self.received.append(raw)
            req = json.loads(raw)
            rid, method = req.get("id"), req.get("method")
            if method == "plugin.approval.resolve":
                await ws.send(json.dumps({"type": "res", "id": rid, "ok": True, "payload": {"ok": True}}))
            elif method == "exec.approval.list":
                record = {
                    "id": "ex1",
                    "request": {"command": "psql -c 'DELETE FROM t;'", "sessionKey": "s-bob"},
                }
                await ws.send(json.dumps({"type": "res", "id": rid, "ok": True, "payload": [record]}))
            elif method == "exec.approval.resolve":
                await ws.send(json.dumps({"type": "res", "id": rid, "ok": True, "payload": {"ok": True}}))
            elif method == "chat.abort":
                err = {"code": "INVALID_REQUEST", "message": "unauthorized"}
                await ws.send(json.dumps({"type": "res", "id": rid, "ok": False, "error": err}))
            else:
                await ws.send(json.dumps({"type": "res", "id": rid, "ok": True, "payload": {"echo": method}}))


@pytest.fixture
async def gateway() -> AsyncIterator[tuple[FakeGateway, str]]:
    gw = FakeGateway()
    async with serve(gw.handler, "127.0.0.1", 0) as server:
        yield gw, f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}"


async def start(sensor: Sensor, upstream: str, trusted: tuple[str, ...] = ("127.0.0.1",)):
    proxy = OpenClawAuditProxyAdapter("127.0.0.1:0", upstream, trusted)
    task = asyncio.create_task(proxy.run(AdapterContext(sensor, user_id="team-audit", hostname="gw")))
    await asyncio.wait_for(proxy.listening.wait(), 5)
    return proxy, task, f"ws://127.0.0.1:{proxy.bound_port}"


def actions(sensor: Sensor) -> list[dict[str, Any]]:
    with sqlite3.connect(sensor.spool.path) as db:
        docs = [json.loads(d) for (d,) in db.execute("SELECT doc FROM outbox WHERE kind = 'event'")]
    return [d for d in docs if d["payload"]["kind"] == "operator.action"]


async def until(cond, timeout: float = 5.0) -> None:
    for _ in range(int(timeout / 0.02)):
        if cond():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("condition not met in time")


IDENTITY = {
    "x-forwarded-user": "secops@corp.test",
    "x-forwarded-proto": "http",
    "x-forwarded-for": "172.28.0.1",
}


async def test_approval_is_recorded_with_the_person_who_pressed_it(gateway, enrolled: Sensor) -> None:
    gw, upstream = gateway
    _, task, url = await start(enrolled, upstream)
    try:
        async with connect(url, additional_headers=IDENTITY, origin="http://localhost:18804") as ws:  # type: ignore[arg-type]
            assert json.loads(await ws.recv())["event"] == "plugin.approval.requested"  # relayed as-is
            await ws.send(
                json.dumps(
                    {
                        "type": "req",
                        "id": "q1",
                        "method": "plugin.approval.resolve",
                        "params": {"id": "ap1", "decision": "allow-once"},
                    }
                )
            )
            assert json.loads(await ws.recv())["ok"] is True
        await until(lambda: len(actions(enrolled)) == 1)
    finally:
        task.cancel()
    [ev] = actions(enrolled)
    assert ev["principal"]["user_id"] == "secops@corp.test"  # who acted, not whose agent ran
    p = ev["payload"]
    assert (p["action"], p["decision"], p["ok"]) == ("approval.resolve", "allow-once", True)
    assert (p["approval_id"], p["call_id"], p["tool"]) == ("ap1", "c1", "exec")
    assert ev["agent"]["session_id"] == "agent:main:dashboard:alice1" and ev["agent"]["run_id"] == "r1"
    assert ev["source"]["sensor"] == "openclaw_audit_proxy"
    assert ev["labels"]["openclaw.client_ip"] == "172.28.0.1"
    # The gateway still sees the identity and the browser origin (trusted-proxy auth, allowedOrigins).
    assert gw.headers[0]["x-forwarded-user"] == "secops@corp.test"
    assert gw.headers[0]["origin"] == "http://localhost:18804"


async def test_exec_approvals_from_a_list_and_refused_aborts(gateway, enrolled: Sensor) -> None:
    _, upstream = gateway
    _, task, url = await start(enrolled, upstream)
    try:
        async with connect(url, additional_headers=IDENTITY) as ws:  # type: ignore[arg-type]
            await ws.recv()
            for req in (
                {"type": "req", "id": "q1", "method": "exec.approval.list", "params": {}},
                {
                    "type": "req",
                    "id": "q2",
                    "method": "exec.approval.resolve",
                    "params": {"id": "ex1", "decision": "deny"},
                },
                {
                    "type": "req",
                    "id": "q3",
                    "method": "chat.abort",
                    "params": {"sessionKey": "s-bob", "runId": "r9"},
                },
            ):
                await ws.send(json.dumps(req))
                await ws.recv()
        await until(lambda: len(actions(enrolled)) == 2)
    finally:
        task.cancel()
    got = {a["payload"]["action"]: a for a in actions(enrolled)}
    ex = got["approval.resolve"]["payload"]
    assert (ex["call_id"], ex["decision"], ex["target_session_id"]) == ("approval:ex1", "deny", "s-bob")
    ab = got["run.abort"]["payload"]
    assert (ab["ok"], ab["error"], ab["target_run_id"]) == (False, "INVALID_REQUEST", "r9")


async def test_conversation_frames_pass_through_unread(gateway, enrolled: Sensor) -> None:
    gw, upstream = gateway
    _, task, url = await start(enrolled, upstream)
    msg = json.dumps(
        {"type": "req", "id": "q1", "method": "chat.send", "params": {"message": "급여 자료 요약해줘"}},
        ensure_ascii=False,
    )
    try:
        async with connect(url, additional_headers=IDENTITY) as ws:  # type: ignore[arg-type]
            await ws.recv()
            await ws.send(msg)
            assert json.loads(await ws.recv())["payload"] == {"echo": "chat.send"}
    finally:
        task.cancel()
    assert gw.received == [msg]  # byte-for-byte
    assert actions(enrolled) == []


async def test_only_the_identity_proxy_may_connect(gateway, enrolled: Sensor) -> None:
    _, upstream = gateway
    _, task, url = await start(enrolled, upstream, trusted=("10.9.9.9",))
    try:
        with pytest.raises(InvalidStatus):
            async with connect(url, additional_headers=IDENTITY):  # type: ignore[arg-type]
                pass
    finally:
        task.cancel()
    _, task, url = await start(enrolled, upstream)
    try:
        with pytest.raises(InvalidStatus):  # trusted peer, but no identity header
            async with connect(url):
                pass
    finally:
        task.cancel()
