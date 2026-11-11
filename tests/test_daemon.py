"""Local sensor daemon (M5): adapters + periodic flush/sync + graceful shutdown."""

from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi.testclient import TestClient

from conftest import CP_ADMIN, CP_URL, CpTransport
from sg_advance.sensor import Sensor, SensorHome, enroll
from sg_advance.sensor.adapters import AdapterContext, ReplayAdapter
from sg_advance.sensor.daemon import Daemon

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples" / "events"


def events_on_server(cp: TestClient) -> int:
    return len(cp.get("/v1/admin/events", params={"limit": 1000}, headers=CP_ADMIN).json())


async def until(cond, timeout: float = 15.0, describe=None) -> None:
    # Generous upper bound: CI runners are ~2x slower than a laptop and the first test of the
    # session also pays cold imports. A passing test returns as soon as the condition holds.
    for _ in range(int(timeout / 0.02)):
        if cond():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("condition not met in time" + (f": {describe()}" if describe else ""))


async def test_daemon_ships_replayed_events_periodically(enrolled: Sensor, cp: TestClient) -> None:
    replay = ReplayAdapter([EXAMPLES / "openclaw.jsonl"])
    daemon = Daemon(enrolled, [replay], AdapterContext(enrolled, "alice"), flush_interval=0.05)
    task = asyncio.create_task(daemon.run())
    try:
        await asyncio.wait_for(replay.done.wait(), 5)
        # flush runs in a worker thread and bumps the counter after it returns, so the server
        # can already hold the events while the counter is still 0: wait for both.
        n = len(list(replay.events()))
        await until(
            lambda: events_on_server(cp) == n and daemon.stats.flushes >= 1,
            describe=lambda: (
                f"server={events_on_server(cp)} expected={n} daemon_done={task.done()} stats={daemon.stats}"
            ),
        )
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


async def test_flush_error_does_not_stop_the_daemon(enrolled: Sensor, cp: TestClient, monkeypatch) -> None:
    """An unexpected error during one flush is logged and the next tick tries again."""
    real = enrolled.flush
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("corrupt row")
        return real()

    monkeypatch.setattr(enrolled, "flush", flaky)
    replay = ReplayAdapter([EXAMPLES / "openclaw.jsonl"])
    daemon = Daemon(enrolled, [replay], AdapterContext(enrolled, "alice"), flush_interval=0.05)
    task = asyncio.create_task(daemon.run())
    try:
        await asyncio.wait_for(replay.done.wait(), 5)
        n = len(list(replay.events()))
        await until(lambda: events_on_server(cp) == n and daemon.stats.flushes >= 1)
        assert not task.done()
        assert daemon.stats.flush_errors == 1
        assert "corrupt row" in (daemon.stats.last_flush_error or "")
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


async def test_shutdown_flushes_what_is_left(enrolled: Sensor, cp: TestClient) -> None:
    replay = ReplayAdapter([EXAMPLES / "claude_code.jsonl"])
    daemon = Daemon(enrolled, [replay], AdapterContext(enrolled, "bob"), flush_interval=3600)
    task = asyncio.create_task(daemon.run())
    await asyncio.wait_for(replay.done.wait(), 5)
    assert events_on_server(cp) == 0  # periodic flush hasn't fired
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    assert events_on_server(cp) == len(list(replay.events()))


async def test_daemon_waits_for_a_policy(cp: TestClient, cp_transport: CpTransport, tmp_path: Path) -> None:
    """First boot with the control plane down: no policy yet, so wait instead of exiting."""
    home = SensorHome(tmp_path / "h")
    token = cp.post("/v1/admin/enrollment-tokens", json={}, headers=CP_ADMIN).json()["token"]
    enroll(home, CP_URL, token, transport=cp_transport)
    sensor = Sensor(home, transport=cp_transport)
    cp_transport.down = True
    daemon = Daemon(sensor, [], AdapterContext(sensor, "x"), sync_interval=0.05, flush_interval=0.05)
    task = asyncio.create_task(daemon.run())
    try:
        await asyncio.sleep(0.2)
        assert not daemon.ready.is_set() and not task.done()
        cp_transport.down = False
        await asyncio.wait_for(daemon.ready.wait(), 5)
        assert sensor.policy is not None
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


async def test_crashing_adapter_does_not_stop_the_others(enrolled: Sensor, cp: TestClient) -> None:
    class Broken:
        name = "broken"

        async def run(self, ctx: AdapterContext) -> None:
            raise RuntimeError("boom")

    replay = ReplayAdapter([EXAMPLES / "openclaw.jsonl"])
    daemon = Daemon(enrolled, [Broken(), replay], AdapterContext(enrolled, "alice"), flush_interval=0.05)
    task = asyncio.create_task(daemon.run())
    try:
        await asyncio.wait_for(replay.done.wait(), 5)
        await until(lambda: events_on_server(cp) > 0)
        assert "boom" in daemon.stats.adapter_errors["broken"]
        assert not task.done()
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
