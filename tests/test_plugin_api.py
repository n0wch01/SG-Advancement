"""M5c: local verdict API for the OpenClaw gateway plugin, bypass detection, degraded CLI."""

from __future__ import annotations

import asyncio
import io
import json
import shutil
import sqlite3
import subprocess
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from sg_advance.sensor import Sensor
from sg_advance.sensor.adapters import AdapterContext
from sg_advance.sensor.cli import main as sensor_main
from sg_advance.sensor.plugin_api import LocalApiServer

ROOT = Path(__file__).resolve().parents[1]
PLUGIN_DIR = ROOT / "integrations" / "openclaw-plugin"


def req(call: str, tool: str = "exec", **params: Any) -> dict[str, Any]:
    return {
        "op": "tool_call",
        "agentId": "main",
        "sessionKey": "agent:main:main",
        "runId": "r1",
        "toolCallId": call,
        "toolName": tool,
        "params": params,
        "requester": {"channel": "webchat", "senderId": "alice-id"},
    }


def spooled(sensor: Sensor, kind: str) -> list[dict[str, Any]]:
    with sqlite3.connect(sensor.spool.path) as db:
        return [json.loads(d) for (d,) in db.execute("SELECT doc FROM outbox WHERE kind = ?", (kind,))]


@pytest.fixture
async def api(enrolled: Sensor) -> AsyncIterator[tuple[LocalApiServer, Path]]:
    d = Path(tempfile.mkdtemp(prefix="sn", dir="/tmp"))  # AF_UNIX paths must stay short
    server = LocalApiServer(AdapterContext(enrolled, "alice", "alice-pc"), d / "s.sock")
    await server.start()
    try:
        yield server, d / "s.sock"
    finally:
        await server.close()
        shutil.rmtree(d, ignore_errors=True)


async def ask(path: Path, *msgs: dict[str, Any] | bytes) -> list[dict[str, Any]]:
    reader, writer = await asyncio.open_unix_connection(str(path))
    out = []
    for m in msgs:
        writer.write(m if isinstance(m, bytes) else (json.dumps(m) + "\n").encode())
        await writer.drain()
        out.append(json.loads(await reader.readline()))
    writer.close()
    return out


async def test_socket_is_private(api) -> None:
    _, path = api
    assert oct(path.stat().st_mode & 0o777) == "0o600"


async def test_verdicts_map_to_plugin_decisions(api, enrolled: Sensor) -> None:
    server, path = api
    hello, block, approve, allow = await ask(
        path,
        {"op": "hello", "plugin": "sg-advance", "version": "0.1.0"},
        req("c1", command="rm -rf ~/projects"),
        req("c2", command="psql $DB -c 'DROP TABLE users;'"),
        req("c3", tool="read", path="README.md"),
    )
    assert hello == {"ok": True} and server.ctx.plugins.active
    assert block["decision"] == "block" and "destructive-shell-command" in block["rules"]
    assert approve["decision"] == "approve" and approve["action"] == "require_approval"
    assert allow["decision"] == "allow"

    findings = {f["rule_id"]: f for f in spooled(enrolled, "finding")}
    resp = findings["destructive-shell-command"]["response"]
    assert resp == {
        "action": "block",
        "enforced": True,
        "enforcer": "openclaw_plugin",
        "detail": "pre-exec: openclaw plugin blocked the tool call",
    }
    assert findings["destructive-sql"]["response"]["detail"].startswith("pre-exec: user approval")
    ev = next(e for e in spooled(enrolled, "event") if e["payload"]["call_id"] == "c1")
    assert ev["source"]["sensor"] == "openclaw_plugin"
    assert ev["labels"]["requester_senderid"] == "alice-id"
    assert all(server.ctx.plugins.seen(c) for c in ("c1", "c2", "c3"))


async def test_bad_requests_are_answered_not_crashed(api) -> None:
    _, path = api
    bad, unknown, resolution = await ask(
        path, b"{nope\n", {"op": "dance"}, {"op": "resolution", "toolCallId": "c1", "decision": "deny"}
    )
    assert bad == {"ok": False, "error": "invalid json"}
    assert unknown["ok"] is False and resolution == {"ok": True}


async def test_ws_adapter_skips_plugin_judged_calls_and_flags_bypass(enrolled: Sensor) -> None:
    from websockets.asyncio.server import serve

    from sg_advance.sensor.adapters.openclaw import OpenClawAdapter
    from test_openclaw_adapter import FakeGateway, tool, until

    gw = FakeGateway()
    ctx = AdapterContext(enrolled, "alice")
    ctx.plugins.touch()  # plugin said hello
    ctx.plugins.mark("c1")  # ...and judged c1 before it ran
    async with serve(gw.handler, "127.0.0.1", 0) as srv:
        url = f"ws://127.0.0.1:{srv.sockets[0].getsockname()[1]}"
        adapter = OpenClawAdapter(url, token="gw-token", enforce=False, plugin_grace=0.3)
        task = asyncio.create_task(adapter.run(ctx))
        try:
            await asyncio.wait_for(adapter.connected.wait(), 5)
            await gw.push(
                tool("start", "exec", "c1", args={"command": "ls"}),
                tool("start", "exec", "c2", args={"command": "ls"}),
            )
            await until(
                lambda: any(f["rule_id"] == "openclaw-plugin-bypass" for f in spooled(enrolled, "finding"))
            )
        finally:
            task.cancel()
    calls = [e for e in spooled(enrolled, "event") if e["payload"]["kind"] == "tool.call"]
    assert [e["payload"]["call_id"] for e in calls] == ["c2"]  # c1 was the plugin's, not judged twice
    assert calls[0]["labels"]["sga_plugin"] == "missing"


def test_evaluate_cli_degraded_path(enrolled: Sensor, monkeypatch, capsys) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(req("c9", command="rm -rf /"))))
    assert sensor_main(["--home", str(enrolled.home.root), "evaluate", "--user", "alice"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["decision"] == "block"
    ev = next(e for e in spooled(enrolled, "event") if e["payload"]["call_id"] == "c9")
    assert ev["labels"]["sga_verdict"] == "degraded"


def test_evaluate_cli_without_cache_says_so(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(req("c9"))))
    assert sensor_main(["--home", str(tmp_path / "none"), "evaluate"]) == 3
    assert json.loads(capsys.readouterr().out)["ok"] is False


def _node_ok() -> bool:
    node = shutil.which("node")
    if not node:
        return False
    major, minor = (
        int(x) for x in subprocess.check_output([node, "--version"], text=True).strip("v\n").split(".")[:2]
    )
    return (major, minor) >= (22, 18)  # type stripping on by default


@pytest.mark.skipif(not _node_ok(), reason="needs Node >= 22.18 for the TypeScript plugin")
async def test_real_plugin_code_against_real_daemon(api) -> None:
    """The plugin's own decide() (TypeScript, run by Node) asking this daemon's socket."""
    _, path = api
    script = f"""
import {{ decide, settingsFrom, socketAsk, cliAsk }} from {json.dumps(str(PLUGIN_DIR / "policy.ts"))};
const s = settingsFrom({{ socketPath: {json.dumps(str(path))}, sensorCli: "/nonexistent" }});
const deps = {{ askDaemon: socketAsk(s.socketPath, 2000), askCli: cliAsk(s.sensorCli, undefined, 1000) }};
const ev = (id, cmd) => ({{ toolName: "exec", toolCallId: id, params: {{ command: cmd }} }});
const ctx = {{ agentId: "main", sessionKey: "agent:main:main" }};
const a = await decide(ev("n1", "rm -rf ~/projects"), ctx, s, deps);
const b = await decide(ev("n2", "ls -la"), ctx, s, deps);
console.log(JSON.stringify({{ a: a.result, aSource: a.source, b: b.result ?? null }}));
"""
    proc = await asyncio.create_subprocess_exec(
        "node",
        "--input-type=module",
        "-e",
        script,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out, err = await asyncio.wait_for(proc.communicate(), 20)
    assert proc.returncode == 0, err.decode()
    res = json.loads(out.decode().strip().splitlines()[-1])
    assert res["aSource"] == "daemon" and res["a"]["block"] is True
    assert res["b"] is None


async def test_plugin_judgement_arriving_after_the_tool_start_is_not_a_bypass(enrolled: Sensor) -> None:
    """Seen live: the gateway broadcast session.tool start in the same instant the plugin asked us.
    The adapter must wait briefly instead of judging the call itself and flagging a bypass."""
    from websockets.asyncio.server import serve

    from sg_advance.sensor.adapters.openclaw import OpenClawAdapter
    from test_openclaw_adapter import FakeGateway, tool

    gw = FakeGateway()
    ctx = AdapterContext(enrolled, "alice")
    ctx.plugins.touch()
    async with serve(gw.handler, "127.0.0.1", 0) as srv:
        url = f"ws://127.0.0.1:{srv.sockets[0].getsockname()[1]}"
        adapter = OpenClawAdapter(url, token="gw-token", enforce=False, plugin_grace=2.0)
        task = asyncio.create_task(adapter.run(ctx))
        try:
            await asyncio.wait_for(adapter.connected.wait(), 5)
            await gw.push(tool("start", "exec", "late", args={"command": "rm -rf ~/x"}))
            await asyncio.sleep(0.3)
            ctx.plugins.mark("late")  # the plugin's request lands a moment later
            await asyncio.sleep(0.5)
        finally:
            task.cancel()
    calls = [e for e in spooled(enrolled, "event") if e["payload"]["kind"] == "tool.call"]
    assert calls == []  # not judged twice, not flagged
    assert not [f for f in spooled(enrolled, "finding") if f["rule_id"] == "openclaw-plugin-bypass"]


# ── plugin heartbeat (sticky expectation, lost / recovered) ─────────────────


def test_registry_expectation_is_sticky_and_persisted(tmp_path) -> None:
    from sg_advance.sensor.registry import PluginRegistry

    state = tmp_path / "plugin-state.json"
    r = PluginRegistry(lost_after=150, state_path=state)
    assert not r.active and r.check(now=10_000) is None  # never seen: nothing expected
    r.heartbeat(now=1_000)
    assert r.active
    assert r.check(now=1_100) is None  # within 150 s
    assert r.check(now=1_200) == "lost"
    assert r.check(now=1_300) is None  # reported once per outage
    assert oct(state.stat().st_mode & 0o777) == "0o600"

    restarted = PluginRegistry(lost_after=150, state_path=state)  # daemon restart
    assert restarted.active and restarted.lost_reported  # still expected, outage remembered
    assert restarted.heartbeat(now=2_000) == "recovered"
    assert restarted.check(now=2_100) is None


def test_daemon_reports_lost_heartbeat_as_finding(enrolled: Sensor) -> None:
    from sg_advance.sensor.daemon import Daemon
    from sg_advance.sensor.registry import PluginRegistry

    ctx = AdapterContext(enrolled, "alice", plugins=PluginRegistry(lost_after=150))
    ctx.plugins.heartbeat(now=1_000)
    daemon = Daemon(enrolled, [], ctx)
    assert daemon.check_plugin_health(now=1_100) is None
    assert daemon.check_plugin_health(now=1_200) == "lost"
    ev = next(e for e in spooled(enrolled, "event") if e["payload"]["kind"] == "sensor.health")
    assert ev["payload"]["status"] == "lost" and ev["payload"]["detail"] == "no heartbeat for 200s"
    f = next(f for f in spooled(enrolled, "finding") if f["rule_id"] == "openclaw-plugin-heartbeat-lost")
    assert f["severity"] == "high"


async def test_hello_after_loss_reports_recovery(api, enrolled: Sensor) -> None:
    server, path = api
    server.ctx.plugins.heartbeat()
    server.ctx.plugins.lost_reported = True  # an outage was reported earlier
    await ask(path, {"op": "hello", "plugin": "sg-advance", "version": "0.1.0"})
    statuses = [
        e["payload"]["status"] for e in spooled(enrolled, "event") if e["payload"]["kind"] == "sensor.health"
    ]
    assert statuses == ["recovered"]
    assert not [f for f in spooled(enrolled, "finding") if f["rule_id"] == "openclaw-plugin-heartbeat-lost"]


def test_goodbye_without_successor_is_lost_quickly() -> None:
    """Live 2026-11-11: `plugins disable` unloads the hooks at once, without a gateway restart."""
    from sg_advance.sensor.registry import PluginRegistry

    r = PluginRegistry(lost_after=150, bye_grace=30)
    r.heartbeat(now=1_000)
    r.goodbye(now=1_010)
    assert r.check(now=1_030) is None  # a restart's new instance gets 30 s to say hello
    assert r.check(now=1_041) == "lost"  # far sooner than the 150 s heartbeat timeout


def test_goodbye_then_hello_is_a_restart_not_a_loss() -> None:
    from sg_advance.sensor.registry import PluginRegistry

    r = PluginRegistry(lost_after=150, bye_grace=30)
    r.heartbeat(now=1_000)
    r.goodbye(now=1_010)
    assert r.heartbeat(now=1_015) is None  # no "recovered": nothing was reported
    assert r.check(now=1_100) is None


async def test_bye_op_and_daemon_detail(api, enrolled: Sensor) -> None:
    from sg_advance.sensor.daemon import Daemon

    server, path = api
    server.ctx.plugins.heartbeat()
    assert await ask(path, {"op": "bye", "plugin": "sg-advance", "reason": "disposed"}) == [{"ok": True}]
    assert server.ctx.plugins.bye_at is not None
    daemon = Daemon(enrolled, [], server.ctx)
    assert daemon.check_plugin_health(now=server.ctx.plugins.bye_at + 31) == "lost"
    ev = next(e for e in spooled(enrolled, "event") if e["payload"]["kind"] == "sensor.health")
    assert "unloaded by the gateway" in ev["payload"]["detail"]


# ── standing operation: token file, background service ──────────────────────


def test_gateway_token_file_must_be_private(tmp_path, monkeypatch) -> None:
    from sg_advance.sensor import SensorError, SensorHome
    from sg_advance.sensor.cli import _openclaw_token

    monkeypatch.delenv("OPENCLAW_GATEWAY_TOKEN", raising=False)
    home = SensorHome(tmp_path)
    assert _openclaw_token(home, None) == ""
    f = tmp_path / "openclaw-token"
    f.write_text("gw-secret\n")
    f.chmod(0o644)
    with pytest.raises(SensorError, match="chmod 600"):
        _openclaw_token(home, None)
    f.chmod(0o600)
    assert _openclaw_token(home, None) == "gw-secret"
    monkeypatch.setenv("OPENCLAW_GATEWAY_TOKEN", "from-env")
    assert _openclaw_token(home, None) == "from-env"


def test_service_definition_keeps_secrets_out(tmp_path) -> None:
    import plistlib

    from sg_advance.sensor.service import launchd_plist, systemd_unit

    doc = plistlib.loads(
        launchd_plist(
            tmp_path, ["--user", "alice", "--openclaw", "ws://127.0.0.1:18789"], exe="/v/bin/sga-sensor"
        )
    )
    assert doc["ProgramArguments"] == [
        "/v/bin/sga-sensor",
        "--home",
        str(tmp_path),
        "run",
        "--user",
        "alice",
        "--openclaw",
        "ws://127.0.0.1:18789",
    ]
    assert doc["KeepAlive"] is True and doc["RunAtLoad"] is True
    # Only PATH (launchd's default can't find `openclaw`/`node`); the token comes from a 0600 file.
    assert set(doc["EnvironmentVariables"]) == {"PATH"}
    assert "/opt/homebrew/bin" in doc["EnvironmentVariables"]["PATH"].split(":")
    assert "Restart=always" in systemd_unit(tmp_path, ["--openclaw"], exe="/v/bin/sga-sensor")
