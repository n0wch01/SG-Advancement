"""Protected resources refuse a session whose agent hook never reached the daemon (2026-11-20 user decision).

Found in the live lab: the Codex profile's hook definitions changed and were never re-trusted, so ``codex
exec`` skipped every SG-Advance hook without a warning, while the protected repository accepted the task
grant. The protected-resource gateways now label the grant's session (``sga_hook_coverage``) and the signed
rule ``protected-resource-without-agent-hook`` refuses it before anything goes upstream."""

from __future__ import annotations

import asyncio
import base64
import http.client
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from sg_advance.schema import AgentEvent
from sg_advance.sensor import Sensor
from sg_advance.sensor.adapters.base import AdapterContext
from sg_advance.sensor.adapters.mcp_gateway import McpGatewayAdapter
from sg_advance.sensor.envelope import envelope
from sg_advance.sensor.task_git import GitProxyAdapter
from sg_advance.task_grants import TaskClaims, sign_task
from test_mcp_gateway import FakeMcp, call, rpc, spooled

RULE = "protected-resource-without-agent-hook"


def grant_for(cp, agent: str = "codex_cli", session: str = "thread-1") -> str:
    now = datetime.now(UTC)
    claims = TaskClaims(
        grant_id="g1", user_id="alice", device_id="dev-alice", binding_id="b1", agent_type=agent,
        session_id=session, project_id="alpha", environment="development", agent_profile="coder",
        actions=("source.read", "source.write"), paths=("src",), issued_at=now,
        expires_at=now + timedelta(minutes=15), policy_version="0" * 64,
    )  # fmt: skip
    return sign_task(claims, cp.app.state.signing_key)


def hook_event(sensor: Sensor, agent: str = "codex_cli", session: str = "thread-1") -> None:
    doc = envelope(sensor=f"{agent}_hook", agent={"type": agent, "session_id": session},
                   payload={"kind": "session.start"}, hostname="pc", user_id="alice")  # fmt: skip
    sensor.process(AgentEvent.model_validate(doc))


def test_coverage_follows_the_grant_sessions_own_hook(cp, enrolled: Sensor) -> None:
    token = grant_for(cp)
    assert enrolled.hook_coverage(token) == {"sga_hook_coverage": "missing"}
    hook_event(enrolled, session="another-thread")
    assert enrolled.hook_coverage(token) == {"sga_hook_coverage": "missing"}  # another session's hook
    hook_event(enrolled, agent="claude_code")
    assert enrolled.hook_coverage(token) == {"sga_hook_coverage": "missing"}  # same id, another agent
    hook_event(enrolled)
    assert enrolled.hook_coverage(token) == {"sga_hook_coverage": "seen"}
    assert enrolled.hook_coverage(token[:-4] + "AAAA") == {}  # unverifiable: the control plane refuses it
    assert enrolled.hook_coverage(None) == {}
    # A gateway's own events never count as the agent's hook.
    gateway = envelope(sensor="mcp_proxy", agent={"type": "codex_cli", "session_id": "thread-2"},
                       payload={"kind": "session.start"}, hostname="pc", user_id="alice")  # fmt: skip
    enrolled.process(AgentEvent.model_validate(gateway))
    assert enrolled.hook_coverage(grant_for(cp, session="thread-2")) == {"sga_hook_coverage": "missing"}


async def test_a_protected_mcp_call_without_the_hook_never_reaches_the_resource(cp, enrolled) -> None:
    upstream = FakeMcp(sse=False)
    server = await upstream.start()
    gateway = McpGatewayAdapter(
        "127.0.0.1:0", {"repo": f"http://127.0.0.1:{upstream.port}/mcp"},
        credentials={"repo": "Bearer device-test"}, protected_resources=frozenset({"repo"}),
    )  # fmt: skip
    await gateway.start(AdapterContext(enrolled, "test", "pc"))
    header = f"X-SGA-Task-Grant: {grant_for(cp)}\r\n"
    try:
        _, refused = await rpc(gateway.port, "/mcp/repo", call(2, "read_file", path="src/a.py"), extra=header)
        assert "hook" in refused["result"]["content"][0]["text"] and refused["result"]["isError"] is True
        assert not [m for m in upstream.seen if m.get("method") == "tools/call"]  # nothing reached it
        hook_event(enrolled)
        _, reply = await rpc(gateway.port, "/mcp/repo", call(3, "read_file", path="src/a.py"), extra=header)
        assert "isError" not in reply["result"]
        assert len([m for m in upstream.seen if m.get("method") == "tools/call"]) == 1
    finally:
        await gateway.close()
        server.close()
    findings = [f for f in spooled(enrolled, "finding") if f["rule_id"] == RULE]
    assert len(findings) == 1 and findings[0]["response"]["enforced"] is True


class Upstream(BaseHTTPRequestHandler):
    hits: list[str] = []

    def log_message(self, *_args: object) -> None:
        pass

    def do_GET(self) -> None:
        Upstream.hits.append(self.path)
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()


async def test_a_git_request_without_the_sessions_hook_never_goes_upstream(cp, enrolled) -> None:
    Upstream.hits = []
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    proxy = GitProxyAdapter("127.0.0.1", 0, f"http://127.0.0.1:{upstream.server_port}", "device-test")
    await proxy.start(AdapterContext(enrolled, "test", "pc"))
    auth = "Basic " + base64.b64encode(f"x:{grant_for(cp, 'claude_code', 'cc-1')}".encode()).decode()

    def advertise() -> tuple[int, bytes]:
        conn = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=10)
        try:
            conn.request("GET", "/git/alpha.git/info/refs?service=git-receive-pack",
                         headers={"Authorization": auth})  # fmt: skip
            response = conn.getresponse()
            return response.status, response.read()
        finally:
            conn.close()

    try:
        status, body = await asyncio.to_thread(advertise)
        assert status == 403 and b"hook" in body and Upstream.hits == []
        hook_event(enrolled, "claude_code", "cc-1")
        status, _ = await asyncio.to_thread(advertise)
        assert status == 200 and len(Upstream.hits) == 1
    finally:
        await proxy.close()
        upstream.shutdown()
        upstream.server_close()
    findings = [f for f in spooled(enrolled, "finding") if f["rule_id"] == RULE]
    assert len(findings) == 1 and findings[0]["agent"]["session_id"] == "cc-1"
    assert not [f for f in spooled(enrolled, "finding") if f["rule_id"] == "unapproved-mcp-tool-call"]
    pushes = [e for e in spooled(enrolled, "event") if e["payload"].get("tool") == "git_push"]
    assert len(pushes) == 1  # a covered session's request is judged by the control plane, not twice
