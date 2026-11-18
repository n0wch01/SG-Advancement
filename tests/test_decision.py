"""The agent-neutral decision path (sensor/decision.py, local_api.py; refactor 2026-11-18).

Claude Code, Codex and the MCP gateway judge through the same functions without any OpenClaw state; the
OpenClaw plugin protocol is an integration that registers its own ops and keeps its own state."""

from __future__ import annotations

import ast
import dataclasses
import json
from pathlib import Path

from sg_advance.sensor import Sensor, hook
from sg_advance.sensor.adapters import AdapterContext
from sg_advance.sensor.adapters.openclaw_state import KEY as OPENCLAW
from sg_advance.sensor.adapters.openclaw_state import openclaw
from sg_advance.sensor.daemon import Daemon
from sg_advance.sensor.decision import CLAUDE_CODE_HOOK, CODEX_CLI_HOOK, MCP_GATEWAY
from sg_advance.sensor.local_api import LocalApiServer
from sg_advance.sensor.plugin_api import OPENCLAW_PLUGIN, openclaw_local_api

ROOT = Path(__file__).resolve().parents[1]
SENSOR = ROOT / "src" / "sg_advance" / "sensor"


def _hook_line(call: str = "t1") -> bytes:
    ev = hook.hook_event({"session_id": "s1", "hook_event_name": "PreToolUse", "tool_name": "Read",
                          "tool_use_id": call, "tool_input": {"file_path": "README.md"}},
                         user_id="bob", hostname="pc")  # fmt: skip
    return json.dumps({"op": "event", "event": ev}).encode()


def test_a_hook_never_creates_or_touches_openclaw_state(enrolled: Sensor, tmp_path: Path) -> None:
    """Before 2026-11-18 every local API request touched the OpenClaw plugin's liveness, so a Claude Code
    hook alone made the sensor expect a plugin and report it "lost" (high alert) 150 s after the last call."""
    ctx = AdapterContext(enrolled, "bob", "pc")
    server = openclaw_local_api(ctx, tmp_path / "s.sock")  # the daemon's server: OpenClaw ops enabled
    assert server.handle(_hook_line())["decision"] == "allow"
    assert OPENCLAW not in ctx.extensions  # a Claude Code / Codex-only PC has no plugin state at all
    daemon = Daemon(enrolled, [], ctx, local_api=server)
    assert daemon.check_plugin_health(now=10_000) is None  # nothing to lose
    # With OpenClaw state present (the daemon always attaches it), hook calls still leave it untouched.
    plugins = openclaw(ctx).plugins
    server.handle(_hook_line("t2"))
    assert plugins.expected is False and plugins.last_contact is None
    assert daemon.check_plugin_health(now=20_000) is None


def test_plugin_ops_exist_only_where_the_integration_registers_them(enrolled: Sensor, tmp_path: Path) -> None:
    ctx = AdapterContext(enrolled, "bob", "pc")
    generic = LocalApiServer(ctx, tmp_path / "g.sock")
    hello = json.dumps({"op": "hello", "plugin": "sg-advance"}).encode()
    assert generic.handle(hello) == {"ok": False, "error": "unknown op 'hello'"}
    assert OPENCLAW not in ctx.extensions
    assert openclaw_local_api(ctx, tmp_path / "o.sock").handle(hello) == {"ok": True}
    assert openclaw(ctx).plugins.expected is True  # the plugin's own hello is what makes it expected


def test_points_are_described_by_capability() -> None:
    """``awaits_answer``: the agent asks the person itself and runs right after (Claude Code, the OpenClaw
    card). The gateway sits in the path; Codex cannot report an answer (user decision: approval = deny)."""
    assert CLAUDE_CODE_HOOK.awaits_answer and OPENCLAW_PLUGIN.awaits_answer
    assert not MCP_GATEWAY.awaits_answer and not CODEX_CLI_HOOK.awaits_answer


def test_the_generic_context_and_decision_path_name_no_product() -> None:
    """The boundary, statically: nothing agent-neutral imports the OpenClaw integration."""
    fields = {f.name: str(f.type) for f in dataclasses.fields(AdapterContext)}
    assert not {"plugins", "people"} & fields.keys()
    assert not any("OpenClaw" in t or "PluginRegistry" in t for t in fields.values())
    for module in ("decision.py", "local_api.py", "approvals.py", "adapters/base.py"):
        tree = ast.parse((SENSOR / module).read_text(encoding="utf-8"))
        imported = {
            (n.module or "") if isinstance(n, ast.ImportFrom) else a.name
            for n in ast.walk(tree)
            if isinstance(n, ast.Import | ast.ImportFrom)
            for a in n.names
        }
        assert not [m for m in imported if "openclaw" in m or "plugin_api" in m or m == "registry"], module
