"""OpenClaw baseline watch (M5d): config file → allowlisted config.snapshot → baseline rules."""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any

from sg_advance.sensor import Sensor
from sg_advance.sensor.adapters import AdapterContext
from sg_advance.sensor.adapters.openclaw_config import (
    OpenClawConfigAdapter,
    exec_policies,
    guard_state,
    posture,
    runtime_pins,
)

TOKEN = "gw-secret-token-value"
EMAIL = "someone@example.com"


def base_config(tmp_path: Path) -> dict[str, Any]:
    plugin_dir = tmp_path / "plugin"
    plugin_dir.mkdir(exist_ok=True)
    (plugin_dir / "openclaw.plugin.json").write_text(json.dumps({"id": "sg-advance"}))
    return {
        "gateway": {"port": 18789, "auth": {"mode": "token", "token": TOKEN}},
        "auth": {"profiles": {"openai:setup-1": {"provider": "openai", "mode": "oauth", "email": EMAIL}}},
        "plugins": {
            "entries": {"sg-advance": {"enabled": True, "config": {"sensorHome": "/h"}}, "openai": {}},
            "load": {"paths": [str(plugin_dir)]},
        },
        "agents": {
            "defaults": {
                "model": "openai/gpt-6-astra@openai:setup-1",
                "models": {"openai/gpt-6-astra": {"agentRuntime": {"id": "openclaw"}}},
                "sandbox": {"mode": "all", "workspaceAccess": "rw"},  # company baseline: sandboxed
            },
            "entries": {"main": {"models": {"openai/gpt-6-astra": {"agentRuntime": {"id": "openclaw"}}}}},
        },
    }


def queued(sensor: Sensor, kind: str) -> list[dict[str, Any]]:
    with sqlite3.connect(sensor.spool.path) as db:
        docs = [json.loads(d) for (d,) in db.execute("SELECT doc FROM outbox WHERE kind = ?", (kind,))]
    # Rule hits promote rows to a higher priority, so storage order is not emission order.
    return sorted(docs, key=lambda d: d["ts"])


def write(path: Path, cfg: dict[str, Any]) -> None:
    path.write_text(json.dumps(cfg))
    # mtime granularity can hide two writes in a row; bump it so the watcher sees each write.
    st = path.stat()
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000))


# ── guard plugin ─────────────────────────────────────────────────────────────


def test_guard_enabled_from_entry_and_load_path(tmp_path: Path) -> None:
    assert guard_state(base_config(tmp_path))[0] == "enabled"


def test_guard_disabled_in_every_way_openclaw_allows(tmp_path: Path) -> None:
    cfg = base_config(tmp_path)
    cfg["plugins"]["entries"]["sg-advance"]["enabled"] = False
    assert guard_state(cfg) == ("disabled", "plugins.entries.sg-advance.enabled=false")

    for change in (
        {"enabled": False},  # all plugins off
        {"deny": ["sg-advance"]},
        {"allow": ["openai"]},  # an allowlist that leaves the guard out
    ):
        cfg = base_config(tmp_path)
        cfg["plugins"].update(change)
        assert guard_state(cfg)[0] == "disabled", change


def test_guard_missing_when_nothing_loads_it(tmp_path: Path) -> None:
    cfg = base_config(tmp_path)
    del cfg["plugins"]["entries"]["sg-advance"]
    assert guard_state(cfg)[0] == "enabled"  # still discovered on the load path
    cfg["plugins"]["load"]["paths"] = []
    assert guard_state(cfg)[0] == "missing"


# ── exec and runtimes ────────────────────────────────────────────────────────


def test_exec_policies_global_and_agent_override(tmp_path: Path) -> None:
    cfg = base_config(tmp_path)
    cfg["tools"] = {"exec": {"security": "allowlist", "ask": "on-miss"}, "elevated": {"enabled": False}}
    cfg["agents"]["entries"]["ops"] = {"tools": {"exec": {"security": "full"}}}
    assert exec_policies(cfg) == [
        {"scope": "global", "security": "allowlist", "ask": "on-miss", "elevated": False},
        {"scope": "agent:ops", "security": "full"},
    ]


def test_exec_defaults_leave_fields_unset(tmp_path: Path) -> None:
    assert exec_policies(base_config(tmp_path)) == [{"scope": "global"}]


def test_runtime_precedence_agent_over_default_over_provider(tmp_path: Path) -> None:
    cfg = base_config(tmp_path)
    cfg["agents"]["defaults"]["model"] = {
        "primary": "openai/gpt-6-astra",
        "fallbacks": ["openai/gpt-6.1-sol"],
    }
    cfg["models"] = {
        "providers": {
            "openai": {
                "agentRuntime": {"id": "codex"},
                "models": [{"id": "gpt-6.1-sol", "agentRuntime": {"id": "auto"}}],
            },
            "anthropic": {},
        }
    }
    cfg["agents"]["entries"]["main"]["models"]["openai/gpt-6.1-sol"] = {"agentRuntime": {"id": "openclaw"}}
    cfg["agents"]["entries"]["writer"] = {"model": "anthropic/claude-x"}
    cfg["agents"]["entries"]["coder"] = {"runtime": {"type": "acp"}}
    pins = {(p["scope"], p["model"]): p["runtime"] for p in runtime_pins(cfg)}
    assert pins[("defaults", "openai/gpt-6-astra")] == "openclaw"  # default-agent pin
    assert pins[("defaults", "openai/gpt-6.1-sol")] == "auto"  # provider-model pin beats provider pin
    assert pins[("agent:main", "openai/gpt-6.1-sol")] == "openclaw"  # agent pin wins
    assert pins[("agent:writer", "anthropic/claude-x")] == "default"  # nothing pins it
    assert pins[("agent:coder", "*")] == "acp"  # external harness


def test_snapshot_never_carries_secrets(tmp_path: Path) -> None:
    text = json.dumps(posture(base_config(tmp_path)))
    assert TOKEN not in text
    assert EMAIL not in text
    assert "sensorHome" not in text  # plugin config payloads stay local too


# ── adapter + rules end to end ───────────────────────────────────────────────


def test_watcher_reports_changes_and_baseline_findings(tmp_path: Path, enrolled: Sensor) -> None:
    path = tmp_path / "openclaw.json"
    cfg = base_config(tmp_path)
    write(path, cfg)
    ctx = AdapterContext(enrolled, user_id="alice", hostname="alice-pc")
    watcher = OpenClawConfigAdapter(path)

    assert watcher.poll(ctx) is True  # first look: baseline snapshot
    assert watcher.poll(ctx) is False  # unchanged file

    cfg["gateway"]["auth"]["token"] = "rotated"  # unrelated to the posture
    write(path, cfg)
    assert watcher.poll(ctx) is False
    assert queued(enrolled, "finding") == []

    cfg["plugins"]["entries"]["sg-advance"]["enabled"] = False
    cfg["tools"] = {"exec": {"security": "full"}}
    cfg["agents"]["defaults"]["models"]["openai/gpt-6-astra"]["agentRuntime"]["id"] = "claude-cli"
    write(path, cfg)
    assert watcher.poll(ctx) is True

    events = queued(enrolled, "event")
    assert [e["payload"]["kind"] for e in events] == ["config.snapshot", "config.snapshot"]
    last = events[-1]["payload"]
    assert last["guard_plugin"] == "disabled"
    assert {"guard_plugin", "exec_policies", "runtimes"} <= set(last["changed"])
    assert events[-1]["source"]["sensor"] == "openclaw_config"
    assert TOKEN not in json.dumps(events) and "rotated" not in json.dumps(events)
    rules = {f["rule_id"] for f in queued(enrolled, "finding")}
    assert rules == {
        "openclaw-guard-plugin-disabled",
        "openclaw-exec-policy-unsafe",
        "openclaw-runtime-unapproved",
    }


def test_watcher_survives_a_half_written_file(tmp_path: Path, enrolled: Sensor) -> None:
    path = tmp_path / "openclaw.json"
    path.write_text('{"plugins": ')
    ctx = AdapterContext(enrolled, user_id="alice")
    watcher = OpenClawConfigAdapter(path)
    assert watcher.poll(ctx) is False
    write(path, base_config(tmp_path))
    assert watcher.poll(ctx) is True  # retried once the write completed


def test_missing_config_is_quiet(tmp_path: Path, enrolled: Sensor) -> None:
    watcher = OpenClawConfigAdapter(tmp_path / "nope.json")
    assert watcher.poll(AdapterContext(enrolled, user_id="alice")) is False


def test_sandbox_posture_fills_openclaw_defaults_and_agent_overrides() -> None:
    from sg_advance.sensor.adapters.openclaw_config import sandboxes

    assert sandboxes({}) == [
        {"scope": "defaults", "mode": "off", "mode_source": "default", "elevated_default": "on"}
    ]
    cfg = {
        "agents": {
            "defaults": {
                "sandbox": {"mode": "non-main", "workspaceAccess": "ro", "scope": "session"},
                "elevatedDefault": "ask",
            },
            "entries": {"main": {"workspace": "/w"}, "research": {"sandbox": {"mode": "off"}}},
        }
    }
    assert sandboxes(cfg) == [
        {
            "scope": "defaults",
            "mode": "non-main",
            "mode_source": "set",
            "workspace_access": "ro",
            "scope_kind": "session",
            "elevated_default": "ask",
        },
        {"scope": "agent:research", "mode": "off", "mode_source": "set"},  # main inherits: no row
    ]
