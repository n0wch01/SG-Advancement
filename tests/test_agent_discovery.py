"""Agent install discovery (M5d): personal OpenClaw installs are found and judged managed or not."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from sg_advance.sensor import Sensor
from sg_advance.sensor.adapters import AdapterContext
from sg_advance.sensor.adapters.agent_discovery import (
    AgentDiscoveryAdapter,
    find_services,
    install_source,
    scan,
)


def fake_code(root: Path, version: str = "2026.11.3") -> Path:
    """A global npm install plus a bin dir whose ``openclaw`` links into it."""
    pkg = root / "lib/node_modules/openclaw"
    pkg.mkdir(parents=True)
    (pkg / "package.json").write_text(json.dumps({"name": "openclaw", "version": version}))
    (pkg / "openclaw.mjs").write_text("#!/usr/bin/env node\n")
    (pkg / "openclaw.mjs").chmod(0o755)
    bin_dir = root / "bin"
    bin_dir.mkdir()
    (bin_dir / "openclaw").symlink_to(pkg / "openclaw.mjs")
    return bin_dir


def fake_instance(home: Path, name: str = ".openclaw", cfg: dict[str, Any] | str | None = None) -> Path:
    d = home / name
    d.mkdir(parents=True)
    body = cfg if isinstance(cfg, str) else json.dumps(cfg or {})
    (d / "openclaw.json").write_text(body)
    return d / "openclaw.json"


GUARDED = {"plugins": {"entries": {"sg-advance": {"enabled": True}}}, "gateway": {"bind": "loopback"}}


def up(_host: str, _port: int) -> bool:
    return True


def down(_host: str, _port: int) -> bool:
    return False


def test_personal_install_without_controls_is_unmanaged(tmp_path) -> None:
    home = tmp_path / "home"
    bin_dir = fake_code(tmp_path / "brew")
    fake_instance(home, cfg={"gateway": {"bind": "lan", "port": 19001, "auth": {"token": "s3cret"}}})
    agents = home / "Library/LaunchAgents"
    agents.mkdir(parents=True)
    (agents / "ai.openclaw.gateway.plist").write_text("")
    (agents / "com.example.other.plist").write_text("")
    probed: list[int] = []
    [row] = scan(
        home, path_env=str(bin_dir), probe=lambda h, p: probed.append(p) or True, platform="darwin", roots=()
    )
    assert row["version"] == "2026.11.3" and row["install_source"] == "npm-global"
    assert row["services"] == ["ai.openclaw.gateway"] and probed == [19001]
    assert row["configured"] and row["running"] and row["bind_scope"] == "network"
    assert row["guard_plugin"] == "missing" and not row["watched"] and not row["managed"]
    assert row["unmanaged_reasons"] == ["guard plugin missing", "no SG-Advance sensor watches this config"]
    assert "s3cret" not in json.dumps(row)  # only allowlisted fields leave the endpoint


def test_guarded_and_watched_install_is_managed_and_profiles_are_separate(tmp_path) -> None:
    home = tmp_path / "home"
    main_cfg = fake_instance(home, cfg=GUARDED)
    fake_instance(home, ".openclaw-dev", cfg=GUARDED)
    (home / ".openclaw.update-captures").mkdir()  # not a profile
    rows = {
        r["instance"]: r for r in scan(home, watched_configs=[main_cfg], path_env="", probe=down, roots=())
    }
    assert set(rows) == {str(home / ".openclaw"), str(home / ".openclaw-dev")}
    main, dev = rows[str(home / ".openclaw")], rows[str(home / ".openclaw-dev")]
    assert main["managed"] and main["bind_scope"] == "loopback" and main["running"] is False
    assert not dev["managed"] and dev["unmanaged_reasons"] == ["no SG-Advance sensor watches this config"]


def test_code_without_config_and_unreadable_config(tmp_path) -> None:
    bin_dir = fake_code(tmp_path / "img")
    [row] = scan(tmp_path / "empty-home", path_env=str(bin_dir), probe=up, roots=())
    assert row["configured"] is False and row["managed"] is False and row["running"] is False
    assert row["instance"].endswith("lib/node_modules/openclaw")

    home = tmp_path / "home"
    fake_instance(home, cfg="{ gateway: { bind: 'lan' } }  // JSON5 hand edit")
    [row] = scan(home, path_env="", probe=down, roots=())
    assert row["guard_plugin"] is None and "config unreadable" in row["unmanaged_reasons"]
    assert scan(tmp_path / "nothing", path_env="", probe=down, roots=()) == []


def test_sources_and_systemd_units(tmp_path) -> None:
    assert install_source(Path("/home/u/.nvm/versions/node/v24/lib/node_modules/openclaw")) == "nvm"
    assert install_source(Path("/home/u/.local/share/pnpm/global/5/node_modules/openclaw")) == "pnpm"
    assert install_source(Path("/app")) == "app"
    units = tmp_path / ".config/systemd/user"
    units.mkdir(parents=True)
    (units / "openclaw-gateway.service").write_text("")
    assert find_services(tmp_path, platform="linux") == ["openclaw-gateway"]


def install_events(sensor: Sensor) -> list[dict[str, Any]]:
    with sqlite3.connect(sensor.spool.path) as db:
        docs = [
            json.loads(d) for (d,) in db.execute("SELECT doc FROM outbox WHERE kind = 'event' ORDER BY rowid")
        ]
    return [d for d in docs if d["payload"]["kind"] == "install.snapshot"]


def findings(sensor: Sensor) -> list[str]:
    with sqlite3.connect(sensor.spool.path) as db:
        docs = [json.loads(d) for (d,) in db.execute("SELECT doc FROM outbox WHERE kind = 'finding'")]
    return [d["rule_id"] for d in docs]


def test_adapter_emits_on_change_only_and_reports_removal(enrolled: Sensor, tmp_path) -> None:
    home = tmp_path / "home"
    cfg = fake_instance(home, cfg={"gateway": {"bind": "lan"}})
    adapter = AgentDiscoveryAdapter(home=home, path_env="", probe=up, roots=())
    ctx = AdapterContext(enrolled, user_id="carol", hostname="carol-pc")
    assert adapter.poll(ctx) == 1
    assert adapter.poll(ctx) == 0  # nothing changed
    assert sorted(findings(enrolled)) == ["openclaw-gateway-network-exposed", "openclaw-unmanaged-install"]

    cfg.write_text(json.dumps(GUARDED))  # carol adds the plugin and closes the port; still unwatched
    assert adapter.poll(ctx) == 1
    ev = install_events(enrolled)[-1]
    assert {"bind", "bind_scope", "guard_plugin", "unmanaged_reasons"} <= set(ev["payload"]["changed"])
    assert ev["source"]["sensor"] == "agent_discovery" and ev["principal"]["user_id"] == "carol"

    adapter.watched_configs = [cfg]  # the company sensor now watches it
    assert adapter.poll(ctx) == 1 and install_events(enrolled)[-1]["payload"]["managed"] is True

    (cfg.parent / "openclaw.json").unlink()
    assert adapter.poll(ctx) == 1
    gone = install_events(enrolled)[-1]["payload"]
    assert gone["present"] is False and gone["changed"] == ["present"]
    # First sight only: adding the plugin left it unmanaged (still unwatched), so no repeat (2026-11-13).
    assert findings(enrolled).count("openclaw-unmanaged-install") == 1


# ── Windows (M12) ───────────────────────────────────────────────────────────


def test_windows_npm_install_task_and_startup_launcher_are_found(tmp_path: Path) -> None:
    home = tmp_path / "gamer"
    pkg = home / "AppData/Roaming/npm/node_modules/openclaw"  # npm's global prefix on Windows
    pkg.mkdir(parents=True)
    (pkg / "package.json").write_text(json.dumps({"name": "openclaw", "version": "2026.11.3"}))
    fake_instance(home, cfg=GUARDED)
    startup = home / "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
    startup.mkdir(parents=True)
    (startup / "OpenClaw Gateway.cmd").write_text("@echo off\n")
    (startup / "other.lnk").write_text("")

    def tasks() -> list[str]:
        return ["OpenClaw Gateway", "Microsoft\\Windows\\Defrag", "GoogleUpdate"]

    assert find_services(home, "win32", tasks) == ["OpenClaw Gateway"]
    rows = scan(home, path_env="", probe=up, platform="linux", roots=())
    [row] = rows
    assert row["version"] == "2026.11.3" and row["install_source"] == "npm-global"
    assert install_source(home / "AppData/Roaming/nvm/v22.12.0/node_modules/openclaw") == "nvm"
