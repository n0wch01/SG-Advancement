"""Installed OpenClaw code vs. policy manifests (sensor/adapters/openclaw_integrity.py)."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from sg_advance.integrity import Manifest, dir_digest, openclaw_components
from sg_advance.sensor import Sensor
from sg_advance.sensor.adapters import AdapterContext
from sg_advance.sensor.adapters.openclaw_integrity import OpenClawIntegrityAdapter

FILES = {
    "package.json": '{"name":"openclaw","version":"9.9.9"}',
    "dist/index.js": "core()",
    "dist/extensions/ollama/index.js": "ollama()",
    "dist/extensions/memory-core/index.js": "memory()",
}


def install(tmp: Path) -> Path:
    root = tmp / "node_modules" / "openclaw"
    for rel, text in FILES.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)
    guard = tmp / "guard"
    guard.mkdir()
    (guard / "index.ts").write_text("guard()")
    return root


def listing(root: Path, tmp: Path, extra: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    ext = root / "dist" / "extensions"
    out = [
        {"id": d.name, "origin": "bundled", "rootDir": str(d), "status": "loaded", "enabled": True}
        for d in sorted(ext.iterdir())
    ]
    out.append({"id": "sg-advance", "origin": "config", "rootDir": str(tmp / "guard"), "status": "loaded"})
    out.append({"id": "off", "origin": "bundled", "rootDir": str(ext / "ollama"), "status": "disabled"})
    return out + (extra or [])


def with_manifests(sensor: Sensor, *manifests: Manifest) -> None:
    sensor.policy = sensor.policy.model_copy(
        update={"manifests": tuple(m.model_dump(mode="json") for m in manifests)}
    )


def queued(sensor: Sensor, kind: str) -> list[dict[str, Any]]:
    with sqlite3.connect(sensor.spool.path) as db:
        docs = [json.loads(d) for (d,) in db.execute("SELECT doc FROM outbox WHERE kind = ?", (kind,))]
    return sorted(docs, key=lambda d: d["ts"])


class Recorder:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def __call__(self, plugin_id: str) -> tuple[bool, str]:
        self.calls.append(plugin_id)
        return True, ""


def setup(tmp_path: Path, enrolled: Sensor, status: str = "approved"):
    root = install(tmp_path)
    good = Manifest(package="openclaw", version="9.9.9", status=status, components=openclaw_components(root))
    pin = Manifest(
        package="local:sg-advance",
        version="0.1.0",
        status="approved",
        components={"plugin:sg-advance": dir_digest(tmp_path / "guard")},
    )
    with_manifests(enrolled, good, pin)
    disabler = Recorder()
    adapter = OpenClawIntegrityAdapter(lister=lambda: listing(root, tmp_path), disabler=disabler)
    return root, adapter, disabler, AdapterContext(enrolled, user_id="alice", hostname="alice-pc")


def test_signed_install_is_verified_and_trusted(tmp_path: Path, enrolled: Sensor) -> None:
    _, adapter, disabler, ctx = setup(tmp_path, enrolled)
    assert adapter.scan(ctx) is True
    report = queued(enrolled, "event")[-1]["payload"]
    assert report["version"] == "9.9.9"
    assert report["core"]["integrity"] == "verified" and report["core"]["trust"] == "approved"
    assert {c["component"]: c["integrity"] for c in report["plugins"]} == {
        "plugin:memory-core": "verified",
        "plugin:ollama": "verified",
        "plugin:sg-advance": "verified",  # pinned by the security team
    }  # "off" is disabled: no code runs, nothing to check
    assert enrolled.trusted["openclaw_plugins"] == {"memory-core", "ollama", "sg-advance"}
    assert queued(enrolled, "finding") == [] and disabler.calls == []
    assert adapter.scan(ctx) is False  # unchanged: no new report


def test_tampered_bundled_plugin_is_quarantined(tmp_path: Path, enrolled: Sensor) -> None:
    root, adapter, disabler, ctx = setup(tmp_path, enrolled)
    adapter.scan(ctx)
    (root / "dist/extensions/ollama/index.js").write_text("ollama(); exfiltrate()")
    assert adapter.scan(ctx) is True
    assert disabler.calls == ["ollama"]
    f = next(f for f in queued(enrolled, "finding") if f["rule_id"] == "openclaw-plugin-tampered")
    assert f["severity"] == "critical"
    assert f["response"]["action"] == "quarantine" and f["response"]["enforced"] is True
    assert "ollama" in f["response"]["detail"]
    assert "ollama" not in enrolled.trusted["openclaw_plugins"]  # name rules apply again


def test_folder_dropped_into_extensions_is_a_mismatch(tmp_path: Path, enrolled: Sensor) -> None:
    root, adapter, disabler, ctx = setup(tmp_path, enrolled)
    evil = root / "dist/extensions/helper"
    evil.mkdir()
    (evil / "index.js").write_text("steal()")
    adapter.lister = lambda: listing(root, tmp_path)
    adapter.scan(ctx)
    report = queued(enrolled, "event")[-1]["payload"]
    assert {c["component"]: c["integrity"] for c in report["plugins"]}["plugin:helper"] == "mismatch"
    assert disabler.calls == ["helper"]


def test_guard_plugin_is_never_disabled(tmp_path: Path, enrolled: Sensor) -> None:
    """Defensive: if the guard itself ever reports a mismatch (here: listed from a bundled folder
    that was edited), quarantining it would only remove the control. Report, don't disable."""
    _, adapter, disabler, ctx = setup(tmp_path, enrolled)
    ollama = tmp_path / "node_modules/openclaw/dist/extensions/ollama"
    adapter.lister = lambda: [{"id": "sg-advance", "origin": "bundled", "rootDir": str(ollama)}]
    (ollama / "index.js").write_text("changed")
    adapter.scan(ctx)
    f = next(f for f in queued(enrolled, "finding") if f["rule_id"] == "openclaw-plugin-tampered")
    assert disabler.calls == []
    assert f["response"]["enforced"] is False and "SG-Advance guard" in f["response"]["detail"]


def test_new_version_before_verification_is_pending(tmp_path: Path, enrolled: Sensor) -> None:
    root, adapter, disabler, ctx = setup(tmp_path, enrolled)
    with_manifests(enrolled)  # the server has not verified this version yet
    adapter.scan(ctx)
    report = queued(enrolled, "event")[-1]["payload"]
    assert report["core"]["integrity"] == "pending" and report["core"]["trust"] == "unverified"
    assert {c["integrity"] for c in report["plugins"]} == {"pending", "unknown"}
    assert enrolled.trusted["openclaw_plugins"] == set()
    rules = {f["rule_id"] for f in queued(enrolled, "finding")}
    assert rules == {"openclaw-version-unapproved"} and disabler.calls == []


def test_cooling_release_is_verified_but_not_yet_trusted(tmp_path: Path, enrolled: Sensor) -> None:
    _, adapter, _, ctx = setup(tmp_path, enrolled, status="cooling")
    adapter.scan(ctx)
    assert enrolled.trusted["openclaw_plugins"] == {"sg-advance"}  # only the approved pin
    assert {f["rule_id"] for f in queued(enrolled, "finding")} == {"openclaw-version-unapproved"}


def test_trusted_set_survives_a_sensor_restart(tmp_path: Path, enrolled: Sensor) -> None:
    _, adapter, _, ctx = setup(tmp_path, enrolled)
    adapter.scan(ctx)
    restarted = Sensor(
        enrolled.home, enrolled.client._transport if hasattr(enrolled.client, "_transport") else None
    )
    assert restarted.trusted["openclaw_plugins"] == {"memory-core", "ollama", "sg-advance"}
