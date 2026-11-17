"""Staged rollout and a signed start time (2026-11-16; Microsoft's PolicyPack carries version, effectiveFrom
and priority for the same reason): new rules reach named canary devices first, then everyone, optionally
from one cut-over time. A rules/ file edited on disk reaches nobody until it is staged or reloaded."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from conftest import CP_ADMIN, CP_URL
from sg_advance.policy import PolicyBundle, PolicyVerificationError
from sg_advance.sensor import Sensor, SensorHome, core, enroll
from sg_advance.sensor.core import SyncStatus
from sg_advance.shorthand import build_event

WHO = {"by": "secops@corp.test", "reason": "test"}


def second(cp: TestClient, transport: Any, tmp_path: Path, device: str = "dev-bob") -> Sensor:
    home = SensorHome(tmp_path / device)
    token = cp.post("/v1/admin/enrollment-tokens", json={}, headers=CP_ADMIN).json()["token"]
    enroll(home, CP_URL, token, device_id=device, transport=transport)
    s = Sensor(home, transport=transport)
    s.start()
    return s


def edit_rules(cp: TestClient) -> None:
    """A reviewed change on disk: rm -rf goes from user approval to deny."""
    path = Path(cp.app.state.settings.rules_dir) / "tool_misuse.yaml"  # type: ignore[attr-defined]
    text = path.read_text(encoding="utf-8")
    old = ("    response: require_approval\n"
           "    tags: [\"grade:3-1\", owasp-llm:LLM06]\n    when: {payload.kind: tool.call}\n")  # fmt: skip
    assert text.count(old) == 1
    path.write_text(text.replace(old, old.replace("require_approval", "block")), encoding="utf-8")


def rm_rf(sensor: Sensor) -> str:
    ev = build_event({"kind": "tool.call", "tool": "Bash", "arguments": {"command": "rm -rf ~/projects"}})
    return sensor.evaluate(ev).verdict.action.value


def post(cp: TestClient, path: str, body: dict[str, Any]) -> Any:
    return cp.post(f"/v1/admin/policy/{path}", json=WHO | body, headers=CP_ADMIN)


def test_canaries_first_then_everyone(cp: TestClient, cp_transport: Any, enrolled: Sensor, tmp_path) -> None:
    bob = second(cp, cp_transport, tmp_path)
    edit_rules(cp)
    # A file edited on disk changes nothing by itself, not even when the policy is rebuilt for another reason.
    cp.app.state.refresh_policy()  # type: ignore[attr-defined]
    assert enrolled.sync_policy() is SyncStatus.UNCHANGED and rm_rf(enrolled) == "require_approval"

    r = post(cp, "stage", {"devices": ["dev-alice"]})
    assert r.status_code == 200 and r.json()["staged_devices"] == ["dev-alice"]
    assert enrolled.sync_policy() is SyncStatus.UPDATED and rm_rf(enrolled) == "block"  # the canary
    assert bob.sync_policy() is SyncStatus.UNCHANGED and rm_rf(bob) == "require_approval"  # everyone else
    devices = {d["device_id"]: d for d in cp.get("/v1/admin/devices", headers=CP_ADMIN).json()}
    assert devices["dev-alice"]["policy_current"] and devices["dev-bob"]["policy_current"]  # each has its own

    assert post(cp, "promote", {}).status_code == 200
    assert bob.sync_policy() is SyncStatus.UPDATED and rm_rf(bob) == "block"
    log = [c["action"] for c in cp.get("/v1/admin/policy/changes", headers=CP_ADMIN).json()]
    assert log[:2] == ["rollout.promote", "rollout.stage"]


def test_discard_takes_the_canary_back(cp: TestClient, enrolled: Sensor) -> None:
    edit_rules(cp)
    post(cp, "stage", {"devices": ["dev-alice"]})
    enrolled.sync_policy()
    assert rm_rf(enrolled) == "block"
    assert post(cp, "discard", {}).status_code == 200
    assert enrolled.sync_policy() is SyncStatus.UPDATED and rm_rf(enrolled) == "require_approval"


def test_one_start_time_for_every_device(cp: TestClient, enrolled: Sensor, monkeypatch) -> None:
    edit_rules(cp)
    post(cp, "stage", {"devices": ["dev-alice"]})
    start = core.now_utc() + timedelta(hours=1)
    post(cp, "promote", {"effective_from": start.isoformat()})
    assert enrolled.sync_policy() is SyncStatus.SCHEDULED and rm_rf(enrolled) == "require_approval"
    later = start + timedelta(seconds=1)
    monkeypatch.setattr(core, "now_utc", lambda: later)
    assert enrolled.sync_policy() is SyncStatus.UPDATED and rm_rf(enrolled) == "block"


def test_the_start_time_is_signed(cp: TestClient) -> None:
    bundle = cp.app.state.policy  # type: ignore[attr-defined]
    key = cp.app.state.signing_key.public_key()  # type: ignore[attr-defined]
    timed = PolicyBundle.from_docs([dict(r) for r in bundle.rules], [], core.now_utc()).signed(
        cp.app.state.signing_key  # type: ignore[attr-defined]
    )
    timed.verify(key)
    later = timed.effective_from + timedelta(days=1)  # type: ignore[operator]
    moved = timed.model_copy(update={"effective_from": later})
    with pytest.raises(PolicyVerificationError):
        moved.verify(key)


def test_guards(cp: TestClient, enrolled: Sensor) -> None:
    assert post(cp, "stage", {"devices": ["nope"]}).status_code == 404
    assert post(cp, "promote", {}).status_code == 409 and post(cp, "discard", {}).status_code == 409
    post(cp, "stage", {"devices": ["dev-alice"]})
    assert post(cp, "stage", {"devices": ["dev-alice"]}).status_code == 409  # one rollout at a time
    assert cp.post("/v1/admin/policy/reload", headers=CP_ADMIN).status_code == 409
    viewer = cp.post("/v1/admin/policy/stage", json=WHO | {"devices": ["dev-alice"]})
    assert viewer.status_code in (401, 403)


def test_a_bundle_without_a_start_time_looks_as_before(cp: TestClient, enrolled: Sensor) -> None:
    """Older sensors forbid unknown fields: the served bundle has no effective_from key unless one is set."""
    token = json.loads(enrolled.home.credentials_path.read_text())["device_token"]
    r = cp.get("/v1/policy", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200 and "effective_from" not in r.json()
