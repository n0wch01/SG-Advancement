"""Package manifests on the control plane (server/manifests.py) and in the signed policy."""

from __future__ import annotations

import shutil
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from conftest import CP_ADMIN, CP_URL, ROOT, CpTransport
from sg_advance.policy import PolicyBundle, load_public_key
from sg_advance.sensor import Sensor, SensorHome, enroll
from sg_advance.server import Settings, create_app
from sg_advance.server.supply import SupplyError, VerifiedPackage
from sg_advance.shorthand import build_event


class FakeVerifier:
    def __init__(self, published_ago: timedelta = timedelta(hours=15)) -> None:
        self.published_ago = published_ago
        self.calls: list[str] = []
        self.fail: dict[str, str] = {}

    def __call__(self, spec: str) -> VerifiedPackage:
        self.calls.append(spec)
        if spec in self.fail:
            raise SupplyError(self.fail[spec])
        name, _, version = spec.rpartition("@")
        return VerifiedPackage(
            package=name,
            version=version,
            integrity="sha512-x",
            published_at=datetime.now(UTC) - self.published_ago,
            source_repo="openclaw/openclaw",
            components={"core": "c" * 64, "plugin:ollama": "o" * 64},
        )


def make_client(tmp_path: Path, verifier: FakeVerifier, cooldown_days: float = 3.0) -> TestClient:
    rules = tmp_path / "cp-rules"
    shutil.copytree(ROOT / "rules", rules)
    settings = Settings(
        # A file DB like production: the verification worker writes from its own thread, which a
        # single shared in-memory connection cannot serve alongside request threads.
        db_url=f"sqlite:///{tmp_path / 'cp.db'}",
        rules_dir=rules,
        admin_token="admin-test",
        signing_key_path=tmp_path / "cp-key.pem",
        release_cooldown_days=cooldown_days,
    )
    return TestClient(create_app(settings, verify_package=verifier))


@pytest.fixture
def verifier() -> FakeVerifier:
    return FakeVerifier()


@pytest.fixture
def cp(tmp_path: Path, verifier: FakeVerifier) -> Iterator[TestClient]:
    with make_client(tmp_path, verifier) as c:
        yield c


def policy(cp: TestClient) -> PolicyBundle:
    pub = cp.get("/v1/admin/policy", headers=CP_ADMIN).json()["public_key"]
    token = cp.post("/v1/admin/enrollment-tokens", json={}, headers=CP_ADMIN).json()["token"]
    dev = cp.post("/v1/enroll", json={}, headers={"Authorization": f"Bearer {token}"}).json()
    bundle = PolicyBundle.model_validate(
        cp.get("/v1/policy", headers={"Authorization": f"Bearer {dev['device_token']}"}).json()
    )
    bundle.verify(load_public_key(pub))  # manifests are covered by the signature
    return bundle


def statuses(bundle: PolicyBundle) -> dict[str, str]:
    return {f"{m['package']}@{m['version']}": m["status"] for m in bundle.manifests}


def admin(cp: TestClient, path: str, body: dict[str, Any]) -> Any:
    r = cp.post(f"/v1/admin/manifests{path}", json=body, headers=CP_ADMIN)
    assert r.status_code < 400, r.text
    return r.json()


def test_add_approve_revoke_flow_reaches_the_signed_policy(cp: TestClient) -> None:
    empty = policy(cp)
    assert empty.manifests == ()

    out = admin(cp, "", {"spec": "openclaw@2026.11.3"})
    assert out["status"] == "cooling" and out["components"] == 2  # released 15 h ago
    p1 = policy(cp)
    assert statuses(p1) == {"openclaw@2026.11.3": "cooling"} and p1.version != empty.version

    assert admin(cp, "/approve", {"spec": "openclaw@2026.11.3", "by": "secops"})["status"] == "approved"
    assert statuses(policy(cp)) == {"openclaw@2026.11.3": "approved"}

    assert admin(cp, "/revoke", {"spec": "openclaw@2026.11.3", "by": "secops"})["status"] == "revoked"
    assert statuses(policy(cp)) == {"openclaw@2026.11.3": "revoked"}


def test_failed_verification_is_shipped_as_rejected(cp: TestClient, verifier: FakeVerifier) -> None:
    verifier.fail["openclaw@6.6.6"] = "provenance does not verify for openclaw/openclaw"
    assert admin(cp, "", {"spec": "openclaw@6.6.6", "approve": True})["status"] == "rejected"
    man = policy(cp).manifests[0]
    assert man["status"] == "rejected" and man["components"] == {}
    r = cp.post("/v1/admin/manifests/approve", json={"spec": "openclaw@6.6.6"}, headers=CP_ADMIN)
    assert r.status_code == 409  # cannot approve what did not verify


def test_pin_in_house_plugin(cp: TestClient) -> None:
    out = admin(
        cp, "/pin", {"plugin_id": "sg-advance", "version": "0.1.0", "digest": "d" * 64, "by": "secops"}
    )
    assert out["status"] == "approved"
    man = policy(cp).manifests[0]
    assert man["package"] == "local:sg-advance" and man["components"] == {"plugin:sg-advance": "d" * 64}


def test_cooldown_end_refreshes_policy_without_an_admin(tmp_path: Path) -> None:
    verifier = FakeVerifier(published_ago=timedelta(0))
    with make_client(tmp_path, verifier, cooldown_days=1.0 / 86400) as cp:  # 1 second
        admin(cp, "", {"spec": "openclaw@1.0.0"})
        assert statuses(policy(cp)) == {"openclaw@1.0.0": "cooling"}
        time.sleep(1.2)
        assert statuses(policy(cp)) == {"openclaw@1.0.0": "trusted"}


def _report(core_version: str, plugins: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    ev = build_event(
        {
            "kind": "integrity.report",
            "product": "openclaw",
            "version": core_version,
            "core": {
                "component": "core",
                "package": "openclaw",
                "version": core_version,
                "digest": "c" * 64,
                "integrity": "pending",
            },
            "plugins": plugins or [],
            "device": "dev-alice",
            "agent": "openclaw",
            "sensor": "openclaw_integrity",
        }
    )
    return ev.model_dump(mode="json")


def _enrolled(cp: TestClient, tmp_path: Path) -> Sensor:
    home = SensorHome(tmp_path / "sensor")
    token = cp.post("/v1/admin/enrollment-tokens", json={}, headers=CP_ADMIN).json()["token"]
    transport = CpTransport(cp)
    enroll(home, CP_URL, token, device_id="dev-alice", transport=transport)
    sensor = Sensor(home, transport=transport)
    sensor.start()
    return sensor


def _wait(cond, timeout: float = 15.0, describe=None) -> None:
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return
        time.sleep(0.05)
    raise AssertionError("condition not met in time" + (f": {describe()}" if describe else ""))


def test_reported_version_is_verified_automatically(
    cp: TestClient, verifier: FakeVerifier, tmp_path: Path
) -> None:
    sensor = _enrolled(cp, tmp_path)
    codex = {
        "component": "plugin:codex",
        "package": "@openclaw/codex",
        "version": "2026.11.3",
        "origin": "global",
        "digest": "x" * 64,
        "integrity": "pending",
    }
    local = {
        "component": "plugin:mine",
        "package": "evil-tools",
        "version": "1",
        "digest": "y" * 64,
        "integrity": "pending",
    }
    from sg_advance.schema import AgentEvent

    sensor.process(AgentEvent.model_validate(_report("2026.11.3", [codex, local])))
    assert sensor.flush().ok
    _wait(lambda: len(verifier.calls) == 2, describe=lambda: f"calls={verifier.calls}")
    # evil-tools has no trusted publisher: never fetched; only a manual pin can vouch for it.
    assert sorted(verifier.calls) == ["@openclaw/codex@2026.11.3", "openclaw@2026.11.3"]
    _wait(
        lambda: len(policy(cp).manifests) == 2,
        describe=lambda: f"manifests={statuses(policy(cp))} queue={cp.app.state.verifying}",
    )
    sensor.sync_policy()
    assert {m["package"] for m in sensor.policy.manifests} == {"openclaw", "@openclaw/codex"}

    sensor.process(AgentEvent.model_validate(_report("2026.11.3")))  # reported again: no re-download
    assert sensor.flush().ok
    time.sleep(0.2)
    assert len(verifier.calls) == 2
