"""The DB is the published policy: workers and restarts agree, including staged rollouts."""

from __future__ import annotations

import dataclasses
import shutil
from datetime import datetime, timedelta
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from sg_advance.policy import PolicyBundle
from sg_advance.server import Settings, create_app
from sg_advance.server.db import utcnow

ROOT = Path(__file__).resolve().parents[1]
ADMIN = {"Authorization": "Bearer persistence-test"}
WHO = {"by": "security-test", "reason": "policy persistence regression"}
RULE = "destructive-shell-command"


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    rules = tmp_path / "rules"
    shutil.copytree(ROOT / "rules", rules)
    return Settings(
        db_url=f"sqlite:///{tmp_path / 'cp.db'}",
        rules_dir=rules,
        signing_key_path=tmp_path / "key.pem",
        admin_token="persistence-test",
        auto_verify=False,
    )


def info(client: TestClient) -> dict:
    response = client.get("/v1/admin/policy", headers=ADMIN)
    assert response.status_code == 200
    return response.json()


def edit(settings: Settings) -> None:
    path = settings.rules_dir / "tool_misuse.yaml"
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    next(r for r in doc["rules"] if r["id"] == RULE)["response"] = "block"
    path.write_text(yaml.safe_dump(doc, allow_unicode=True, sort_keys=False), encoding="utf-8")


def enroll(client: TestClient, device: str, group: str | None = None) -> dict:
    response = client.post("/v1/admin/enrollment-tokens", headers=ADMIN, json={"group": group})
    assert response.status_code == 201
    response = client.post(
        "/v1/enroll",
        headers={"Authorization": "Bearer " + response.json()["token"]},
        json={"device_id": device},
    )
    assert response.status_code == 201
    return {"Authorization": "Bearer " + response.json()["device_token"]}


def rollout(client: TestClient, action: str, **body) -> dict:
    response = client.post(f"/v1/admin/policy/{action}", headers=ADMIN, json=WHO | body)
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.parametrize("scope", ["common", "qa"])
def test_overrides_reach_another_worker_and_its_warm_group_cache(settings: Settings, scope: str) -> None:
    with TestClient(create_app(settings)) as first:
        assert (
            first.post("/v1/admin/policy/groups", headers=ADMIN, json=WHO | {"name": "qa"}).status_code == 201
        )
        device = enroll(first, "qa-device", "qa")
        with TestClient(create_app(settings)) as second:
            before = second.get("/v1/policy", headers=device).json()["version"]
            response = first.put(
                "/v1/admin/policy/overrides",
                headers=ADMIN,
                json=WHO
                | {
                    "scope": scope,
                    "rule_id": RULE,
                    "response": "block",
                },
            )
            assert response.status_code == 200
            received = second.get("/v1/policy", headers=device)
            bundle = PolicyBundle.model_validate(received.json())
            bundle.verify(first.app.state.signing_key.public_key())
            assert bundle.version != before
            assert next(r for r in bundle.rules if r["id"] == RULE)["response"] == "block"
            assert bundle.version == first.get("/v1/policy", headers=device).json()["version"]


def test_a_restart_ignores_unpublished_or_broken_rules_files(settings: Settings) -> None:
    with TestClient(create_app(settings)) as first:
        before = info(first)["version"]
    edit(settings)
    with TestClient(create_app(settings)) as restarted:
        assert info(restarted)["version"] == before
    (settings.rules_dir / "tool_misuse.yaml").write_text("not: [valid", encoding="utf-8")
    with TestClient(create_app(settings)) as restarted:
        assert info(restarted)["version"] == before
        assert restarted.post("/v1/admin/policy/reload", headers=ADMIN).status_code == 422
        assert info(restarted)["version"] == before


@pytest.mark.parametrize("finish", ["promote", "discard"])
def test_staging_survives_restart_and_can_be_finished_on_another_worker(
    settings: Settings, finish: str
) -> None:
    with TestClient(create_app(settings)) as first:
        canary = enroll(first, "canary")
        ordinary = enroll(first, "ordinary")
        before = info(first)["version"]
        edit(settings)
        staged = rollout(first, "stage", devices=["canary"])
    with TestClient(create_app(settings)) as restarted, TestClient(create_app(settings)) as other:
        assert restarted.get("/v1/admin/policy/rollout", headers=ADMIN).json() == staged
        assert other.get("/v1/policy", headers=canary).json()["version"] == staged["staged_version"]
        assert other.get("/v1/policy", headers=ordinary).json()["version"] == before
        rollout(restarted, finish)
        expected = staged["staged_version"] if finish == "promote" else before
        assert info(other)["version"] == expected
        assert other.get("/v1/policy", headers=canary).json()["version"] == expected
        assert other.get("/v1/admin/policy/rollout", headers=ADMIN).json()["staged_version"] is None
    with TestClient(create_app(settings)) as restarted:
        assert info(restarted)["version"] == expected


def test_promoted_start_time_survives_restart_for_common_and_group_policies(settings: Settings) -> None:
    start = (utcnow() + timedelta(hours=1)).isoformat()
    with TestClient(create_app(settings)) as first:
        assert (
            first.post("/v1/admin/policy/groups", headers=ADMIN, json=WHO | {"name": "qa"}).status_code == 201
        )
        device = enroll(first, "qa-device", "qa")
        edit(settings)
        rollout(first, "stage", devices=["qa-device"], effective_from=start)
        rollout(first, "promote", effective_from=start)
        before = first.get("/v1/policy", headers=device).json()
    with TestClient(create_app(settings)) as restarted:
        assert restarted.get("/v1/policy", headers=device).json() == before
        assert datetime.fromisoformat(before["effective_from"]) == datetime.fromisoformat(start)
        actual = restarted.get("/v1/admin/policy/rollout", headers=ADMIN).json()["current_effective_from"]
        assert datetime.fromisoformat(actual) == datetime.fromisoformat(start)


def test_explicit_reload_publishes_to_other_workers_and_survives_restart(settings: Settings) -> None:
    with TestClient(create_app(settings)) as first, TestClient(create_app(settings)) as second:
        before = info(second)["version"]
        edit(settings)
        assert info(second)["version"] == before
        response = first.post("/v1/admin/policy/reload", headers=ADMIN)
        assert response.status_code == 200
        after = response.json()["version"]
        assert after != before and info(second)["version"] == after
    with TestClient(create_app(settings)) as restarted:
        assert info(restarted)["version"] == after


def test_another_workers_rules_directory_cannot_override_the_db(settings: Settings, tmp_path: Path) -> None:
    with TestClient(create_app(settings)) as first:
        before = info(first)["version"]
        other_rules = tmp_path / "other-rules"
        shutil.copytree(settings.rules_dir, other_rules)
        other_settings = dataclasses.replace(settings, rules_dir=other_rules)
        edit(other_settings)
        with TestClient(create_app(other_settings)) as other:
            assert info(other)["version"] == before


def test_another_worker_cannot_overwrite_a_rollout_that_changed_during_preparation(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sg_advance.server import policy_admin

    with TestClient(create_app(settings)) as first, TestClient(create_app(settings)) as other:
        enroll(first, "first-canary")
        enroll(first, "other-canary")
        edit(settings)
        read = policy_admin.read_base_docs

        def concurrent_stage(app):
            base = read(app)
            if app is first.app:
                rollout(other, "stage", devices=["other-canary"])
            return base

        monkeypatch.setattr(policy_admin, "read_base_docs", concurrent_stage)
        response = first.post(
            "/v1/admin/policy/stage", headers=ADMIN, json=WHO | {"devices": ["first-canary"]}
        )
        assert response.status_code == 409
        assert "changed" in response.json()["detail"]
        assert first.get("/v1/admin/policy/rollout", headers=ADMIN).json()["staged_devices"] == [
            "other-canary"
        ]
        log = first.get("/v1/admin/policy/changes", headers=ADMIN).json()
        assert [row["action"] for row in log].count("rollout.stage") == 1


def test_manifest_changes_invalidate_other_workers_policy_cache(settings: Settings) -> None:
    with TestClient(create_app(settings)) as first, TestClient(create_app(settings)) as other:
        device = enroll(first, "device")
        before = other.get("/v1/policy", headers=device).json()["version"]
        response = first.post("/v1/admin/manifests/pin", headers=ADMIN, json={
            "plugin_id": "test-plugin", "version": "local", "digest": "a" * 64,
        })
        assert response.status_code == 201
        published = other.get("/v1/policy", headers=device).json()
        assert published["version"] != before
        assert published == first.get("/v1/policy", headers=device).json()
