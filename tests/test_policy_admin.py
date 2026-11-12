"""M9 policy management: groups, layered overrides (team = stricter only), per-group signed bundles,
change log, and sensors in different groups judging the same call differently."""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient

from conftest import CP_ADMIN, CP_URL, CpTransport
from sg_advance.schema import AgentEvent
from sg_advance.sensor import Sensor
from sg_advance.sensor.core import enroll
from sg_advance.sensor.state import SensorHome
from sg_advance.server.policy_layers import COMMON, Override, apply_common, apply_group, check

VIEWER = {"Authorization": "Bearer view-test"}
WHO = {"by": "secops@corp.test", "reason": "test"}


# ── pure layering ───────────────────────────────────────────────────────────

SQL = {"id": "destructive-sql", "response": "require_approval", "enabled": True, "match": {"type": "regex"}}
EGRESS = {
    "id": "egress",
    "response": "alert",
    "enabled": True,
    "match": {"type": "allowlist", "allow": ["a.com", "b.com"]},
}


def test_groups_can_only_tighten() -> None:
    assert check(SQL, "data", Override(response="block")) == []
    assert check(SQL, "data", Override(enabled=True)) == []
    assert "cannot turn a rule off" in check(SQL, "data", Override(enabled=False))[0]
    assert "cannot lower" in check(SQL, "data", Override(response="alert"))[0]
    assert check(EGRESS, "data", Override(allow=("a.com",))) == []
    assert "only narrow" in check(EGRESS, "data", Override(allow=("a.com", "evil.com")))[0]
    assert "not an allowlist rule" in check(SQL, "data", Override(allow=("x",)))[0]
    globbed = {**EGRESS, "match": {"type": "allowlist", "allow": ["*.openai.com", "b.com"]}}
    assert check(globbed, "data", Override(allow=("api.openai.com", "B.com"))) == []  # covered: narrower
    assert check(globbed, "data", Override(allow=("*.com",)))  # a wider glob is not
    assert apply_group([globbed], {"egress": Override(allow=("api.openai.com", "x.com"))})[0]["match"][
        "allow"
    ] == ["api.openai.com"]
    assert "unknown response" in check(SQL, COMMON, Override(response="nuke"))[0]
    assert "nothing to change" in check(SQL, COMMON, Override())[0]
    # Security may loosen the common policy.
    assert check(SQL, COMMON, Override(enabled=False, response="alert")) == []


def test_group_merge_stays_stricter_even_with_stale_overrides() -> None:
    common = apply_common([SQL, EGRESS], {"destructive-sql": Override(response="abort_session")})
    # Written when common was require_approval; common has since gone stricter than the group's value.
    group = apply_group(
        common, {"destructive-sql": Override(response="block"), "egress": Override(allow=("b.com", "zzz"))}
    )
    by_id = {r["id"]: r for r in group}
    assert by_id["destructive-sql"]["response"] == "abort_session"
    assert by_id["egress"]["match"]["allow"] == ["b.com"]  # intersection, never wider
    assert SQL["response"] == "require_approval" and EGRESS["match"]["allow"] == [
        "a.com",
        "b.com",
    ]  # inputs untouched


# ── API, bundles, sensors ───────────────────────────────────────────────────


@pytest.fixture
def cpv(cp: TestClient) -> TestClient:
    cp.app.state.settings = dataclasses.replace(cp.app.state.settings, dashboard_token="view-test")
    return cp


def sensor_in(cp: TestClient, transport: CpTransport, tmp_path, device: str, group: str | None) -> Sensor:
    body: dict[str, Any] = {"group": group} if group else {}
    token = cp.post("/v1/admin/enrollment-tokens", json=body, headers=CP_ADMIN).json()["token"]
    home = SensorHome(tmp_path / device)
    enroll(home, CP_URL, token, device_id=device, transport=transport)
    s = Sensor(home, transport=transport)
    s.start()
    return s


def delete_all() -> AgentEvent:
    return AgentEvent.model_validate(
        {
            "ts": datetime.now(UTC),
            "endpoint": {"device_id": "pending"},
            "principal": {"user_id": "u"},
            "agent": {"type": "openclaw", "session_id": "s"},
            "source": {"sensor": "openclaw_plugin"},
            "payload": {
                "kind": "tool.call",
                "call_id": "c1",
                "tool": "exec",
                "arguments": {"command": "psql -c 'DELETE FROM users;'"},
            },
        }
    )


def action(sensor: Sensor) -> str:
    return sensor.evaluate(delete_all()).verdict.action.value


def test_team_policy_reaches_only_that_teams_sensors(
    cpv: TestClient, cp_transport: CpTransport, tmp_path
) -> None:
    r = cpv.post("/v1/admin/policy/groups", json={"name": "data-team", **WHO}, headers=CP_ADMIN)
    assert r.status_code == 201, r.text
    data = sensor_in(cpv, cp_transport, tmp_path, "data-pc", "data-team")
    other = sensor_in(cpv, cp_transport, tmp_path, "other-pc", None)
    assert action(data) == action(other) == "require_approval"

    r = cpv.put(
        "/v1/admin/policy/overrides",
        json={"scope": "data-team", "rule_id": "destructive-sql", "response": "block", **WHO},
        headers=CP_ADMIN,
    )
    assert r.status_code == 200, r.text
    assert data.sync_policy().value == "updated" and other.sync_policy().value == "unchanged"
    assert action(data) == "block" and action(other) == "require_approval"

    pulled = cp_transport.client.get(
        "/v1/policy", headers={"Authorization": f"Bearer {data.creds.device_token}"}
    )
    assert pulled.headers["x-sga-policy-group"] == "data-team"

    scopes = {s["name"]: s for s in cpv.get("/v1/admin/policy/scopes", headers=VIEWER).json()["scopes"]}
    assert scopes["data-team"]["devices"] == 1 and scopes["data-team"]["overrides"] == 1
    assert scopes[COMMON]["version"] != scopes["data-team"]["version"]
    devices = {d["device_id"]: d for d in cpv.get("/v1/admin/devices", headers=VIEWER).json()}
    assert devices["data-pc"]["group"] == "data-team" and devices["data-pc"]["policy_current"] is True

    # Moving the device back to common: its next pull loosens to the common policy.
    r = cpv.put("/v1/admin/devices/data-pc/group", json={"group": None, **WHO}, headers=CP_ADMIN)
    assert r.status_code == 200
    assert data.sync_policy().value == "updated" and action(data) == "require_approval"


def test_loosening_is_refused_for_teams_but_logged_for_common(cpv: TestClient) -> None:
    cpv.post("/v1/admin/policy/groups", json={"name": "web", **WHO}, headers=CP_ADMIN)
    bad = [
        {"scope": "web", "rule_id": "destructive-sql", "enabled": False},
        {"scope": "web", "rule_id": "destructive-sql", "response": "alert"},
        {"scope": "web", "rule_id": "egress-unapproved-host", "allow": ["evil.example"]},
    ]
    for body in bad:
        r = cpv.put("/v1/admin/policy/overrides", json={**body, **WHO}, headers=CP_ADMIN)
        assert r.status_code == 422, body
    assert (
        cpv.put("/v1/admin/policy/overrides", json={**bad[0]}, headers=CP_ADMIN).status_code == 422
    )  # no by/reason
    assert cpv.put("/v1/admin/policy/overrides", json={**bad[1], **WHO}, headers=VIEWER).status_code == 403

    # Security turns a rule off company-wide: allowed, and the log says who, why, before/after.
    body = {
        "scope": COMMON,
        "rule_id": "exhaustion-keyword-prompt",
        "enabled": False,
        "by": "lead",
        "reason": "noisy",
    }
    r = cpv.put("/v1/admin/policy/overrides", json=body, headers=CP_ADMIN)
    assert r.status_code == 200
    rows = {
        x["id"]: x for x in cpv.get("/v1/admin/policy/rules", params={"scope": "web"}, headers=VIEWER).json()
    }
    row = rows["exhaustion-keyword-prompt"]
    assert row["base"]["enabled"] is True and row["effective"]["enabled"] is False
    assert row["common_override"] == {"enabled": False} and row["group_override"] is None
    # The team turns it back on for itself: stricter, so allowed.
    r = cpv.put(
        "/v1/admin/policy/overrides",
        json={"scope": "web", "rule_id": "exhaustion-keyword-prompt", "enabled": True, **WHO},
        headers=CP_ADMIN,
    )
    assert r.status_code == 200
    rows = {
        x["id"]: x for x in cpv.get("/v1/admin/policy/rules", params={"scope": "web"}, headers=VIEWER).json()
    }
    assert rows["exhaustion-keyword-prompt"]["effective"]["enabled"] is True

    log = cpv.get("/v1/admin/policy/changes", headers=VIEWER).json()
    assert [c["action"] for c in log] == ["override.set", "override.set", "group.create"]
    assert log[1]["actor"] == "lead" and log[1]["reason"] == "noisy" and log[1]["after"] == {"enabled": False}
    assert log[0]["id"] > log[1]["id"] > log[2]["id"]
    assert cpv.get("/v1/admin/policy/scopes", headers=VIEWER).json()["revision"] == log[0]["id"]

    r = cpv.post(
        "/v1/admin/policy/overrides/clear",
        json={"scope": COMMON, "rule_id": "exhaustion-keyword-prompt", **WHO},
        headers=CP_ADMIN,
    )
    assert r.status_code == 200
    assert cpv.get("/v1/admin/policy/changes", headers=VIEWER).json()[0]["before"] == {"enabled": False}


def test_groups_and_tokens_validate(cpv: TestClient) -> None:
    assert (
        cpv.post("/v1/admin/policy/groups", json={"name": "common", **WHO}, headers=CP_ADMIN).status_code
        == 422
    )
    assert (
        cpv.post("/v1/admin/policy/groups", json={"name": "Bad Name", **WHO}, headers=CP_ADMIN).status_code
        == 422
    )
    assert (
        cpv.post("/v1/admin/policy/groups", json={"name": "ok", **WHO}, headers=CP_ADMIN).status_code == 201
    )
    assert (
        cpv.post("/v1/admin/policy/groups", json={"name": "ok", **WHO}, headers=CP_ADMIN).status_code == 409
    )
    assert (
        cpv.post("/v1/admin/enrollment-tokens", json={"group": "nope"}, headers=CP_ADMIN).status_code == 404
    )
    assert cpv.get("/v1/admin/policy/rules", params={"scope": "nope"}, headers=VIEWER).status_code == 404
    r = cpv.put(
        "/v1/admin/policy/overrides",
        json={"scope": COMMON, "rule_id": "no-such-rule", "enabled": False, **WHO},
        headers=CP_ADMIN,
    )
    assert r.status_code == 404


def test_without_overrides_the_bundle_is_the_repository_policy(cp: TestClient) -> None:
    from sg_advance.policy import PolicyBundle

    on_disk = PolicyBundle.load(cp.app.state.settings.rules_dir, list(cp.app.state.policy.manifests))
    assert cp.app.state.policy.version == on_disk.version
