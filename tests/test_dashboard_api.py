"""SGA-Dashboard API (M7): read-only dashboard token, overview summary, finding detail, static mount."""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from conftest import CP_ADMIN, ROOT
from sg_advance.sensor import Sensor
from sg_advance.sensor.adapters import ReplayAdapter
from sg_advance.server.app import create_app

VIEWER = {"Authorization": "Bearer view-test"}


@pytest.fixture
def cp_view(cp: TestClient) -> TestClient:
    cp.app.state.settings = dataclasses.replace(cp.app.state.settings, dashboard_token="view-test")
    return cp


def replay(sensor: Sensor, *names: str) -> None:
    for name in names:
        for ev in ReplayAdapter([ROOT / "examples/events" / name]).events():
            sensor.process(ev)
    assert sensor.flush().ok


def test_dashboard_token_reads_but_never_writes(cp_view: TestClient) -> None:
    assert cp_view.get("/v1/admin/whoami", headers=VIEWER).json() == {"role": "viewer"}
    assert cp_view.get("/v1/admin/whoami", headers=CP_ADMIN).json() == {"role": "admin"}
    for path in ("/v1/admin/findings", "/v1/admin/events", "/v1/admin/devices", "/v1/admin/approvals"):
        assert cp_view.get(path, headers=VIEWER).status_code == 200, path
    assert cp_view.get("/v1/admin/manifests", headers=VIEWER).status_code == 200
    r = cp_view.post("/v1/admin/enrollment-tokens", json={}, headers=VIEWER)
    assert r.status_code == 403 and "read-only" in r.text
    assert cp_view.post("/v1/admin/policy/reload", headers=VIEWER).status_code == 403
    r = cp_view.post("/v1/admin/manifests/approve", json={"spec": "x@1"}, headers=VIEWER)
    assert r.status_code == 403
    assert cp_view.get("/v1/admin/findings", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_without_a_configured_dashboard_token_nothing_else_gets_in(cp: TestClient) -> None:
    assert cp.get("/v1/admin/whoami", headers=VIEWER).status_code == 401
    assert cp.get("/v1/admin/whoami").status_code == 401


def test_summary_counts_and_since(cp_view: TestClient, enrolled: Sensor) -> None:
    replay(enrolled, "openclaw_shadow.jsonl", "claude_code.jsonl")
    s = cp_view.get("/v1/admin/summary", headers=VIEWER).json()
    f = s["findings"]
    assert f["total"] == sum(f["by_severity"].values()) > 0
    assert list(f["by_severity"]) == ["critical", "high", "medium", "low", "info"]
    rules = {r["rule_id"]: r for r in f["top_rules"]}
    assert rules["openclaw-unmanaged-install"]["title"] and rules["openclaw-unmanaged-install"]["count"] == 1
    users = [u["user_id"] for u in f["top_users"]]
    assert "carol@corp.test" in users and "alice@corp.test" not in users  # alice's install is managed
    order = ["info", "low", "medium", "high", "critical"]
    ranks = [order.index(u["max_severity"]) for u in f["top_users"]]
    assert ranks == sorted(ranks, reverse=True)  # worst person first
    assert s["events"]["by_kind"]["install.snapshot"] == 2
    assert s["devices"] == {"total": 1, "active": 1, "policy_current": 1}
    assert [d["finding_id"] for d in s["recent"]] == [
        d["finding_id"] for d in cp_view.get("/v1/admin/findings?limit=10", headers=VIEWER).json()
    ]
    later = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    empty = cp_view.get("/v1/admin/summary", params={"since": later}, headers=VIEWER).json()
    assert empty["findings"]["total"] == 0 and empty["recent"] == [] and empty["events"]["total"] == 0


def test_finding_detail_has_evidence_and_the_conversation(cp_view: TestClient, enrolled: Sensor) -> None:
    replay(enrolled, "claude_code.jsonl")
    findings = cp_view.get("/v1/admin/findings", headers=VIEWER).json()
    target = next(f for f in findings if f["evidence_event_ids"])
    d = cp_view.get(f"/v1/admin/findings/{target['finding_id']}", headers=VIEWER).json()
    assert d["finding"]["finding_id"] == target["finding_id"]
    assert [e["event_id"] for e in d["evidence"]] == list(target["evidence_event_ids"])
    ids = [e["event_id"] for e in d["session_events"]]
    assert target["evidence_event_ids"][-1] in ids
    ts = [e["ts"] for e in d["session_events"]]
    assert ts == sorted(ts)  # oldest first, up to the finding
    assert all(e["agent"]["session_id"] == target["agent"]["session_id"] for e in d["session_events"])
    assert target["finding_id"] not in [x["finding_id"] for x in d["session_findings"]]
    assert cp_view.get("/v1/admin/findings/nope", headers=VIEWER).status_code == 404


def test_built_dashboard_is_served_with_strict_headers(cp: TestClient, tmp_path) -> None:
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<!doctype html><title>SGA-Dashboard</title>")
    (dist / "assets" / "app.js").write_text("console.log(1)")
    settings = dataclasses.replace(cp.app.state.settings, dashboard_dir=dist)
    with TestClient(create_app(settings)) as c:
        r = c.get("/dashboard/")
        assert r.status_code == 200 and "SGA-Dashboard" in r.text
        assert "default-src 'self'" in r.headers["content-security-policy"]
        assert r.headers["x-content-type-options"] == "nosniff"
        assert c.get("/dashboard/assets/app.js").status_code == 200
        assert c.get("/", follow_redirects=False).headers["location"] == "/dashboard/"
        assert "content-security-policy" not in c.get("/healthz").headers
    with TestClient(create_app(dataclasses.replace(settings, dashboard_dir=tmp_path / "missing"))) as c:
        assert c.get("/dashboard/").status_code == 404  # not built yet: the API still runs
        assert c.get("/healthz").status_code == 200


def test_inventory_keeps_the_latest_snapshot_per_install(cp_view: TestClient, enrolled: Sensor) -> None:
    replay(enrolled, "openclaw_shadow.jsonl", "openclaw_team.jsonl")
    # carol's install changes later: plugin added. Only the newer state should be listed.
    later = next(ReplayAdapter([ROOT / "examples/events/openclaw_shadow.jsonl"]).events())
    p = later.payload.model_copy(update={"guard_plugin": "enabled", "changed": ("guard_plugin",)})
    newer = {"ts": later.ts + timedelta(minutes=5), "payload": p, "event_id": "x1"}
    enrolled.process(later.model_copy(update=newer))
    assert enrolled.flush().ok
    [dev] = cp_view.get("/v1/admin/inventory", headers=VIEWER).json()
    assert dev["device_id"] == "dev-alice" and dev["policy_current"] is True
    installs = {i["payload"]["instance"]: i for i in dev["installs"]}
    assert set(installs) == {"/home/carol/.openclaw", "/Users/alice/.openclaw"}
    assert installs["/home/carol/.openclaw"]["payload"]["guard_plugin"] == "enabled"
    assert installs["/home/carol/.openclaw"]["user_id"] == "carol@corp.test"
    assert [a["payload"]["agent_id"] for a in dev["agents"]] == ["main"]
    assert sum(dev["open_findings"].values()) > 0
    assert cp_view.post("/v1/admin/inventory", headers=VIEWER).status_code in (403, 405)
