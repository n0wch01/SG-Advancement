"""Control Plane API (M3): enrollment, auth, ingest, policy distribution, queries."""

from __future__ import annotations

import json
import shutil
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from agent_sentinel.detect import Engine
from agent_sentinel.detect.cli import load_events
from agent_sentinel.policy import PolicyBundle
from agent_sentinel.redact import redact_event
from agent_sentinel.server import Settings, create_app
from agent_sentinel.server.db import EnrollmentToken, EventRow, utcnow

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples" / "events"
ADMIN = {"Authorization": "Bearer admin-test"}


def make_client(tmp_path: Path, db_url: str = "sqlite://", **kw: Any) -> TestClient:
    rules = tmp_path / "rules"
    if not rules.exists():
        shutil.copytree(ROOT / "rules", rules)
    app = create_app(Settings(db_url=db_url, rules_dir=rules, admin_token="admin-test", **kw))
    return TestClient(app)


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    with make_client(tmp_path) as c:
        yield c


def enrollment_token(client: TestClient, **body: Any) -> str:
    r = client.post("/v1/admin/enrollment-tokens", json=body, headers=ADMIN)
    assert r.status_code == 201, r.text
    return r.json()["token"]


def enroll(client: TestClient, device_id: str | None = "dev-bob") -> dict[str, str]:
    """Returns auth headers for the new device."""
    tok = enrollment_token(client)
    r = client.post(
        "/v1/enroll",
        json={"device_id": device_id, "hostname": "bob-pc", "os": "linux"},
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert r.status_code == 201, r.text
    return {"Authorization": f"Bearer {r.json()['device_token']}"}


def example_events(name: str) -> list[dict[str, Any]]:
    """Parsed like a sensor would: every event gets a fixed event_id before it is shipped.
    (Raw fixture lines have no event_id, so each parse would mint new ids and defeat dedup.)"""
    return [e.model_dump(mode="json") for e in load_events([EXAMPLES / name])]


def event(device_id: str = "dev-bob", **payload: Any) -> dict[str, Any]:
    return {
        "ts": "2026-11-10T02:00:00Z",
        "endpoint": {"device_id": device_id},
        "principal": {"user_id": "bob"},
        "agent": {"type": "claude_code", "session_id": "s1"},
        "source": {"sensor": "claude_code_hook"},
        "payload": payload or {"kind": "session.start"},
    }


# ── enrollment & auth ───────────────────────────────────────────────────────


def test_healthz_needs_no_auth(client: TestClient) -> None:
    r = client.get("/healthz")
    assert r.status_code == 200
    assert len(r.json()["policy_version"]) == 64


def test_admin_routes_require_admin_token(client: TestClient) -> None:
    assert client.get("/v1/admin/devices").status_code == 401
    assert client.get("/v1/admin/devices", headers={"Authorization": "Bearer nope"}).status_code == 401
    device = enroll(client)
    assert client.get("/v1/admin/devices", headers=device).status_code == 401


def test_enrollment_token_is_single_use_by_default(client: TestClient) -> None:
    tok = {"Authorization": f"Bearer {enrollment_token(client)}"}
    assert client.post("/v1/enroll", json={"device_id": "a"}, headers=tok).status_code == 201
    r = client.post("/v1/enroll", json={"device_id": "b"}, headers=tok)
    assert r.status_code == 401
    assert "invalid or expired" in r.json()["detail"]


def test_enrollment_token_max_uses(client: TestClient) -> None:
    tok = {"Authorization": f"Bearer {enrollment_token(client, max_uses=2)}"}
    codes = [client.post("/v1/enroll", json={}, headers=tok).status_code for _ in range(3)]
    assert codes == [201, 201, 401]


def test_expired_enrollment_token_is_rejected(client: TestClient) -> None:
    tok = enrollment_token(client)
    db = client.app.state.db  # type: ignore[attr-defined]
    with next(db.session()) as s:
        et = s.scalars(select(EnrollmentToken)).one()
        et.expires_at = utcnow() - timedelta(seconds=1)
        s.commit()
    r = client.post("/v1/enroll", json={}, headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 401


def test_enroll_generates_id_and_rejects_duplicates(client: TestClient) -> None:
    tok = {"Authorization": f"Bearer {enrollment_token(client, max_uses=3)}"}
    generated = client.post("/v1/enroll", json={}, headers=tok).json()["device_id"]
    assert generated.startswith("dev-")
    assert client.post("/v1/enroll", json={"device_id": "x1"}, headers=tok).status_code == 201
    assert client.post("/v1/enroll", json={"device_id": "x1"}, headers=tok).status_code == 409


def test_enroll_rejects_bad_device_id_and_wrong_token_kind(client: TestClient) -> None:
    tok = {"Authorization": f"Bearer {enrollment_token(client)}"}
    assert client.post("/v1/enroll", json={"device_id": "../etc"}, headers=tok).status_code == 422
    assert client.post("/v1/enroll", json={}, headers=ADMIN).status_code == 401


def test_device_token_is_stored_hashed(client: TestClient) -> None:
    headers = enroll(client)
    raw = headers["Authorization"].removeprefix("Bearer ")
    db = client.app.state.db  # type: ignore[attr-defined]
    with db.engine.connect() as conn:
        dump = "\n".join(str(row) for row in conn.exec_driver_sql("SELECT * FROM devices"))
    assert raw not in dump


def test_sensor_routes_reject_unknown_tokens(client: TestClient) -> None:
    for headers in ({}, ADMIN, {"Authorization": "Bearer sdt_forged"}):
        assert client.get("/v1/policy", headers=headers).status_code == 401
        assert client.post("/v1/events", json={"events": []}, headers=headers).status_code == 401


# ── ingest ──────────────────────────────────────────────────────────────────


def test_ingest_events_is_idempotent(client: TestClient) -> None:
    device = enroll(client)
    events = example_events("claude_code.jsonl")
    r = client.post("/v1/events", json={"events": events}, headers=device)
    assert r.json() == {"accepted": len(events), "duplicates": 0}

    stored = client.get("/v1/admin/events", headers=ADMIN).json()
    assert {e["event_id"] for e in stored} == {e["event_id"] for e in events}
    assert all(e["received_ts"] for e in stored)

    r = client.post("/v1/events", json={"events": events[:2]}, headers=device)
    assert r.json() == {"accepted": 0, "duplicates": 2}


def test_event_without_id_gets_one_but_cannot_be_deduplicated(client: TestClient) -> None:
    device = enroll(client)
    ev = event()
    for _ in range(2):
        client.post("/v1/events", json={"events": [ev]}, headers=device)
    assert len(client.get("/v1/admin/events", headers=ADMIN).json()) == 2


def test_duplicate_within_one_batch_is_counted_once(client: TestClient) -> None:
    device = enroll(client)
    ev = event()
    ev["event_id"] = "e-1"
    r = client.post("/v1/events", json={"events": [ev, ev]}, headers=device)
    assert r.json() == {"accepted": 1, "duplicates": 1}


def test_device_cannot_report_for_another_device(client: TestClient) -> None:
    device = enroll(client, "dev-bob")
    r = client.post("/v1/events", json={"events": [event(), event("dev-alice")]}, headers=device)
    assert r.status_code == 403
    assert "dev-alice" in r.json()["detail"]
    assert client.get("/v1/admin/events", headers=ADMIN).json() == []  # whole batch rejected


def test_server_redacts_again(client: TestClient) -> None:
    device = enroll(client)
    secret = "AKIAABCDEFGHIJKLMNOP"
    ev = event(kind="tool.call", call_id="c1", tool="Bash", arguments={"command": f"echo {secret}"})
    client.post("/v1/events", json={"events": [ev]}, headers=device)
    stored = client.get("/v1/admin/events", headers=ADMIN).json()[0]
    assert secret not in json.dumps(stored)
    assert "[REDACTED:aws-access-key]" in stored["payload"]["arguments"]["command"]


def test_batch_limit(tmp_path: Path) -> None:
    with make_client(tmp_path, max_batch=2) as client:
        device = enroll(client)
        r = client.post("/v1/events", json={"events": [event()] * 3}, headers=device)
        assert r.status_code == 413


def test_invalid_event_is_rejected(client: TestClient) -> None:
    device = enroll(client)
    bad = event()
    bad["payload"] = {"kind": "tool.call"}  # missing call_id / tool
    assert client.post("/v1/events", json={"events": [bad]}, headers=device).status_code == 422


# ── policy ──────────────────────────────────────────────────────────────────


def test_policy_etag_and_device_policy_state(client: TestClient) -> None:
    device = enroll(client)
    before = client.get("/v1/admin/devices", headers=ADMIN).json()[0]
    assert before["policy_current"] is False

    r = client.get("/v1/policy", headers=device)
    assert r.status_code == 200
    bundle = r.json()
    assert r.headers["etag"] == f'"{bundle["version"]}"'
    assert len(bundle["rules"]) == client.get("/v1/admin/policy", headers=ADMIN).json()["rule_count"]

    r = client.get("/v1/policy", headers={**device, "If-None-Match": r.headers["etag"]})
    assert r.status_code == 304
    after = client.get("/v1/admin/devices", headers=ADMIN).json()[0]
    assert after["policy_current"] is True
    assert after["policy_version"] == bundle["version"]


def test_policy_reload(client: TestClient, tmp_path: Path) -> None:
    device = enroll(client)
    v1 = client.get("/v1/policy", headers=device).json()["version"]
    f = tmp_path / "rules" / "tool_misuse.yaml"
    f.write_text(f.read_text("utf-8").replace("severity: high", "severity: critical", 1), "utf-8")

    r = client.post("/v1/admin/policy/reload", headers=ADMIN)
    assert r.status_code == 200
    v2 = r.json()["version"]
    assert v2 != v1
    assert client.get("/v1/admin/devices", headers=ADMIN).json()[0]["policy_current"] is False
    assert client.get("/v1/policy", headers={**device, "If-None-Match": f'"{v1}"'}).status_code == 200


def test_broken_rule_file_keeps_old_policy(client: TestClient, tmp_path: Path) -> None:
    v1 = client.get("/v1/admin/policy", headers=ADMIN).json()["version"]
    (tmp_path / "rules" / "broken.yaml").write_text("version: 1\nrules:\n  - id: Bad Id\n", "utf-8")
    r = client.post("/v1/admin/policy/reload", headers=ADMIN)
    assert r.status_code == 422
    assert "broken.yaml" in r.json()["detail"]
    assert client.get("/v1/admin/policy", headers=ADMIN).json()["version"] == v1


# ── end to end ──────────────────────────────────────────────────────────────


def test_sensor_flow_end_to_end(client: TestClient) -> None:
    """What the M4 sensor will do: enroll → pull policy → detect locally → ship redacted data."""
    device = enroll(client, "dev-bob")
    bundle = PolicyBundle.model_validate(client.get("/v1/policy", headers=device).json())
    engine = Engine(bundle.to_ruleset())

    events = load_events([EXAMPLES / "claude_code.jsonl"])
    findings = [f for v in engine.replay(events) for f in v.findings]
    assert findings, "claude_code.jsonl should trigger rules"

    payload = [redact_event(e).model_dump(mode="json") for e in events]
    assert client.post("/v1/events", json={"events": payload}, headers=device).status_code == 200
    r = client.post(
        "/v1/findings", json={"findings": [f.model_dump(mode="json") for f in findings]}, headers=device
    )
    assert r.json() == {"accepted": len(findings), "duplicates": 0}

    got = client.get("/v1/admin/findings", params={"user_id": "bob"}, headers=ADMIN).json()
    assert {f["rule_id"] for f in got} == {f.rule_id for f in findings}
    high = client.get("/v1/admin/findings", params={"min_severity": "high"}, headers=ADMIN).json()
    assert all(f["severity"] in ("high", "critical") for f in high)
    assert len(high) == sum(1 for f in findings if f.severity.at_least("high"))

    session = events[0].agent.session_id
    timeline = client.get("/v1/admin/events", params={"session_id": session}, headers=ADMIN).json()
    assert [e["ts"] for e in timeline] == sorted((e["ts"] for e in timeline), reverse=True)


def test_data_survives_restart_and_times_stay_utc(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'sentinel.db'}"
    with make_client(tmp_path, db_url=url) as client:
        device = enroll(client)
        client.post("/v1/events", json={"events": [event()]}, headers=device)

    with make_client(tmp_path, db_url=url) as client:
        stored = client.get("/v1/admin/events", headers=ADMIN).json()
        assert len(stored) == 1
        assert stored[0]["ts"].endswith("Z")
        assert client.get("/v1/policy", headers=device).status_code == 200  # device token still valid
        db = client.app.state.db  # type: ignore[attr-defined]
        with next(db.session()) as s:
            row = s.scalars(select(EventRow)).one()
            assert row.ts.tzinfo is not None
