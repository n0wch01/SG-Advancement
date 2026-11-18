"""Personal identity, default-deny API permissions and cross-project disclosure regressions."""

from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest
from fastapi import Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from conftest import CP_ADMIN
from sg_advance.schema import AgentEvent
from sg_advance.server.auth import require_admin
from sg_advance.server.db import AuditEntry, EventRow, UserToken, utcnow

PREFIX = "/v1/admin/rbac"


def post(cp, path, body, headers=CP_ADMIN, expected=201):
    response = cp.post(PREFIX + path, json=body, headers=headers)
    assert response.status_code == expected, response.text
    return response.json()


def person(cp, name, role=None, project=None):
    post(cp, "/users", {"id": name, "name": name.title()})
    if role:
        bind(cp, name, role, project)
    token = post(cp, f"/users/{name}/tokens", {})
    return {"Authorization": "Bearer " + token["token"]}, token["token_id"]


def bind(cp, user, role, project=None):
    return post(cp, "/bindings", {"user_id": user, "role_id": role, "project_id": project})["binding_id"]


def device(cp, name, user):
    token = cp.post("/v1/admin/enrollment-tokens", headers=CP_ADMIN, json={}).json()["token"]
    response = cp.post("/v1/enroll", headers={"Authorization": "Bearer " + token}, json={"device_id": name})
    assert response.status_code == 201, response.text
    headers = {"Authorization": "Bearer " + response.json()["device_token"]}
    response = cp.put(PREFIX + f"/devices/{name}/owner", headers=CP_ADMIN, json={"user_id": user})
    assert response.status_code == 200, response.text
    return headers


def session(cp, headers, device_id, project, session_id="shared", agent="codex_cli"):
    return post(
        cp,
        "/sessions",
        {"device_id": device_id, "agent_type": agent, "session_id": session_id, "project_id": project},
        headers,
    )["binding_id"]


def ingest(cp, device_headers, device_id, session_id="shared", **changes):
    doc = AgentEvent.model_validate(
        {
            "event_id": uuid4().hex,
            "ts": utcnow().isoformat(),
            "endpoint": {"device_id": device_id},
            "principal": {"user_id": "spoofed-administrator", "groups": ["security_admin"]},
            "agent": {"type": "codex_cli", "session_id": session_id},
            "source": {"sensor": "codex_cli_hook"},
            "labels": {"sga_project_id": "forged-project", "sga_verified_user": "forged-user"},
            "payload": {
                "kind": "tool.call",
                "call_id": uuid4().hex,
                "tool": "Bash",
                "arguments": {"command": "echo hello"},
            },
            **changes,
        }
    ).model_dump(mode="json")
    response = cp.post("/v1/events", headers=device_headers, json={"events": [doc]})
    assert response.status_code == 200, response.text
    finding = {
        "finding_id": uuid4().hex,
        "ts": doc["ts"],
        "rule_id": "scope-test",
        "severity": "high",
        "category": "tool_misuse",
        "title": "Scoped finding",
        "principal": doc["principal"],
        "agent": doc["agent"],
        "endpoint": doc["endpoint"],
        "evidence_event_ids": [doc["event_id"]],
        "labels": doc["labels"],
    }
    response = cp.post("/v1/findings", headers=device_headers, json={"findings": [finding]})
    assert response.status_code == 200, response.text
    return doc, finding


@pytest.fixture
def scoped(cp):
    for project in ("alpha", "beta"):
        post(cp, "/projects", {"id": project, "name": project})
    alice, _ = person(cp, "alice", "developer", "alpha")
    bob, _ = person(cp, "bob", "qa", "beta")
    sensor_a, sensor_b = device(cp, "device-a", "alice"), device(cp, "device-b", "bob")
    session(cp, alice, "device-a", "alpha")
    session(cp, bob, "device-b", "beta")
    return alice, bob, sensor_a, sensor_b


def test_personal_tokens_are_hashed_expire_revoke_and_disable_immediately(cp):
    headers, token_id = person(cp, "alice")
    who = cp.get("/v1/admin/whoami", headers=headers)
    assert who.status_code == 200 and who.json()["user_id"] == "alice"
    assert who.json()["permissions"] == []
    with Session(cp.app.state.db.engine) as db:
        row = db.get(UserToken, token_id)
        assert row.token_hash != headers["Authorization"].removeprefix("Bearer ")
        row.expires_at = utcnow() - timedelta(seconds=1)
        db.commit()
    assert cp.get("/v1/admin/whoami", headers=headers).status_code == 401
    issued = post(cp, "/users/alice/tokens", {})
    fresh = {"Authorization": "Bearer " + issued["token"]}
    assert cp.delete(PREFIX + "/tokens/" + issued["token_id"], headers=fresh).status_code == 200
    assert cp.get("/v1/admin/whoami", headers=fresh).status_code == 401
    issued = post(cp, "/users/alice/tokens", {})
    fresh = {"Authorization": "Bearer " + issued["token"]}
    assert (
        cp.put(PREFIX + "/users/alice/enabled", headers=CP_ADMIN, json={"enabled": False}).status_code == 200
    )
    assert cp.get("/v1/admin/whoami", headers=fresh).status_code == 401


def test_project_lists_counts_evidence_timeline_and_risk_cannot_disclose_other_scope(cp, scoped):
    alice, bob, sensor_a, sensor_b = scoped
    a, af = ingest(cp, sensor_a, "device-a")
    b, bf = ingest(cp, sensor_b, "device-b")
    old, oldf = ingest(cp, sensor_a, "device-a", "unregistered")
    for path, key, expected in (
        ("events", "event_id", a["event_id"]),
        ("findings", "finding_id", af["finding_id"]),
    ):
        rows = cp.get("/v1/admin/" + path, headers=alice).json()
        assert [r[key] for r in rows] == [expected]
        assert rows[0]["principal"]["user_id"] == "alice"
        assert rows[0]["principal"]["groups"] == []
        assert rows[0]["labels"]["sga_project_id"] == "alpha"
    summary = cp.get("/v1/admin/summary", headers=alice).json()
    assert summary["events"]["total"] == summary["findings"]["total"] == 1
    assert summary["findings"]["top_users"][0]["user_id"] == "alice"
    for finding in (bf, oldf):
        assert cp.get("/v1/admin/findings/" + finding["finding_id"], headers=alice).status_code == 404
    timeline = cp.get("/v1/admin/timeline", headers=alice, params={"session_id": "shared"}).json()
    assert [e["event_id"] for e in timeline["events"]] == [a["event_id"]]
    assert [f["finding_id"] for f in timeline["findings"]] == [af["finding_id"]]
    assert [r["user_id"] for r in cp.get("/v1/admin/risk", headers=alice).json()] == ["alice"]
    assert cp.get("/v1/admin/events", headers=alice, params={"device_id": "device-b"}).json() == []
    assert len(cp.get("/v1/admin/events", headers=CP_ADMIN).json()) == 3
    # A valid same-project finding cannot turn foreign evidence IDs into a read capability.
    forged = dict(
        af, finding_id=uuid4().hex, evidence_event_ids=[a["event_id"], b["event_id"], old["event_id"]]
    )
    assert cp.post("/v1/findings", headers=sensor_a, json={"findings": [forged]}).status_code == 200
    detail = cp.get("/v1/admin/findings/" + forged["finding_id"], headers=alice).json()
    assert [e["event_id"] for e in detail["evidence"]] == [a["event_id"]]
    with Session(cp.app.state.db.engine) as db:
        assert db.get(EventRow, old["event_id"]).project_id is None


def test_identity_and_security_permissions_are_separate_and_actors_cannot_be_forged(cp, scoped):
    alice, _, _, _ = scoped
    security, _ = person(cp, "security", "security_admin")
    admin, _ = person(cp, "identity-admin", "identity_admin")
    for headers in (alice, security):
        assert cp.get(PREFIX, headers=headers).status_code == 403
    assert cp.get("/v1/admin/events", headers=admin).status_code == 403
    assert cp.get("/v1/admin/policy", headers=admin).status_code == 403
    assert cp.get("/v1/admin/policy", headers=security).status_code == 200
    body = {"name": "restricted", "by": "forged-superuser", "reason": "regression"}
    response = cp.post("/v1/admin/policy/groups", headers=security, json=body)
    assert response.status_code == 201, response.text
    changes = cp.get("/v1/admin/policy/changes", headers=security).json()
    assert changes[0]["actor"] == "security"
    with Session(cp.app.state.db.engine) as db:
        docs = [r.doc for r in db.scalars(select(AuditEntry).where(AuditEntry.kind == "identity"))]
        assert not any("sut_" in str(d) for d in docs)


def test_registered_scope_is_immutable_and_client_claims_cannot_register_other_humans_or_projects(cp, scoped):
    alice, _, _, _ = scoped
    body = {"device_id": "device-a", "agent_type": "codex_cli", "session_id": "new", "project_id": "beta"}
    assert cp.post(PREFIX + "/sessions", headers=alice, json=body).status_code == 403
    body.update(project_id="alpha", user_id="bob")
    assert cp.post(PREFIX + "/sessions", headers=alice, json=body).status_code == 403
    body.update(user_id="alice", session_id="shared")
    assert cp.post(PREFIX + "/sessions", headers=alice, json=body).status_code == 409
    assert cp.get("/v1/admin/policy", headers=alice).status_code == 403
    assert cp.get("/v1/admin/audit/chain", headers=alice).status_code == 403
    assert cp.post("/v1/admin/policy/reload", headers=alice).status_code == 403


def test_team_membership_and_binding_revocation_take_effect_on_next_request(cp, scoped):
    _, _, sensor_a, _ = scoped
    ingest(cp, sensor_a, "device-a")
    reader, _ = person(cp, "reader")
    post(cp, "/teams", {"id": "qa-team", "name": "QA"})
    response = cp.put(PREFIX + "/teams/qa-team/members/reader", headers=CP_ADMIN, json={"enabled": True})
    assert response.status_code == 200
    binding = post(cp, "/bindings", {"team_id": "qa-team", "role_id": "qa", "project_id": "alpha"})
    assert len(cp.get("/v1/admin/events", headers=reader).json()) == 1
    assert cp.delete(PREFIX + "/bindings/" + binding["binding_id"], headers=CP_ADMIN).status_code == 200
    assert cp.get("/v1/admin/events", headers=reader).status_code == 403
    bind(cp, "reader", "qa", "alpha")
    assert len(cp.get("/v1/admin/events", headers=reader).json()) == 1


def test_unreviewed_new_admin_endpoint_denies_personal_tokens(cp):
    security, _ = person(cp, "security", "security_admin")

    @cp.app.get("/v1/admin/unreviewed", dependencies=[Depends(require_admin)])
    def unreviewed():
        return {"private": "content"}

    assert cp.get("/v1/admin/unreviewed", headers=security).status_code == 403
    assert cp.get("/v1/admin/unreviewed", headers=CP_ADMIN).status_code == 200


def test_approval_counts_metrics_and_indirect_evidence_are_scoped(cp, scoped):
    alice, bob, sensor_a, sensor_b = scoped
    a, af = ingest(cp, sensor_a, "device-a")
    b, bf = ingest(cp, sensor_b, "device-b")
    approved_ids = []
    for device_id, headers, other, foreign_finding in (
        ("device-a", sensor_a, b, bf),
        ("device-b", sensor_b, a, af),
    ):
        approval, _ = ingest(
            cp,
            headers,
            device_id,
            payload={
                "kind": "approval.resolved",
                "call_id": "same-call-id",
                "tool": "Bash",
                "decision": "allow-once",
                "approved": True,
                "max_severity": "high",
                "request_event_id": other["event_id"],
                "finding_ids": [foreign_finding["finding_id"]],
            },
        )
        approved_ids.append(approval["event_id"])
    for headers, expected in ((alice, approved_ids[0]), (bob, approved_ids[1]), (alice, approved_ids[0])):
        rows = cp.get("/v1/admin/approvals", headers=headers).json()
        assert [r["event_id"] for r in rows] == [expected]
        assert rows[0]["held_call"] is None and rows[0]["asked_by"] == []
        assert cp.get("/v1/admin/approvals/review-count", headers=headers).json() == {"pending": 1}
        assert cp.get("/v1/admin/approvals/metrics", headers=headers).json()["user"]["requests"] == 1
    assert cp.get("/v1/admin/approvals/review-count", headers=CP_ADMIN).json() == {"pending": 2}


def test_soc_can_only_block_registered_sessions_in_its_project(cp, scoped):
    _, _, sensor_a, sensor_b = scoped
    _, af = ingest(cp, sensor_a, "device-a")
    _, bf = ingest(cp, sensor_b, "device-b")
    soc, _ = person(cp, "soc", "soc", "alpha")
    body = {
        "device_id": "device-a",
        "target": "shared",
        "action": "block_session",
        "finding_id": af["finding_id"],
        "by": "forged-security",
        "reason": "scope regression",
    }
    response = cp.post("/v1/admin/actions", headers=soc, json=body)
    assert response.status_code == 201, response.text
    assert response.json()["created_by"] == "soc"
    foreign = dict(body, device_id="device-b", finding_id=bf["finding_id"])
    assert cp.post("/v1/admin/actions", headers=soc, json=foreign).status_code == 404
    assert cp.post("/v1/admin/actions", headers=soc, json=dict(body, action="block_user")).status_code == 403
    cp.post("/v1/admin/actions", headers=CP_ADMIN, json=foreign).raise_for_status()
    rows = cp.get("/v1/admin/actions", headers=soc).json()
    assert len(rows) == 1 and rows[0]["device_id"] == "device-a"
    assert cp.get("/v1/admin/inventory", headers=soc).json()[0]["device_id"] == "device-a"


def test_registration_does_not_reclassify_older_records(cp, scoped):
    alice, _, sensor_a, _ = scoped
    before, _ = ingest(cp, sensor_a, "device-a", "later-registration")
    session(cp, alice, "device-a", "alpha", "later-registration")
    after, _ = ingest(cp, sensor_a, "device-a", "later-registration")
    ids = {e["event_id"] for e in cp.get("/v1/admin/events", headers=alice).json()}
    assert after["event_id"] in ids and before["event_id"] not in ids
    assert cp.get(PREFIX + "/owned-devices", headers=alice).json() == [{"device_id": "device-a"}]


def test_editing_a_role_cannot_turn_global_binding_into_unscoped_resource_authority(cp):
    post(cp, "/users", {"id": "custom", "name": "Custom"})
    response = cp.put(
        PREFIX + "/roles/custom-role", headers=CP_ADMIN, json={"permissions": ["activity.read"]}
    )
    assert response.status_code == 200
    bind(cp, "custom", "custom-role")
    response = cp.put(
        PREFIX + "/roles/custom-role",
        headers=CP_ADMIN,
        json={"permissions": ["activity.read", "source.write"]},
    )
    assert response.status_code == 200
    from sg_advance.server.access import identity_for
    from sg_advance.server.db import User

    with Session(cp.app.state.db.engine) as db:
        identity = identity_for(db, db.get(User, "custom"))
        assert not identity.allows("source.write", "alpha", "development")
