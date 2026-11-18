"""Online task authorization. Capabilities never replace fresh identity and resource checks."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Annotated, Any, Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from ..task_grants import (
    AGENT_PROFILES,
    GrantError,
    TaskClaims,
    relative_path,
    sign_task,
    verify_task,
    within,
)
from . import audit_chain, risk
from .access import actor, identity_for
from .auth import CurrentIdentity, DbSession, require_device
from .db import (
    AgentSessionBinding,
    Device,
    DevicePosture,
    Project,
    RemoteAction,
    TaskGrant,
    User,
    UserToken,
    utcnow,
)
from .policy_admin import policy_for
from .resource_files import permission_for

admin = APIRouter(prefix="/v1/admin/tasks", tags=["task grants"])
sensor = APIRouter(prefix="/v1", tags=["task grants"])
CurrentDevice = Annotated[Device, Depends(require_device)]
MAX_CHAIN = 5


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class GrantIn(Model):
    binding_id: str = Field(min_length=1, max_length=64)
    environment: Literal["development", "test"] = "development"
    agent_profile: Literal["reader", "tester", "coder"] = "coder"
    actions: list[str] = Field(min_length=1, max_length=5)
    paths: list[Annotated[str, Field(min_length=1, max_length=256)]] = Field(min_length=1, max_length=16)
    lifetime_seconds: int = Field(default=900, ge=1, le=3600)
    parent_token: str | None = Field(default=None, max_length=16384)


class Check(Model):
    at: AwareDatetime
    reasons: list[Annotated[str, Field(max_length=300)]] = Field(default_factory=list, max_length=30)


class PostureIn(Model):
    checks: dict[str, Check] = Field(max_length=32)


def denied(code: str) -> None:
    raise HTTPException(403, f"task authorization denied: {code}")


def checked_posture(request: Request, db: Session, device_id: str, now: datetime) -> None:
    settings = request.app.state.settings
    max_age = timedelta(seconds=settings.resource_posture_max_age_seconds)
    row = db.get(DevicePosture, device_id)
    if row is None or now - row.received_at > max_age:
        denied("posture_missing_or_stale")
    assert row is not None
    checks = {key: Check.model_validate(value) for key, value in row.checks.items()}
    if not settings.resource_required_checks or not set(settings.resource_required_checks) <= checks.keys():
        denied("required_posture_check_missing")
    if not checks or any(
        c.reasons or c.at > now + timedelta(seconds=30) or now - c.at > max_age for c in checks.values()
    ):
        denied("posture_degraded_or_stale")


def current_state(request: Request, db: Session, claims: TaskClaims, *, action: str | None = None) -> None:
    """Use an internal, unscoped DB session: user-visible query filters cannot hide a block or risk."""
    now = utcnow()
    user, device = db.get(User, claims.user_id), db.get(Device, claims.device_id)
    project, binding = db.get(Project, claims.project_id), db.get(AgentSessionBinding, claims.binding_id)
    if user is None or user.disabled_at is not None:
        denied("user_disabled")
    if (
        device is None
        or device.revoked_at is not None
        or device.owner_user_id != claims.user_id
        or (device.cert_not_after is not None and device.cert_not_after <= now)
    ):
        denied("device_unavailable")
    if (
        project is None
        or project.disabled_at is not None
        or claims.environment not in project.environments
        or not project.workspace_root
        or request.app.state.settings.resource_root is None
    ):
        denied("project_or_environment_unavailable")
    assert device is not None and user is not None
    if (
        binding is None
        or binding.revoked_at is not None
        or (binding.user_id, binding.device_id, binding.project_id, binding.agent_type, binding.session_id)
        != (claims.user_id, claims.device_id, claims.project_id, claims.agent_type, claims.session_id)
    ):
        denied("session_registration_invalid")
    if claims.policy_version != policy_for(request.app, device.group_name, device.device_id).version:
        denied("policy_changed")
    checked_posture(request, db, device.device_id, now)
    person = risk.scores(db, now, verified_only=True).get(user.user_id)
    if person is not None and person.elevated:
        denied("user_risk_elevated")
    actions = list(
        db.scalars(
            select(RemoteAction)
            .where(
                RemoteAction.device_id == device.device_id,
                RemoteAction.target.in_((claims.session_id, claims.user_id)),
                RemoteAction.action.in_(("block_session", "unblock_session", "block_user", "unblock_user")),
            )
            .order_by(RemoteAction.created_at, RemoteAction.id)
        )
    )
    latest = {}
    for row in actions:
        kind = "session" if row.action.endswith("session") else "user"
        if (kind == "session" and row.target == claims.session_id) or (
            kind == "user" and row.target == claims.user_id
        ):
            latest[kind] = row.action
    if any(value.startswith("block_") for value in latest.values()):
        denied("remote_block")
    if action is not None and (
        action not in claims.actions
        or action not in AGENT_PROFILES[claims.agent_profile]
        or not identity_for(db, user).allows(action, claims.project_id, claims.environment)
    ):
        denied("action_not_authorized")


def online_claims(
    request: Request,
    token: str,
    *,
    device_id: str | None = None,
    action: str | None = None,
    path: str | None = None,
) -> TaskClaims:
    try:
        claims = verify_task(token, request.app.state.signing_key.public_key())
    except GrantError:
        denied("invalid_grant")
        raise AssertionError("unreachable") from None
    if device_id is not None and claims.device_id != device_id:
        denied("wrong_device")
    if path is not None and not any(within(path, prefix) for prefix in claims.paths):
        denied("resource_outside_grant")
    with Session(request.app.state.db.engine) as db:
        seen: set[str] = set()
        current = claims
        child = None
        while True:
            if current.grant_id in seen or len(seen) >= MAX_CHAIN:
                denied("invalid_delegation_chain")
            seen.add(current.grant_id)
            row = db.get(TaskGrant, current.grant_id)
            if (
                row is None
                or row.revoked_at is not None
                or row.expires_at <= utcnow()
                or current.issued_at > utcnow() + timedelta(seconds=30)
                or current.expires_at <= utcnow()
                or row.claims != current.model_dump(mode="json")
                or row.parent_id != current.parent_id
            ):
                denied("grant_expired_revoked_or_unknown")
            assert row is not None
            origin = db.get(UserToken, row.origin_token_id)
            if (
                origin is None
                or origin.user_id != current.user_id
                or origin.revoked_at is not None
                or origin.expires_at <= utcnow()
            ):
                denied("origin_authentication_revoked")
            current_state(request, db, current, action=action)
            if path is not None and not any(within(path, prefix) for prefix in current.paths):
                denied("resource_outside_parent")
            if child is not None and not attenuates(child, current):
                denied("delegation_exceeds_parent")
            if current.parent_id is None:
                break
            parent = db.get(TaskGrant, current.parent_id)
            if parent is None or parent.origin_token_id != row.origin_token_id:
                denied("parent_grant_unknown")
            child, current = current, TaskClaims.model_validate(parent.claims)
    return claims


def attenuates(child: TaskClaims, parent: TaskClaims) -> bool:
    return (
        (child.user_id, child.device_id, child.project_id, child.environment, child.policy_version)
        == (parent.user_id, parent.device_id, parent.project_id, parent.environment, parent.policy_version)
        and child.expires_at <= parent.expires_at
        and child.issued_at >= parent.issued_at
        and set(child.actions) <= set(parent.actions)
        and all(any(within(path, p) for p in parent.paths) for path in child.paths)
    )


def issue(
    request: Request,
    body: GrantIn,
    *,
    user_id: str,
    origin_token_id: str | None,
    device_id: str | None = None,
) -> dict[str, Any]:
    parent = online_claims(request, body.parent_token, device_id=device_id) if body.parent_token else None
    with Session(request.app.state.db.engine) as db:
        binding = db.get(AgentSessionBinding, body.binding_id)
        if binding is None or binding.user_id != user_id or (device_id and binding.device_id != device_id):
            denied("session_not_owned")
        assert binding is not None
        device = db.get(Device, binding.device_id)
        if device is None:
            denied("device_unavailable")
        assert device is not None
        if not set(body.actions) <= AGENT_PROFILES[body.agent_profile]:
            denied("agent_profile_scope")
        try:
            paths = tuple(sorted({relative_path(p) for p in body.paths}))
            for path in paths:
                permission_for(path, write=False)
        except GrantError:
            denied("invalid_resource_path")
            raise AssertionError("unreachable") from None
        now = utcnow()
        expiry = now + timedelta(seconds=body.lifetime_seconds)
        if parent is not None:
            expiry = min(expiry, parent.expires_at)
            parent_row = db.get(TaskGrant, parent.grant_id)
            assert parent_row is not None
            origin_token_id = parent_row.origin_token_id
            cursor, depth = parent_row, 1
            while cursor.parent_id:
                depth += 1
                cursor = db.get(TaskGrant, cursor.parent_id)
                assert cursor is not None
            if depth >= MAX_CHAIN:
                denied("delegation_depth_limit")
        if origin_token_id is None:
            denied("personal_authentication_required")
        claims = TaskClaims(
            grant_id=uuid4().hex,
            user_id=user_id,
            device_id=device.device_id,
            binding_id=binding.binding_id,
            agent_type=binding.agent_type,
            session_id=binding.session_id,
            project_id=binding.project_id,
            environment=body.environment,
            agent_profile=body.agent_profile,
            actions=tuple(sorted(set(body.actions))),
            paths=paths,
            issued_at=now,
            expires_at=expiry,
            policy_version=policy_for(request.app, device.group_name, device.device_id).version,
            parent_id=parent.grant_id if parent else None,
        )
        if parent is not None and not attenuates(claims, parent):
            denied("delegation_exceeds_parent")
        for action in claims.actions:
            current_state(request, db, claims, action=action)
            if parent is not None:
                online_claims(request, body.parent_token or "", action=action)
        origin = db.get(UserToken, origin_token_id)
        if origin is None or origin.user_id != user_id or origin.revoked_at or origin.expires_at <= now:
            denied("origin_authentication_revoked")
        db.add(
            TaskGrant(
                grant_id=claims.grant_id,
                user_id=user_id,
                device_id=device.device_id,
                project_id=claims.project_id,
                binding_id=claims.binding_id,
                origin_token_id=origin_token_id,
                parent_id=claims.parent_id,
                claims=claims.model_dump(mode="json"),
                expires_at=claims.expires_at,
            )
        )
        audit_chain.append(
            db,
            "task_grant",
            claims.grant_id,
            {"actor": user_id, "action": "issue", "claims": claims.model_dump(mode="json")},
        )
        db.commit()
    return {
        "grant_id": claims.grant_id,
        "claims": claims.model_dump(mode="json"),
        "token": sign_task(claims, request.app.state.signing_key),
        "revoked_at": None,
    }


@admin.post("", status_code=201)
def issue_task(body: GrantIn, request: Request, identity: CurrentIdentity) -> dict[str, Any]:
    return issue(request, body, user_id=identity.user_id, origin_token_id=request.state.user_token_id)


@admin.get("")
def list_tasks(db: DbSession, identity: CurrentIdentity) -> list[dict[str, Any]]:
    q = select(TaskGrant)
    if not identity.allows("identity.manage") and not identity.allows("activity.read"):
        q = q.where(
            or_(
                TaskGrant.user_id == identity.user_id,
                TaskGrant.project_id.in_(identity.scope("activity.read") or ()),
            )
        )
    return [
        {"grant_id": g.grant_id, "claims": g.claims, "revoked_at": g.revoked_at}
        for g in db.scalars(q.order_by(TaskGrant.created_at.desc()))
    ]


@admin.delete("/{grant_id}")
def revoke_task(grant_id: str, request: Request, db: DbSession, identity: CurrentIdentity) -> dict[str, bool]:
    row = db.get(TaskGrant, grant_id)
    if row is None or not (
        row.user_id == identity.user_id
        or identity.allows("identity.manage")
        or identity.allows("response.manage", row.project_id)
    ):
        raise HTTPException(404, "task grant not found")
    row.revoked_at = utcnow()
    audit_chain.append(db, "task_grant", row.grant_id, {"actor": actor(request), "action": "revoke"})
    db.commit()
    return {"revoked": True}


@sensor.post("/tasks/delegate", status_code=201)
def delegate_task(body: GrantIn, request: Request, device: CurrentDevice) -> dict[str, Any]:
    if not body.parent_token:
        denied("parent_grant_required")
    parent = online_claims(request, body.parent_token or "", device_id=device.device_id)
    return issue(request, body, user_id=parent.user_id, origin_token_id=None, device_id=device.device_id)


@sensor.post("/posture")
def report_posture(body: PostureIn, device: CurrentDevice, db: DbSession) -> dict[str, bool]:
    now = utcnow()
    if any(c.at > now + timedelta(seconds=30) for c in body.checks.values()):
        raise HTTPException(422, "future posture timestamp")
    row = db.get(DevicePosture, device.device_id)
    if row is None:
        row = DevicePosture(device_id=device.device_id, checks={}, received_at=now)
        db.add(row)
    row.checks, row.received_at = body.model_dump(mode="json")["checks"], now
    device.last_seen = now
    db.commit()
    return {"accepted": True}
