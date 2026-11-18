"""Identity administration and explicit user/device/session project registration."""

from __future__ import annotations

from datetime import timedelta
from typing import Annotated, Any
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import or_, select

from ..authorization import GLOBAL_ONLY, PERMISSIONS, RESOURCE_PERMISSIONS
from ..schema import AgentType
from . import audit_chain
from .access import actor, identity_for, require_permission
from .auth import USER_PREFIX, CurrentIdentity, DbSession, hash_token, new_token
from .db import (
    AgentSessionBinding,
    Device,
    Project,
    Role,
    RoleBinding,
    Team,
    TeamMember,
    User,
    UserToken,
    utcnow,
)

router = APIRouter(prefix="/v1/admin/rbac", tags=["identity"])
Id = Annotated[str, Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,99}$")]


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Named(Model):
    id: Id
    name: str = Field(min_length=1, max_length=200)


class ProjectIn(Named):
    workspace_root: str | None = Field(default=None, max_length=1000)
    environments: list[str] = Field(default_factory=lambda: ["development", "test"], max_length=10)


class TokenIn(Model):
    lifetime_seconds: int = Field(default=8 * 3600, ge=60, le=30 * 86400)


class Enabled(Model):
    enabled: bool


class PermissionsIn(Model):
    permissions: list[str]


class BindingIn(Model):
    role_id: Id
    user_id: Id | None = None
    team_id: Id | None = None
    project_id: Id | None = None
    environment: str = Field(default="development", min_length=1, max_length=40)

    @model_validator(mode="after")
    def one_subject(self) -> BindingIn:
        if (self.user_id is None) == (self.team_id is None):
            raise ValueError("exactly one user_id or team_id is required")
        return self


class OwnerIn(Model):
    user_id: Id


class SessionIn(Model):
    device_id: str = Field(min_length=1, max_length=100)
    agent_type: AgentType
    session_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")
    project_id: Id
    user_id: Id | None = None


def need(db: Any, model: Any, key: Any) -> Any:
    row = db.get(model, key)
    if row is None:
        raise HTTPException(404, "record not found")
    return row


def record(request: Request, db: Any, action: str, target: str, detail: dict[str, Any]) -> None:
    audit_chain.append(
        db,
        "identity",
        uuid4().hex,
        {
            "actor": actor(request),
            "action": action,
            "target": target,
            "detail": detail,
            "at": utcnow(),
        },
    )
    db.commit()


@router.get("")
def administration(request: Request, db: DbSession, identity: CurrentIdentity) -> dict[str, Any]:
    require_permission(request, "identity.manage")
    return {
        "users": [
            {"user_id": u.user_id, "display_name": u.display_name, "disabled_at": u.disabled_at}
            for u in db.scalars(select(User).order_by(User.user_id))
        ],
        "teams": [{"team_id": t.team_id, "name": t.name} for t in db.scalars(select(Team))],
        "memberships": [{"user_id": m.user_id, "team_id": m.team_id} for m in db.scalars(select(TeamMember))],
        "roles": [{"role_id": r.role_id, "permissions": r.permissions} for r in db.scalars(select(Role))],
        "bindings": [
            {
                "binding_id": b.binding_id,
                "user_id": b.user_id,
                "team_id": b.team_id,
                "role_id": b.role_id,
                "project_id": b.project_id,
                "environment": b.environment,
            }
            for b in db.scalars(select(RoleBinding).where(RoleBinding.revoked_at.is_(None)))
        ],
        "tokens": [
            {
                "token_id": t.token_id,
                "user_id": t.user_id,
                "expires_at": t.expires_at,
                "revoked_at": t.revoked_at,
            }
            for t in db.scalars(select(UserToken))
        ],
        "devices": [
            {"device_id": d.device_id, "owner_user_id": d.owner_user_id} for d in db.scalars(select(Device))
        ],
        "permissions": sorted(PERMISSIONS),
    }


@router.post("/users", status_code=201)
def create_user(body: Named, request: Request, db: DbSession, identity: CurrentIdentity) -> dict[str, str]:
    require_permission(request, "identity.manage")
    if db.get(User, body.id):
        raise HTTPException(409, "user already exists")
    db.add(User(user_id=body.id, display_name=body.name))
    record(request, db, "user.create", body.id, {"name": body.name})
    return {"user_id": body.id}


@router.post("/users/{user_id}/tokens", status_code=201)
def issue_token(
    user_id: str, body: TokenIn, request: Request, db: DbSession, identity: CurrentIdentity
) -> dict[str, Any]:
    require_permission(request, "identity.manage")
    user = need(db, User, user_id)
    if user.disabled_at is not None:
        raise HTTPException(409, "user disabled")
    token, token_id = new_token(USER_PREFIX), uuid4().hex
    expires = utcnow() + timedelta(seconds=body.lifetime_seconds)
    db.add(UserToken(token_id=token_id, user_id=user_id, token_hash=hash_token(token), expires_at=expires))
    record(request, db, "token.issue", token_id, {"user_id": user_id, "expires_at": expires})
    return {"token_id": token_id, "token": token, "expires_at": expires}


@router.delete("/tokens/{token_id}")
def revoke_token(
    token_id: str, request: Request, db: DbSession, identity: CurrentIdentity
) -> dict[str, bool]:
    token = need(db, UserToken, token_id)
    if token.user_id != identity.user_id:
        require_permission(request, "identity.manage")
    token.revoked_at = utcnow()
    record(request, db, "token.revoke", token_id, {})
    return {"revoked": True}


@router.put("/users/{user_id}/enabled")
def enable_user(
    user_id: str, body: Enabled, request: Request, db: DbSession, identity: CurrentIdentity
) -> dict[str, bool]:
    require_permission(request, "identity.manage")
    user = need(db, User, user_id)
    user.disabled_at = None if body.enabled else utcnow()
    if not body.enabled:
        for binding in db.scalars(select(AgentSessionBinding).where(AgentSessionBinding.user_id == user_id)):
            binding.revoked_at = utcnow()
    record(request, db, "user.enabled", user_id, {"enabled": body.enabled})
    return {"enabled": body.enabled}


@router.post("/teams", status_code=201)
def create_team(body: Named, request: Request, db: DbSession, identity: CurrentIdentity) -> dict[str, str]:
    require_permission(request, "identity.manage")
    if db.get(Team, body.id):
        raise HTTPException(409, "team already exists")
    db.add(Team(team_id=body.id, name=body.name))
    record(request, db, "team.create", body.id, {"name": body.name})
    return {"team_id": body.id}


@router.put("/teams/{team_id}/members/{user_id}")
def membership(
    team_id: str, user_id: str, body: Enabled, request: Request, db: DbSession, identity: CurrentIdentity
) -> dict[str, bool]:
    require_permission(request, "identity.manage")
    need(db, Team, team_id)
    need(db, User, user_id)
    row = db.get(TeamMember, (team_id, user_id))
    if body.enabled and row is None:
        db.add(TeamMember(team_id=team_id, user_id=user_id))
    if not body.enabled and row is not None:
        db.delete(row)
    record(request, db, "team.membership", team_id, {"user_id": user_id, "enabled": body.enabled})
    return {"enabled": body.enabled}


@router.put("/roles/{role_id}")
def set_role(
    role_id: Id, body: PermissionsIn, request: Request, db: DbSession, identity: CurrentIdentity
) -> dict[str, str]:
    require_permission(request, "identity.manage")
    if set(body.permissions) - PERMISSIONS:
        raise HTTPException(422, "unknown permission")
    role = db.get(Role, role_id)
    if role is None:
        role = Role(role_id=role_id, permissions=[])
        db.add(role)
    role.permissions = sorted(set(body.permissions))
    record(request, db, "role.set", role_id, {"permissions": role.permissions})
    return {"role_id": role_id}


@router.post("/bindings", status_code=201)
def create_binding(
    body: BindingIn, request: Request, db: DbSession, identity: CurrentIdentity
) -> dict[str, str]:
    require_permission(request, "identity.manage")
    role = need(db, Role, body.role_id)
    need(db, User if body.user_id else Team, body.user_id or body.team_id)
    if body.project_id:
        project = need(db, Project, body.project_id)
        if project.disabled_at is not None or body.environment not in project.environments:
            raise HTTPException(422, "inactive project or environment outside project limits")
        if set(role.permissions) & GLOBAL_ONLY:
            raise HTTPException(422, "this role includes global control-plane permissions")
    elif set(role.permissions) & RESOURCE_PERMISSIONS:
        raise HTTPException(422, "resource permissions require an explicit project")
    key = uuid4().hex
    db.add(RoleBinding(binding_id=key, **body.model_dump()))
    record(request, db, "binding.create", key, body.model_dump())
    return {"binding_id": key}


@router.delete("/bindings/{binding_id}")
def revoke_binding(
    binding_id: str, request: Request, db: DbSession, identity: CurrentIdentity
) -> dict[str, bool]:
    require_permission(request, "identity.manage")
    need(db, RoleBinding, binding_id).revoked_at = utcnow()
    record(request, db, "binding.revoke", binding_id, {})
    return {"revoked": True}


@router.get("/projects")
def list_projects(db: DbSession, identity: CurrentIdentity) -> list[dict[str, Any]]:
    visible = {a.project_id for a in identity.assignments if a.project_id is not None}
    q = select(Project)
    if not identity.allows("identity.manage") and not identity.allows("activity.read"):
        q = q.where(Project.project_id.in_(visible))
    return [
        {
            "project_id": p.project_id,
            "name": p.name,
            "environments": p.environments,
            "disabled_at": p.disabled_at,
        }
        for p in db.scalars(q.order_by(Project.project_id))
    ]


@router.post("/projects", status_code=201)
def create_project(
    body: ProjectIn, request: Request, db: DbSession, identity: CurrentIdentity
) -> dict[str, str]:
    require_permission(request, "identity.manage")
    if db.get(Project, body.id):
        raise HTTPException(409, "project already exists")
    if not body.environments or any(
        e not in {"development", "test", "production"} for e in body.environments
    ):
        raise HTTPException(422, "invalid environment limits")
    if body.workspace_root:
        from pathlib import Path

        root = Path(body.workspace_root)
        if not root.is_absolute() or not root.is_dir():
            raise HTTPException(422, "workspace_root must be an existing absolute server-side directory")
        allowed = request.app.state.settings.resource_root
        if (
            allowed is None
            or root.is_symlink()
            or not root.resolve().is_relative_to(allowed.resolve())
            or root.resolve() == allowed.resolve()
        ):
            raise HTTPException(
                422, "workspace_root must be a dedicated child of configured SGA_RESOURCE_ROOT"
            )
    db.add(
        Project(
            project_id=body.id,
            name=body.name,
            workspace_root=body.workspace_root,
            environments=sorted(set(body.environments)),
        )
    )
    record(request, db, "project.create", body.id, {"name": body.name, "environments": body.environments})
    return {"project_id": body.id}


@router.put("/devices/{device_id}/owner")
def assign_owner(
    device_id: str, body: OwnerIn, request: Request, db: DbSession, identity: CurrentIdentity
) -> dict[str, str]:
    require_permission(request, "identity.manage")
    need(db, User, body.user_id)
    device = need(db, Device, device_id)
    if device.owner_user_id != body.user_id:
        for binding in db.scalars(
            select(AgentSessionBinding).where(AgentSessionBinding.device_id == device_id)
        ):
            binding.revoked_at = utcnow()
    device.owner_user_id = body.user_id
    record(request, db, "device.identity_owner", device_id, {"user_id": body.user_id})
    return {"device_id": device_id, "owner_user_id": body.user_id}


@router.get("/sessions")
def list_sessions(db: DbSession, identity: CurrentIdentity) -> list[dict[str, Any]]:
    q = select(AgentSessionBinding)
    if not identity.allows("identity.manage") and not identity.allows("activity.read"):
        q = q.where(
            or_(
                AgentSessionBinding.user_id == identity.user_id,
                AgentSessionBinding.project_id.in_(identity.scope("activity.read") or ()),
            )
        )
    return [
        {
            "binding_id": b.binding_id,
            "device_id": b.device_id,
            "agent_type": b.agent_type,
            "session_id": b.session_id,
            "project_id": b.project_id,
            "user_id": b.user_id,
            "revoked_at": b.revoked_at,
        }
        for b in db.scalars(q.order_by(AgentSessionBinding.created_at.desc()))
    ]


@router.get("/owned-devices")
def owned_devices(db: DbSession, identity: CurrentIdentity) -> list[dict[str, str]]:
    return [
        {"device_id": d.device_id}
        for d in db.scalars(
            select(Device).where(Device.owner_user_id == identity.user_id, Device.revoked_at.is_(None))
        )
    ]


@router.post("/sessions", status_code=201)
def register_session(
    body: SessionIn, request: Request, db: DbSession, identity: CurrentIdentity
) -> dict[str, str]:
    user_id = body.user_id or identity.user_id
    if user_id != identity.user_id:
        require_permission(request, "identity.manage")
    user = need(db, User, user_id)
    device = need(db, Device, body.device_id)
    project = need(db, Project, body.project_id)
    if user.disabled_at or device.revoked_at or project.disabled_at or device.owner_user_id != user_id:
        raise HTTPException(403, "active user, owned device and project registration required")
    if not identity_for(db, user).allows("sessions.register", body.project_id):
        raise HTTPException(403, "user cannot register sessions for this project")
    if body.agent_type not in {AgentType.CLAUDE_CODE, AgentType.CODEX_CLI}:
        raise HTTPException(422, "session registration currently supports Claude Code and Codex CLI")
    existing = db.scalar(
        select(AgentSessionBinding).where(
            AgentSessionBinding.device_id == body.device_id,
            AgentSessionBinding.agent_type == body.agent_type,
            AgentSessionBinding.session_id == body.session_id,
        )
    )
    if existing is not None:
        raise HTTPException(409, "session registration is immutable; use a new agent session")
    key = uuid4().hex
    db.add(
        AgentSessionBinding(
            binding_id=key,
            device_id=body.device_id,
            agent_type=str(body.agent_type),
            session_id=body.session_id,
            project_id=body.project_id,
            user_id=user_id,
        )
    )
    record(request, db, "session.register", key, body.model_dump(mode="json") | {"user_id": user_id})
    return {"binding_id": key}


@router.delete("/sessions/{binding_id}")
def revoke_session(
    binding_id: str, request: Request, db: DbSession, identity: CurrentIdentity
) -> dict[str, bool]:
    binding = need(db, AgentSessionBinding, binding_id)
    if binding.user_id != identity.user_id and not identity.allows("identity.manage"):
        require_permission(request, "response.manage", binding.project_id)
    binding.revoked_at = utcnow()
    record(request, db, "session.revoke", binding_id, {})
    return {"revoked": True}
