"""Verified control-plane identities, explicit permissions and request-local read scope."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException, Request
from sqlalchemy import event, false, or_, select
from sqlalchemy.orm import Session, with_loader_criteria

from ..authorization import GLOBAL_ONLY, PERMISSIONS, RESOURCE_PERMISSIONS, ROLE_DEFAULTS
from .db import (
    AgentSessionBinding,
    Device,
    EventRow,
    FindingIndicator,
    FindingRow,
    Project,
    RemoteAction,
    Role,
    RoleBinding,
    TeamMember,
    User,
)


@dataclass(frozen=True)
class Assignment:
    role_id: str
    permissions: frozenset[str]
    project_id: str | None
    environment: str


@dataclass(frozen=True)
class Identity:
    user_id: str
    display_name: str
    assignments: tuple[Assignment, ...] = ()
    legacy_role: str | None = None

    def allows(self, permission: str, project_id: str | None = None, environment: str | None = None) -> bool:
        if self.legacy_role == "admin":
            return True
        if self.legacy_role == "viewer":
            return permission in {
                "activity.read",
                "devices.read",
                "policy.read",
                "audit.read",
                "response.read",
            }
        if permission not in PERMISSIONS:
            return False
        return any(
            permission in a.permissions
            and (
                permission not in RESOURCE_PERMISSIONS
                or (a.project_id is not None and project_id is not None)
            )
            and (a.project_id is None or (permission not in GLOBAL_ONLY and a.project_id == project_id))
            and (environment is None or a.environment == environment)
            for a in self.assignments
        )

    def scope(self, permission: str) -> frozenset[str] | None:
        if self.allows(permission):
            return None
        return frozenset(
            a.project_id
            for a in self.assignments
            if a.project_id is not None and self.allows(permission, a.project_id)
        )

    def has_any(self, permission: str) -> bool:
        return self.allows(permission) or bool(self.scope(permission))


def seed_roles(db: Session) -> None:
    for name, permissions in ROLE_DEFAULTS.items():
        if db.get(Role, name) is None:
            db.add(Role(role_id=name, permissions=sorted(permissions)))
    db.commit()


def identity_for(db: Session, user: User) -> Identity:
    teams = select(TeamMember.team_id).where(TeamMember.user_id == user.user_id)
    rows = db.execute(
        select(RoleBinding, Role.permissions)
        .join(Role, Role.role_id == RoleBinding.role_id)
        .where(
            RoleBinding.revoked_at.is_(None),
            or_(RoleBinding.user_id == user.user_id, RoleBinding.team_id.in_(teams)),
        )
    )
    active = set(db.scalars(select(Project.project_id).where(Project.disabled_at.is_(None))))
    assignments = tuple(
        Assignment(r.role_id, frozenset(p) & PERMISSIONS, r.project_id, r.environment)
        for r, p in rows
        if r.project_id is None or r.project_id in active
    )
    return Identity(user.user_id, user.display_name, assignments)


def current(request: Request) -> Identity:
    return request.state.identity


def require_permission(request: Request, permission: str, project_id: str | None = None) -> None:
    if not current(request).allows(permission, project_id):
        raise HTTPException(403, f"permission required: {permission}")


def actor(request: Request) -> str:
    return current(request).user_id


def admin_permission(path: str, method: str) -> str | None:
    """Unknown routes deny personal tokens until their permission/scope has been reviewed."""
    if method in {"GET", "HEAD"}:
        groups = {
            "authenticated": {"/whoami"},
            "activity.read": {
                "/events",
                "/findings",
                "/findings/{finding_id}",
                "/summary",
                "/timeline",
                "/risk",
                "/approvals",
                "/approvals/review-count",
                "/approvals/metrics",
            },
            "devices.read": {"/devices", "/inventory"},
            "devices.manage": {"/enrollment-tokens"},
            "policy.read": {
                "/policy",
                "/policy/scopes",
                "/policy/rules",
                "/policy/changes",
                "/policy/rollout",
                "/manifests",
            },
            "audit.read": {"/audit/chain", "/audit/chain/verify"},
            "response.read": {"/actions"},
        }
    else:
        groups = {
            "policy.write": {
                "/policy/reload",
                "/policy/groups",
                "/devices/{device_id}/group",
                "/policy/overrides",
                "/policy/overrides/clear",
                "/policy/stage",
                "/policy/promote",
                "/policy/discard",
                "/manifests",
                "/manifests/approve",
                "/manifests/revoke",
                "/manifests/skill",
                "/manifests/pin",
            },
            "devices.manage": {
                "/enrollment-tokens",
                "/enrollment-tokens/{token_id}/revoke",
                "/devices/{device_id}/revoke",
                "/devices/{device_id}/owner",
                "/install-command",
            },
            "response.manage": {"/actions"},
            "approvals.review": {"/approvals/{event_id}/review"},
        }
    suffix = path.removeprefix("/v1/admin")
    return next((permission for permission, paths in groups.items() if suffix in paths), None)


def attach_scope(db: Session, identity: Identity) -> None:
    """Apply the same scope to documents, aggregates, nested evidence and campaign queries.

    Sensor ingestion and internal policy sessions do not install this read filter. Scoped admin
    endpoints use ORM statements; Core/text queries are refused rather than silently bypassing it.
    """
    if db.info.get("sga_scope_installed") or identity.legacy_role is not None:
        return
    db.info["sga_scope_installed"] = True
    projects = identity.scope("activity.read")
    responses = identity.scope("response.read")
    criteria: list[Any] = []
    if projects is not None:
        for model in (EventRow, FindingRow):
            criteria.append(with_loader_criteria(model, model.project_id.in_(projects), include_aliases=True))
        ids = select(FindingRow.finding_id).where(FindingRow.project_id.in_(projects))
        criteria.append(
            with_loader_criteria(
                FindingIndicator,
                FindingIndicator.finding_id.in_(ids),
                include_aliases=True,
            )
        )
    if responses is not None:
        criteria.append(
            with_loader_criteria(
                RemoteAction,
                RemoteAction.project_id.in_(responses),
                include_aliases=True,
            )
        )
    if not identity.allows("devices.read") and not identity.allows("devices.manage"):
        visible = identity.scope("devices.read")
        device_ids = select(AgentSessionBinding.device_id).where(
            AgentSessionBinding.project_id.in_(visible or ()),
            AgentSessionBinding.revoked_at.is_(None),
        )
        condition = or_(
            Device.owner_user_id == identity.user_id, Device.device_id.in_(device_ids) if visible else false()
        )
        criteria.append(with_loader_criteria(Device, condition, include_aliases=True))

    def restrict(state: Any) -> None:
        if not state.is_select:
            return
        if not state.is_orm_statement:
            raise HTTPException(403, "scoped reads require an ORM statement")
        state.statement = state.statement.options(*criteria)

    event.listen(db, "do_orm_execute", restrict)


def collection_identity(db: Session, device: Device, doc: Any) -> tuple[Any, str | None, str | None]:
    """Attribution is a server registration, never a client project/role label or historic guess."""
    labels = {
        k: v
        for k, v in doc.labels.items()
        if k not in {"sga_project_id", "sga_verified_user", "sga_identity_source"}
    }
    binding = db.scalar(
        select(AgentSessionBinding).where(
            AgentSessionBinding.device_id == device.device_id,
            AgentSessionBinding.agent_type == str(doc.agent.type),
            AgentSessionBinding.session_id == doc.agent.session_id,
            AgentSessionBinding.revoked_at.is_(None),
        )
    )
    if binding is not None:
        user = db.get(User, binding.user_id)
        project = db.get(Project, binding.project_id)
        if (
            user is not None
            and user.disabled_at is None
            and project is not None
            and project.disabled_at is None
            and device.owner_user_id == user.user_id
        ):
            labels.update(
                sga_project_id=project.project_id,
                sga_verified_user=user.user_id,
                sga_identity_source="registered_session",
            )
            principal = doc.principal.model_copy(
                update={
                    "user_id": user.user_id,
                    "display_name": user.display_name,
                    "groups": (),
                }
            )
            return (
                doc.model_copy(update={"labels": labels, "principal": principal}),
                project.project_id,
                user.user_id,
            )
    labels["sga_identity_source"] = "unverified"
    return doc.model_copy(update={"labels": labels}), None, None
