"""Policy management (M9): groups, layered overrides, signed bundles per group, change log.

Each device belongs to at most one group (``devices.group_name``; set from the enrollment token,
changed by an admin). It pulls the common bundle, or common + its group's stricter overrides
(``policy_layers``). Both are signed like before; the bundle format is unchanged, so sensors need
nothing new. The group and policy revision travel in response headers only.

Every write (group created, device moved, override set or cleared) appends a ``policy_changes`` row
with who (``by``, required: the admin token is shared), why (``reason``, required) and before/after.
Its id is the policy revision. Reads work with the dashboard token; writes need the admin token.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..detect.rules import RuleSet
from ..policy import PolicyBundle
from .auth import DbSession, require_admin
from .db import Device, Group, PolicyChange, PolicyOverride, utcnow
from .policy_layers import COMMON, RESPONSES, Override, apply_common, apply_group, check

router = APIRouter(prefix="/v1/admin", tags=["policy"], dependencies=[Depends(require_admin)])

GROUP_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


# ── building bundles ────────────────────────────────────────────────────────


def _overrides(db: Session, scope: str) -> dict[str, Override]:
    rows = db.scalars(select(PolicyOverride).where(PolicyOverride.scope == scope))
    return {
        r.rule_id: Override(
            enabled=r.enabled, response=r.response, allow=tuple(r.allow) if r.allow is not None else None
        )
        for r in rows
    }


def base_docs(app: FastAPI) -> list[dict[str, Any]]:
    return [r.model_dump(mode="json") for r in RuleSet.load(app.state.settings.rules_dir).rules]


def build_common(app: FastAPI, db: Session, manifests: list[dict[str, Any]]) -> PolicyBundle:
    docs = apply_common(base_docs(app), _overrides(db, COMMON))
    app.state.common_docs = docs
    app.state.group_policies = {}
    return PolicyBundle.from_docs(docs, manifests).signed(app.state.signing_key)


def policy_for(app: FastAPI, group: str | None) -> PolicyBundle:
    """The bundle a device of ``group`` gets (common when None or unknown)."""
    common: PolicyBundle = app.state.policy
    if not group:
        return common
    cache: dict[str, PolicyBundle] = app.state.group_policies
    if group not in cache:
        for db in app.state.db.session():
            if db.get(Group, group) is None:
                return common
            docs = apply_group(app.state.common_docs, _overrides(db, group))
        cache[group] = PolicyBundle.from_docs(docs, list(common.manifests)).signed(app.state.signing_key)
    return cache[group]


def revision(db: Session) -> int:
    return db.scalar(select(func.max(PolicyChange.id))) or 0


# ── models ──────────────────────────────────────────────────────────────────


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Who(_Model):
    by: str = Field(
        min_length=1, max_length=200, description="Who makes the change (the admin token is shared)"
    )
    reason: str = Field(min_length=1, max_length=1000, description="Why: kept in the change log")


class GroupCreate(Who):
    name: str = Field(description="lowercase letters, digits, - and _")
    description: str | None = Field(default=None, max_length=500)


class DeviceGroup(Who):
    group: str | None = Field(description="None: common policy only")


class OverrideSet(Who):
    scope: str = Field(description='"common" or a group name')
    rule_id: str
    enabled: bool | None = None
    response: str | None = None
    allow: list[str] | None = None


class OverrideClear(Who):
    scope: str
    rule_id: str


class ScopeOut(_Model):
    name: str
    description: str | None
    devices: int
    version: str
    overrides: int


class PolicyScopes(_Model):
    revision: int
    scopes: list[ScopeOut]


class RuleLayer(_Model):
    enabled: bool
    response: str
    allow: list[str] | None


class RuleRow(_Model):
    id: str
    title: str
    severity: str
    category: str
    match_type: str
    base: RuleLayer
    common_override: dict[str, Any] | None
    group_override: dict[str, Any] | None
    effective: RuleLayer


class ChangeOut(_Model):
    id: int
    ts: datetime
    actor: str
    role: str
    action: str
    scope: str | None
    rule_id: str | None
    target: str | None
    before: dict[str, Any] | None
    after: dict[str, Any] | None
    reason: str


class WriteResult(_Model):
    revision: int
    scope: str | None
    version: str | None


# ── helpers ─────────────────────────────────────────────────────────────────


def _need_admin(request: Request) -> None:
    if request.state.role != "admin":  # GET-only dashboard token never gets here; belt and braces
        raise HTTPException(status.HTTP_403_FORBIDDEN, "policy changes need the admin token")


def _scope_exists(db: Session, scope: str) -> None:
    if scope != COMMON and db.get(Group, scope) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"no such group: {scope}")


def _log(db: Session, request: Request, who: Who, action: str, **fields: Any) -> PolicyChange:
    row = PolicyChange(actor=who.by, role=request.state.role, action=action, reason=who.reason, **fields)
    db.add(row)
    return row


def _layer(doc: dict[str, Any]) -> RuleLayer:
    match = doc.get("match") or {}
    return RuleLayer(
        enabled=doc.get("enabled", True),
        response=doc.get("response", "alert"),
        allow=list(match.get("allow") or []) if match.get("type") == "allowlist" else None,
    )


def _refresh(app: FastAPI) -> None:
    app.state.refresh_policy()


# ── reads ───────────────────────────────────────────────────────────────────


@router.get("/policy/scopes", response_model=PolicyScopes)
def scopes(request: Request, db: DbSession) -> PolicyScopes:
    """The common policy and each group: devices, current bundle version, number of overrides."""
    app = request.app
    counts = dict(db.execute(select(Device.group_name, func.count()).group_by(Device.group_name)).all())
    ov = dict(db.execute(select(PolicyOverride.scope, func.count()).group_by(PolicyOverride.scope)).all())
    out = [
        ScopeOut(
            name=COMMON,
            description="회사 공통 기준선",
            devices=counts.get(None, 0),
            version=app.state.policy.version,
            overrides=ov.get(COMMON, 0),
        )
    ]
    for g in db.scalars(select(Group).order_by(Group.name)):
        out.append(
            ScopeOut(
                name=g.name,
                description=g.description,
                devices=counts.get(g.name, 0),
                version=policy_for(app, g.name).version,
                overrides=ov.get(g.name, 0),
            )
        )
    return PolicyScopes(revision=revision(db), scopes=out)


@router.get("/policy/rules", response_model=list[RuleRow])
def rules(request: Request, db: DbSession, scope: str = COMMON) -> list[RuleRow]:
    """Every rule with its base values, the overrides on top and the effective result for ``scope``."""
    _scope_exists(db, scope)
    app = request.app
    base = {d["id"]: d for d in base_docs(app)}
    common_ov = _overrides(db, COMMON)
    group_ov = _overrides(db, scope) if scope != COMMON else {}
    effective = {
        d["id"]: d
        for d in (app.state.common_docs if scope == COMMON else apply_group(app.state.common_docs, group_ov))
    }
    out = []
    for rid, doc in base.items():
        c, g = common_ov.get(rid), group_ov.get(rid)
        out.append(
            RuleRow(
                id=rid,
                title=doc["title"],
                severity=doc["severity"],
                category=doc["category"],
                match_type=doc["match"]["type"],
                base=_layer(doc),
                common_override=c.as_dict() if c else None,
                group_override=g.as_dict() if g else None,
                effective=_layer(effective[rid]),
            )
        )
    return out


@router.get("/policy/changes", response_model=list[ChangeOut])
def changes(
    db: DbSession,
    scope: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[ChangeOut]:
    """Newest first."""
    q = select(PolicyChange)
    if scope:
        q = q.where(PolicyChange.scope == scope)
    rows = db.scalars(q.order_by(PolicyChange.id.desc()).limit(limit).offset(offset))
    return [ChangeOut.model_validate(r, from_attributes=True) for r in rows]


# ── writes (admin token) ────────────────────────────────────────────────────


@router.post("/policy/groups", response_model=WriteResult, status_code=status.HTTP_201_CREATED)
def create_group(body: GroupCreate, request: Request, db: DbSession) -> WriteResult:
    _need_admin(request)
    if body.name == COMMON or not GROUP_NAME.match(body.name):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "group name: [a-z0-9][a-z0-9_-]*, not 'common'"
        )
    if db.get(Group, body.name) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, f"group {body.name} exists")
    db.add(Group(name=body.name, description=body.description, created_by=body.by))
    row = _log(db, request, body, "group.create", scope=body.name, after={"description": body.description})
    db.commit()
    return WriteResult(revision=row.id, scope=body.name, version=policy_for(request.app, body.name).version)


@router.put("/devices/{device_id}/group", response_model=WriteResult)
def assign_device(device_id: str, body: DeviceGroup, request: Request, db: DbSession) -> WriteResult:
    _need_admin(request)
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")
    if body.group is not None:
        _scope_exists(db, body.group)
    before = device.group_name
    device.group_name = body.group
    row = _log(
        db,
        request,
        body,
        "device.assign",
        scope=body.group or COMMON,
        target=device_id,
        before={"group": before},
        after={"group": body.group},
    )
    db.commit()
    return WriteResult(revision=row.id, scope=body.group, version=policy_for(request.app, body.group).version)


@router.put("/policy/overrides", response_model=WriteResult)
def set_override(body: OverrideSet, request: Request, db: DbSession) -> WriteResult:
    _need_admin(request)
    _scope_exists(db, body.scope)
    app = request.app
    below = (
        {d["id"]: d for d in app.state.common_docs}
        if body.scope != COMMON
        else {d["id"]: d for d in base_docs(app)}
    )
    rule = below.get(body.rule_id)
    if rule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"no such rule: {body.rule_id}")
    ov = Override(body.enabled, body.response, tuple(body.allow) if body.allow is not None else None)
    problems = check(rule, body.scope, ov)
    if problems:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "; ".join(problems))
    row = db.scalar(
        select(PolicyOverride).where(
            PolicyOverride.scope == body.scope, PolicyOverride.rule_id == body.rule_id
        )
    )
    before = (
        Override(row.enabled, row.response, tuple(row.allow) if row.allow is not None else None)
        if row
        else None
    )
    if row is None:
        row = PolicyOverride(scope=body.scope, rule_id=body.rule_id)
        db.add(row)
    row.enabled, row.response, row.allow = (
        ov.enabled,
        ov.response,
        list(ov.allow) if ov.allow is not None else None,
    )
    row.updated_at, row.updated_by, row.reason = utcnow(), body.by, body.reason
    change = _log(
        db,
        request,
        body,
        "override.set",
        scope=body.scope,
        rule_id=body.rule_id,
        before=before.as_dict() if before else None,
        after=ov.as_dict(),
    )
    db.commit()
    _refresh(app)
    return WriteResult(revision=change.id, scope=body.scope, version=_version(app, body.scope))


@router.post("/policy/overrides/clear", response_model=WriteResult)
def clear_override(body: OverrideClear, request: Request, db: DbSession) -> WriteResult:
    """Back to the layer below (a group returns to common; common returns to the repository rule)."""
    _need_admin(request)
    _scope_exists(db, body.scope)
    row = db.scalar(
        select(PolicyOverride).where(
            PolicyOverride.scope == body.scope, PolicyOverride.rule_id == body.rule_id
        )
    )
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no override for that rule in that scope")
    before = Override(row.enabled, row.response, tuple(row.allow) if row.allow is not None else None)
    db.delete(row)
    change = _log(
        db, request, body, "override.clear", scope=body.scope, rule_id=body.rule_id, before=before.as_dict()
    )
    db.commit()
    _refresh(request.app)
    return WriteResult(revision=change.id, scope=body.scope, version=_version(request.app, body.scope))


def _version(app: FastAPI, scope: str) -> str:
    return policy_for(app, None if scope == COMMON else scope).version


RESPONSE_CHOICES = RESPONSES  # re-exported for the CLI's help text
