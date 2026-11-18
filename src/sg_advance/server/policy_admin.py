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
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..policy import PolicyBundle
from . import audit_chain, policy_runtime
from .access import actor, require_permission
from .auth import DbSession, require_admin
from .db import Device, Group, PolicyChange, PolicyOverride, utcnow
from .policy_layers import COMMON, RESPONSES, Override, apply_common, apply_group, check
from .policy_runtime import PolicyView, StagedSnapshot, current_view, read_base_docs

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
    """The published base from the DB, not unreviewed edits in this worker's rules directory."""
    return current_view(app).base


def policy_for(app: FastAPI, group: str | None, device_id: str | None = None) -> PolicyBundle:
    """The bundle a device of ``group`` gets (common when None or unknown); a canary of a staged rollout
    gets the staged rules (with its group's overrides)."""
    view = current_view(app)
    staged = view.staged
    if staged is not None and device_id is not None and device_id in staged.devices:
        return staged.bundles.get(group or COMMON, staged.bundles[COMMON])
    return view.groups.get(group or COMMON, view.policy)


def reload_base(app: FastAPI, db: Session, role: str, actor_id: str) -> None:
    """Explicitly publish this worker's reviewed files; a failure leaves the DB snapshot intact."""
    view = current_view(app)
    if view.staged is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "a rollout is staged: promote or discard it first")
    try:
        base = read_base_docs(app)
        bundle = PolicyBundle.from_docs(
            apply_common(base, _overrides(db, COMMON)),
            list(view.policy.manifests), view.policy.effective_from,
        ).signed(app.state.signing_key)
    except ValueError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(e)) from e
    policy_runtime.publish(db, view.generation, base_rules=base)
    audit_chain.append(db, "policy_reload", str(view.generation + 1), {
        "actor": actor_id, "role": role, "before": view.policy.version, "after": bundle.version,
    })
    db.commit()


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


class StageIn(Who):
    devices: list[str] = Field(min_length=1, description="Canary device ids that get the new rules first")
    effective_from: AwareDatetime | None = Field(default=None, description="Canaries install it from then on")


class PromoteIn(Who):
    effective_from: AwareDatetime | None = Field(
        default=None, description="Every device installs the new policy from this time on (one cut-over)"
    )


class RolloutOut(_Model):
    current_version: str
    current_effective_from: datetime | None
    staged_version: str | None
    staged_devices: list[str]
    staged_effective_from: datetime | None


class WriteResult(_Model):
    revision: int
    scope: str | None
    version: str | None


# ── helpers ─────────────────────────────────────────────────────────────────


def _need_admin(request: Request) -> PolicyView:
    require_permission(request, "policy.write")
    return current_view(request.app)


def _scope_exists(db: Session, scope: str) -> None:
    if scope != COMMON and db.get(Group, scope) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"no such group: {scope}")


def _log(db: Session, request: Request, who: Who, action: str, **fields: Any) -> PolicyChange:
    row = PolicyChange(
        actor=actor(request), role=request.state.role, action=action, reason=who.reason, **fields
    )
    db.add(row)
    db.flush()  # the change id is the audit reference
    doc = {
        "actor": actor(request), "role": request.state.role, "action": action, "reason": who.reason, **fields
    }
    audit_chain.append(db, "policy_change", str(row.id), doc)
    policy_runtime.bump(db)
    return row


def _layer(doc: dict[str, Any]) -> RuleLayer:
    match = doc.get("match") or {}
    return RuleLayer(
        enabled=doc.get("enabled", True),
        response=doc.get("response", "alert"),
        allow=list(match.get("allow") or []) if match.get("type") == "allowlist" else None,
    )


def _refresh(app: FastAPI) -> None:
    current_view(app, force=True)  # _log invalidated all workers in the write's own transaction


# ── reads ───────────────────────────────────────────────────────────────────


@router.get("/policy/scopes", response_model=PolicyScopes)
def scopes(request: Request, db: DbSession) -> PolicyScopes:
    """The common policy and each group: devices, current bundle version, number of overrides."""
    app = request.app
    view = current_view(app)
    counts = dict(db.execute(select(Device.group_name, func.count()).group_by(Device.group_name)).all())
    ov = dict(db.execute(select(PolicyOverride.scope, func.count()).group_by(PolicyOverride.scope)).all())
    out = [
        ScopeOut(
            name=COMMON,
            description="회사 공통 기준선",
            devices=counts.get(None, 0),
            version=view.policy.version,
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
    view = current_view(app)
    base = {d["id"]: d for d in view.base}
    common_ov = _overrides(db, COMMON)
    group_ov = _overrides(db, scope) if scope != COMMON else {}
    effective = {
        d["id"]: d
        for d in (view.common if scope == COMMON else apply_group(view.common, group_ov))
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
    db.add(Group(name=body.name, description=body.description, created_by=actor(request)))
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
    view = _need_admin(request)
    _scope_exists(db, body.scope)
    app = request.app
    below = (
        {d["id"]: d for d in view.common}
        if body.scope != COMMON
        else {d["id"]: d for d in view.base}
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
    row.updated_at, row.updated_by, row.reason = utcnow(), actor(request), body.reason
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


# ── staged rollout routes ───────────────────────────────────────────────────


def _rollout(app: FastAPI) -> RolloutOut:
    view = current_view(app)
    staged = view.staged
    return RolloutOut(
        current_version=view.policy.version,
        current_effective_from=view.policy.effective_from,
        staged_version=staged.version if staged else None,
        staged_devices=sorted(staged.devices) if staged else [],
        staged_effective_from=staged.effective_from if staged else None,
    )


@router.get("/policy/rollout", response_model=RolloutOut)
def rollout(request: Request) -> RolloutOut:
    return _rollout(request.app)


@router.post("/policy/stage", response_model=RolloutOut)
def stage(body: StageIn, request: Request, db: DbSession) -> RolloutOut:
    """Read ``rules/`` now and give those rules to the named devices only."""
    view = _need_admin(request)
    app = request.app
    if view.staged is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "a rollout is already staged: promote or discard it")
    unknown = [d for d in body.devices if db.get(Device, d) is None]
    if unknown:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"no such device: {', '.join(unknown)}")
    try:
        base = read_base_docs(app)
    except ValueError as e:  # RuleLoadError: a broken rules/ never reaches even a canary
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(e)) from e
    staged = StagedSnapshot(base=base, devices=frozenset(body.devices), effective_from=body.effective_from)
    candidate = PolicyBundle.from_docs(
        apply_common(base, _overrides(db, COMMON)), list(view.policy.manifests), body.effective_from
    ).signed(app.state.signing_key)
    policy_runtime.publish(db, view.generation, staged=staged.model_dump(mode="json"))
    after = {"version": candidate.version, "devices": sorted(staged.devices),
             "effective_from": body.effective_from.isoformat() if body.effective_from else None}  # fmt: skip
    _log(db, request, body, "rollout.stage", target=",".join(sorted(staged.devices))[:200], after=after)
    db.commit()
    return _rollout(app)


@router.post("/policy/promote", response_model=RolloutOut)
def promote(body: PromoteIn, request: Request, db: DbSession) -> RolloutOut:
    """The staged rules become everyone's (from ``effective_from`` on, when given)."""
    view = _need_admin(request)
    app = request.app
    staged = view.staged
    if staged is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "nothing is staged")
    before = {"version": view.policy.version}
    candidate = PolicyBundle.from_docs(
        apply_common(staged.base, _overrides(db, COMMON)), list(view.policy.manifests), body.effective_from
    ).signed(app.state.signing_key)
    policy_runtime.publish(
        db, view.generation, base_rules=staged.base, effective_from=body.effective_from, staged=None
    )
    after = {"version": candidate.version, "staged_version": staged.version,
             "effective_from": body.effective_from.isoformat() if body.effective_from else None}  # fmt: skip
    _log(db, request, body, "rollout.promote", before=before, after=after)
    db.commit()
    return _rollout(app)


@router.post("/policy/discard", response_model=RolloutOut)
def discard(body: Who, request: Request, db: DbSession) -> RolloutOut:
    """Drop the staged rules: canaries go back to the current policy at their next sync."""
    view = _need_admin(request)
    app = request.app
    staged = view.staged
    if staged is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "nothing is staged")
    policy_runtime.publish(db, view.generation, staged=None)
    _log(db, request, body, "rollout.discard", target=",".join(sorted(staged.devices))[:200],
         before={"version": staged.version})  # fmt: skip
    db.commit()
    return _rollout(app)
