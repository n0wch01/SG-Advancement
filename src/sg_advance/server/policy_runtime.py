"""DB-backed published policy and immutable per-generation views for each server process.

Only the initial bootstrap, explicit reload and staging read rules/; restarting a worker never
publishes a file edit. Policy writes invalidate other workers through a transactional generation.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import AwareDatetime, BaseModel, ConfigDict
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..detect.rules import RuleSet
from ..policy import PolicyBundle
from .db import Group, PolicyOverride, PolicyState, utcnow
from .manifests import manifest_docs
from .policy_layers import COMMON, Override, apply_common, apply_group


class StagedSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    base: list[dict[str, Any]]
    devices: frozenset[str]
    effective_from: AwareDatetime | None = None


@dataclass(frozen=True)
class Staged:
    base: list[dict[str, Any]]
    devices: frozenset[str]
    effective_from: datetime | None
    version: str
    bundles: dict[str, PolicyBundle]


@dataclass(frozen=True)
class PolicyView:
    generation: int
    base: list[dict[str, Any]]
    common: list[dict[str, Any]]
    policy: PolicyBundle
    groups: dict[str, PolicyBundle]
    staged: Staged | None
    next_change: datetime | None


def read_base_docs(app: FastAPI) -> list[dict[str, Any]]:
    return [r.model_dump(mode="json") for r in RuleSet.load(app.state.settings.rules_dir).rules]


def _bootstrap(app: FastAPI, db: Session) -> PolicyState:
    row = db.get(PolicyState, 1)
    if row is None:
        row = PolicyState(id=1, generation=1, base_rules=read_base_docs(app))
        db.add(row)
        try:
            db.commit()
        except IntegrityError:  # another worker bootstrapped the same database
            db.rollback()
            row = db.get(PolicyState, 1)
            if row is None:
                raise
    return row


def bump(db: Session) -> None:
    """Invalidate worker caches in the same transaction as the policy/configuration write."""
    db.execute(update(PolicyState).where(PolicyState.id == 1).values(generation=PolicyState.generation + 1))


def publish(db: Session, expected: int, **fields: Any) -> None:
    """Publish a rollout transition only if it was based on the current generation (no lost updates)."""
    result = db.execute(
        update(PolicyState)
        .where(PolicyState.id == 1, PolicyState.generation == expected)
        .values(generation=PolicyState.generation + 1, **fields)
    )
    if result.rowcount != 1:
        raise HTTPException(409, "policy changed while preparing this update; reload and retry")


def _build(app: FastAPI, db: Session, row: PolicyState) -> PolicyView:
    layers: dict[str, dict[str, Override]] = defaultdict(dict)
    for ov in db.scalars(select(PolicyOverride)):
        layers[ov.scope][ov.rule_id] = Override(
            ov.enabled, ov.response, tuple(ov.allow) if ov.allow is not None else None
        )
    names = list(db.scalars(select(Group.name)))
    manifests, next_change = manifest_docs(db, timedelta(days=app.state.settings.release_cooldown_days))

    def bundles(base: list[dict[str, Any]], start: datetime | None) -> tuple[list[dict[str, Any]], dict]:
        common = apply_common(base, layers[COMMON])
        docs = {COMMON: common} | {g: apply_group(common, layers[g]) for g in names}
        return common, {
            g: PolicyBundle.from_docs(d, manifests, start).signed(app.state.signing_key)
            for g, d in docs.items()
        }

    common, active = bundles(row.base_rules, row.effective_from)
    staged = None
    if row.staged is not None:
        saved = StagedSnapshot.model_validate(row.staged)
        _, candidates = bundles(saved.base, saved.effective_from)
        staged = Staged(
            saved.base, saved.devices, saved.effective_from, candidates[COMMON].version, candidates
        )
    return PolicyView(row.generation, row.base_rules, common, active[COMMON], active, staged, next_change)


def current_view(app: FastAPI, *, force: bool = False) -> PolicyView:
    """Use a complete view of one DB generation; verify the generation after reading its inputs."""
    with app.state.policy_lock:
        for _ in range(3):
            for db in app.state.db.session():
                row = _bootstrap(app, db)
                cached: PolicyView | None = getattr(app.state, "policy_view", None)
                due = cached and cached.next_change is not None and utcnow() >= cached.next_change
                if cached is not None and cached.generation == row.generation and not due and not force:
                    return cached
                generation = row.generation
                view = _build(app, db, row)
                # Reading again avoids caching mixed inputs if another worker committed during the build.
                if db.scalar(select(PolicyState.generation).where(PolicyState.id == 1)) != generation:
                    continue
                app.state.policy_view = view
                # Compatibility aliases for diagnostics/tests; execution uses the atomic view above.
                app.state.policy = view.policy
                app.state.base_docs = view.base
                app.state.common_docs = view.common
                app.state.staged = view.staged
                app.state.policy_refresh_at = view.next_change
                return view
        raise HTTPException(503, "policy is changing; a consistent snapshot is not available")


def refresh(app: FastAPI) -> PolicyBundle:
    """Called after manifest writes, or explicitly: invalidate every worker and rebuild this one."""
    with app.state.policy_lock:
        for db in app.state.db.session():
            _bootstrap(app, db)
            bump(db)
            db.commit()
        return current_view(app, force=True).policy
