"""Package manifests on the control plane (M5d): verify, decide, ship in the signed policy.

Flow: a sensor reports an OpenClaw version (``integrity.report``) → if unknown, the server verifies
it in the background (npm registry signature + Sigstore provenance, ``supply.py``) and stores the
component digests → the next policy bundle carries them with a status:

- ``approved`` / ``revoked``: security decided (``sga-server manifest approve|revoke``)
- ``trusted``: verified and released at least ``release_cooldown_days`` ago
- ``cooling``: verified, but younger than that (tamper checks already work; trust waits)
- ``rejected``: verification failed (bad signature, foreign build repository, …)

In-house plugins that are not on npm (the SG-Advance guard itself) are pinned by digest.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Iterable
from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..integrity import Manifest, effective_status
from ..schema import AgentEvent, EventKind
from .auth import DbSession, require_admin
from .db import EventRow, PackageManifestRow, utcnow
from .supply import DEFAULT_PUBLISHERS, SupplyError, VerifiedPackage, parse_spec, publisher_for

log = logging.getLogger(__name__)


# ── policy view ─────────────────────────────────────────────────────────────


def manifest_docs(
    db: Session, cooldown: timedelta, now: datetime | None = None
) -> tuple[list[dict[str, Any]], datetime | None]:
    """Manifests for the policy bundle, and when the next status change (cooldown end) happens."""
    now = now or utcnow()
    docs, next_change = [], None
    for row in db.scalars(select(PackageManifestRow).order_by(PackageManifestRow.spec)):
        if row.error:
            st = "rejected"
        else:
            st = effective_status(row.approved, row.revoked, row.published_at, cooldown, now)
        trusted_after = row.published_at + cooldown if row.published_at else None
        if (
            st == "cooling"
            and trusted_after is not None
            and (next_change is None or trusted_after < next_change)
        ):
            next_change = trusted_after
        man = Manifest(
            package=row.package,
            version=row.version,
            status=st,
            components={} if row.error else dict(row.components),
            integrity=row.integrity,
            published_at=row.published_at,
            source_repo=row.source_repo,
            trusted_after=trusted_after,
        )
        docs.append(man.model_dump(mode="json"))
    return docs, next_change


# ── storing ─────────────────────────────────────────────────────────────────


def _upsert(db: Session, spec: str) -> PackageManifestRow:
    row = db.get(PackageManifestRow, spec)
    if row is None:
        package, version = parse_spec(spec)
        row = PackageManifestRow(
            spec=spec, package=package, version=version, components={}, verified_at=utcnow()
        )
        db.add(row)
    return row


def store_verified(db: Session, pkg: VerifiedPackage) -> PackageManifestRow:
    row = _upsert(db, f"{pkg.package}@{pkg.version}")
    row.integrity, row.published_at, row.source_repo = pkg.integrity, pkg.published_at, pkg.source_repo
    row.components, row.error, row.verified_at = pkg.components, None, utcnow()
    db.commit()
    return row


def store_failure(db: Session, spec: str, error: str) -> PackageManifestRow:
    row = _upsert(db, spec)
    row.error, row.components, row.verified_at = error[:1000], {}, utcnow()
    db.commit()
    return row


def verify_into(app: Any, spec: str) -> PackageManifestRow:
    """Run the configured verifier and store the outcome either way."""
    for db in app.state.db.session():
        try:
            pkg = app.state.verify_package(spec)
        except SupplyError as e:
            log.warning("package %s failed verification: %s", spec, e)
            return store_failure(db, spec, str(e))
        log.info("package %s verified (%d components)", spec, len(pkg.components))
        return store_verified(db, pkg)
    raise RuntimeError("no database session")


# ── automatic verification of versions sensors report ───────────────────────


def wanted_specs(events: Iterable[AgentEvent]) -> set[str]:
    """npm package versions an integrity report could not check yet (no manifest)."""
    out: set[str] = set()
    for ev in events:
        if ev.kind is not EventKind.INTEGRITY_REPORT:
            continue
        p = ev.payload
        comps = [p.core, *p.plugins] if p.core else list(p.plugins)
        for c in comps:
            if c.integrity == "pending" and c.trust == "unverified" and c.package and c.version:
                out.add(f"{c.package}@{c.version}")
    return out


def schedule_verification(app: Any, db: Session, specs: set[str]) -> list[str]:
    """Queue background verification for unknown, publisher-backed specs. Returns what was queued.

    One worker thread handles the queue in order: each job downloads a whole package (OpenClaw is
    ~110 MB), and a single writer keeps SQLite happy."""
    if not app.state.settings.auto_verify:
        return []
    queued = []
    with app.state.verify_lock:
        for spec in sorted(specs):
            if spec in app.state.verifying or db.get(PackageManifestRow, spec) is not None:
                continue
            try:
                publisher_for(parse_spec(spec)[0], DEFAULT_PUBLISHERS)
            except SupplyError:
                continue  # nobody we trust publishes it: only a manual pin can vouch for it
            app.state.verifying.add(spec)
            app.state.verify_queue.put(spec)
            queued.append(spec)
        if queued and app.state.verify_worker is None:
            app.state.verify_worker = threading.Thread(target=_worker, args=(app,), daemon=True)
            app.state.verify_worker.start()
    return queued


def _worker(app: Any) -> None:
    while True:
        spec = app.state.verify_queue.get()
        try:
            verify_into(app, spec)
            app.state.refresh_policy()
        except Exception:  # noqa: BLE001 - one bad job must not stop the worker
            log.exception("background verification of %s crashed", spec)
        finally:
            with app.state.verify_lock:
                app.state.verifying.discard(spec)
            app.state.verify_queue.task_done()


# ── admin API ───────────────────────────────────────────────────────────────

router = APIRouter(prefix="/v1/admin/manifests", tags=["admin"], dependencies=[Depends(require_admin)])


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ManifestOut(_Model):
    spec: str
    status: str
    published_at: datetime | None
    trusted_after: datetime | None
    source_repo: str | None
    components: int
    decided_by: str | None
    error: str | None


class SpecRequest(_Model):
    spec: str = Field(description="npm name@version, e.g. openclaw@2026.11.3")
    by: str | None = Field(default=None, description="Who decided (audit)")


class AddRequest(SpecRequest):
    approve: bool = False


class PinRequest(_Model):
    plugin_id: str
    version: str = "local"
    digest: str = Field(description="integrity.dir_digest of the plugin directory")
    by: str | None = None


def _out(row: PackageManifestRow, cooldown: timedelta) -> ManifestOut:
    st = "rejected" if row.error else effective_status(row.approved, row.revoked, row.published_at, cooldown)
    return ManifestOut(
        spec=row.spec,
        status=st,
        published_at=row.published_at,
        trusted_after=row.published_at + cooldown if row.published_at else None,
        source_repo=row.source_repo,
        components=len(row.components or {}),
        decided_by=row.decided_by,
        error=row.error,
    )


def _cooldown(request: Request) -> timedelta:
    return timedelta(days=request.app.state.settings.release_cooldown_days)


@router.get("", response_model=list[ManifestOut])
def list_manifests(request: Request, db: DbSession) -> list[ManifestOut]:
    rows = db.scalars(select(PackageManifestRow).order_by(PackageManifestRow.spec))
    return [_out(r, _cooldown(request)) for r in rows]


@router.post("", response_model=ManifestOut, status_code=status.HTTP_201_CREATED)
def add_manifest(body: AddRequest, request: Request, db: DbSession) -> ManifestOut:
    """Verify a package now (downloads it) and optionally approve it in the same step."""
    try:
        parse_spec(body.spec)
    except SupplyError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(e)) from e
    verify_into(request.app, body.spec)
    db.expire_all()
    row = db.get(PackageManifestRow, body.spec)
    assert row is not None
    if body.approve and not row.error:
        row.approved, row.revoked, row.decided_by, row.decided_at = True, False, body.by, utcnow()
        db.commit()
    request.app.state.refresh_policy()
    return _out(row, _cooldown(request))


def _decide(request: Request, db: Session, spec: str, *, approve: bool, by: str | None) -> ManifestOut:
    row = db.get(PackageManifestRow, spec)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"{spec} is not known; add it first")
    if approve and row.error:
        raise HTTPException(status.HTTP_409_CONFLICT, f"{spec} failed verification: {row.error}")
    row.approved, row.revoked = approve, not approve
    row.decided_by, row.decided_at = by, utcnow()
    db.commit()
    request.app.state.refresh_policy()
    return _out(row, _cooldown(request))


@router.post("/approve", response_model=ManifestOut)
def approve_manifest(body: SpecRequest, request: Request, db: DbSession) -> ManifestOut:
    """Trust a verified version now (e.g. an urgent fix still inside the release cooldown)."""
    return _decide(request, db, body.spec, approve=True, by=body.by)


@router.post("/revoke", response_model=ManifestOut)
def revoke_manifest(body: SpecRequest, request: Request, db: DbSession) -> ManifestOut:
    """Stop trusting a version (e.g. it turned out to be malicious): plugins lose trusted status."""
    return _decide(request, db, body.spec, approve=False, by=body.by)


class SkillApproveRequest(_Model):
    ref: str = Field(description="source:name as in the inventory, e.g. openclaw-managed:pdf-tools")
    digest: str | None = Field(
        default=None, description="integrity.dir_digest of the skill directory you reviewed"
    )
    current: bool = Field(
        default=False, description="Approve the digest sensors last reported for this skill (no digest given)"
    )
    by: str | None = None


def _reported_skill_digest(db: Session, ref: str) -> str | None:
    """Newest digest any sensor reported for this skill in an inventory snapshot."""
    q = select(EventRow).where(EventRow.kind == "inventory.snapshot").order_by(EventRow.ts.desc()).limit(200)
    for row in db.scalars(q):
        for sk in row.doc["payload"].get("skills") or []:
            if sk.get("ref") == ref and sk.get("digest"):
                return sk["digest"]
    return None


@router.post("/skill", response_model=ManifestOut, status_code=status.HTTP_201_CREATED)
def approve_skill(body: SkillApproveRequest, request: Request, db: DbSession) -> ManifestOut:
    """Approve one skill's exact files (by digest). A changed skill is a new digest: approve again,
    or it shows as tampered. Revoke with the returned spec."""
    digest = body.digest
    if digest is None:
        if not body.current:
            raise HTTPException(422, "give digest, or current=true")
        digest = _reported_skill_digest(db, body.ref)
        if digest is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, f"no sensor has reported a digest for {body.ref}")
    spec = f"skill:{body.ref}@{digest[:12]}"
    row = db.get(PackageManifestRow, spec) or PackageManifestRow(
        spec=spec, package=f"skill:{body.ref}", version=digest[:12], verified_at=utcnow()
    )
    row.components = {f"skill:{body.ref}": digest}
    row.error, row.approved, row.revoked = None, True, False
    row.decided_by, row.decided_at = body.by, utcnow()
    db.merge(row)
    db.commit()
    request.app.state.refresh_policy()
    return _out(db.get(PackageManifestRow, spec), _cooldown(request))  # type: ignore[arg-type]


@router.post("/pin", response_model=ManifestOut, status_code=status.HTTP_201_CREATED)
def pin_plugin(body: PinRequest, request: Request, db: DbSession) -> ManifestOut:
    """Vouch for an in-house plugin that is not published (e.g. the SG-Advance guard) by digest."""
    spec = f"local:{body.plugin_id}@{body.version}"
    row = db.get(PackageManifestRow, spec) or PackageManifestRow(
        spec=spec, package=f"local:{body.plugin_id}", version=body.version, verified_at=utcnow()
    )
    row.components = {f"plugin:{body.plugin_id}": body.digest}
    row.error, row.approved, row.revoked = None, True, False
    row.decided_by, row.decided_at = body.by, utcnow()
    db.merge(row)
    db.commit()
    request.app.state.refresh_policy()
    return _out(db.get(PackageManifestRow, spec), _cooldown(request))  # type: ignore[arg-type]
