"""Control Plane API (M3): device enrollment, event/finding ingest, policy distribution.

Sensor-facing routes live under ``/v1`` and authenticate with a device token.
Admin routes live under ``/v1/admin`` and authenticate with the admin token.
"""

from __future__ import annotations

import logging
import queue
import secrets
import threading
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import __version__
from ..policy import PolicyBundle, key_id, load_or_create_signing_key, public_key_b64
from ..redact import redact_event, redact_text
from ..schema import AgentEvent, Finding, Severity
from . import audit, dashboard, manifests, policy_admin
from .auth import (
    DEVICE_PREFIX,
    ENROLL_PREFIX,
    DbSession,
    Token,
    hash_token,
    new_token,
    require_admin,
    require_device,
)
from .db import Database, Device, EnrollmentToken, EventRow, FindingRow, Group, utcnow
from .settings import Settings

log = logging.getLogger(__name__)

DEVICE_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$"

CurrentDevice = Annotated[Device, Depends(require_device)]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ── request / response models ───────────────────────────────────────────────


class EnrollRequest(_Model):
    device_id: str | None = Field(
        default=None, pattern=DEVICE_ID_PATTERN, description="Requested id; generated if omitted"
    )
    hostname: str | None = Field(default=None, max_length=255)
    os: str | None = Field(default=None, max_length=100)
    sensor_version: str | None = Field(default=None, max_length=50)


class EnrollResponse(_Model):
    device_id: str
    device_token: str = Field(description="Shown once. Store it on the endpoint; the server keeps a hash")
    policy_public_key: str = Field(description="base64 Ed25519 key the sensor verifies policy bundles with")
    policy_key_id: str


class EventBatch(_Model):
    events: list[AgentEvent]


class FindingBatch(_Model):
    findings: list[Finding]


class IngestResult(_Model):
    accepted: int
    duplicates: int


class EnrollmentTokenRequest(_Model):
    label: str | None = Field(default=None, max_length=200)
    max_uses: int = Field(default=1, ge=1, le=10_000)
    ttl_hours: float = Field(default=24, gt=0, le=24 * 365)
    group: str | None = Field(
        default=None, description="Devices enrolled with this token join this policy group"
    )


class EnrollmentTokenResponse(_Model):
    token: str = Field(description="Shown once")
    label: str | None
    max_uses: int
    expires_at: datetime
    group: str | None = None


class DeviceOut(_Model):
    device_id: str
    hostname: str | None
    os: str | None
    sensor_version: str | None
    enrolled_at: datetime
    last_seen: datetime | None
    policy_version: str | None
    policy_current: bool = Field(description="Sensor has pulled the policy the server serves it now")
    group: str | None = Field(default=None, description="Policy group (M9); None: common policy only")


class PolicyInfo(_Model):
    version: str
    rule_count: int
    enabled_count: int
    key_id: str
    public_key: str = Field(description="Give this to installers who want to pin the key")


# ── helpers ─────────────────────────────────────────────────────────────────


def _check_batch(request: Request, items: Sequence[object]) -> None:
    limit: int = request.app.state.settings.max_batch
    if len(items) > limit:
        raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, f"batch larger than {limit}")


def _check_owner(device: Device, items: Sequence[AgentEvent | Finding]) -> None:
    """A sensor may only report about itself. Stops one enrolled device from forging another's data."""
    for i, item in enumerate(items):
        if item.endpoint.device_id != device.device_id:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"item {i}: endpoint.device_id {item.endpoint.device_id!r} does not match "
                f"the authenticated device {device.device_id!r}",
            )


def _existing_ids(db: Session, column: Any, ids: list[str]) -> set[str]:
    return set(db.scalars(select(column).where(column.in_(ids)))) if ids else set()


def _policy(request: Request) -> PolicyBundle:
    app = request.app
    due = app.state.policy_refresh_at
    if due is not None and utcnow() >= due:  # a release cooldown ended: cooling → trusted
        app.state.refresh_policy()
    return app.state.policy


def _public_key(request: Request) -> str:
    return public_key_b64(request.app.state.signing_key.public_key())


def _policy_info(request: Request) -> PolicyInfo:
    bundle = _policy(request)
    pub = _public_key(request)
    return PolicyInfo(
        version=bundle.version,
        rule_count=len(bundle.rules),
        enabled_count=sum(1 for r in bundle.rules if r.get("enabled", True)),
        key_id=key_id(pub),
        public_key=pub,
    )


def _load_signed_policy(app: FastAPI) -> PolicyBundle:
    """Rules from disk + package manifests from the DB, signed. Records when it next goes stale."""
    cooldown = timedelta(days=app.state.settings.release_cooldown_days)
    for db in app.state.db.session():
        docs, next_change = manifests.manifest_docs(db, cooldown)
    app.state.policy_refresh_at = next_change
    for db in app.state.db.session():
        return policy_admin.build_common(app, db, docs)  # rules/ + common overrides (M9)
    raise RuntimeError("no database session")


def _default_package_verifier(settings: Settings) -> Any:
    """npm + Sigstore, created on first use so startup never needs the network."""
    state: dict[str, Any] = {}

    def verify(spec: str) -> Any:
        from .supply import HttpFetcher, sigstore_verifier, verify_npm_package

        if "provenance" not in state:
            state["provenance"] = sigstore_verifier()
        return verify_npm_package(
            spec, fetcher=HttpFetcher(), provenance=state["provenance"], registry=settings.npm_registry
        )

    return verify


Limit = Annotated[int, Query(ge=1, le=1000)]
Offset = Annotated[int, Query(ge=0)]


# ── sensor routes ───────────────────────────────────────────────────────────

sensor = APIRouter(prefix="/v1", tags=["sensor"])


@sensor.post("/enroll", response_model=EnrollResponse, status_code=status.HTTP_201_CREATED)
def enroll(body: EnrollRequest, request: Request, db: DbSession, token: Token) -> EnrollResponse:
    """Exchange a one-time enrollment token for a long-lived device token."""
    if not token.startswith(ENROLL_PREFIX):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not an enrollment token")
    et = db.scalar(select(EnrollmentToken).where(EnrollmentToken.token_hash == hash_token(token)))
    now = utcnow()
    if et is None or et.uses >= et.max_uses or (et.expires_at is not None and et.expires_at <= now):
        # Same answer for unknown / used up / expired: don't help guessing.
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or expired enrollment token")

    device_id = body.device_id or f"dev-{secrets.token_hex(4)}"
    if db.get(Device, device_id) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, f"device {device_id!r} already enrolled")

    device_token = new_token(DEVICE_PREFIX)
    db.add(
        Device(
            device_id=device_id,
            token_hash=hash_token(device_token),
            hostname=body.hostname,
            os=body.os,
            sensor_version=body.sensor_version,
            enrolled_at=now,
            enrolled_with=et.id,
            last_seen=now,
            group_name=et.group_name,
        )
    )
    et.uses += 1
    db.commit()
    pub = _public_key(request)
    return EnrollResponse(
        device_id=device_id, device_token=device_token, policy_public_key=pub, policy_key_id=key_id(pub)
    )


@sensor.get("/policy", response_model=PolicyBundle, responses={304: {"description": "Not modified"}})
def get_policy(
    request: Request,
    response: Response,
    device: CurrentDevice,
    db: DbSession,
    if_none_match: Annotated[str | None, Header()] = None,
) -> PolicyBundle | Response:
    """This device's policy bundle: common, or common + its group's stricter overrides (M9).
    Send ``If-None-Match: "<version>"`` to get 304 when unchanged."""
    _policy(request)  # refresh when a release cooldown ended
    bundle = policy_admin.policy_for(request.app, device.group_name)
    etag = f'"{bundle.version}"'
    device.last_seen = utcnow()
    device.policy_version = bundle.version
    db.commit()
    headers = {"ETag": etag, "X-SGA-Policy-Group": device.group_name or policy_admin.COMMON}
    if if_none_match is not None and if_none_match.strip() in (etag, bundle.version):
        return Response(status_code=status.HTTP_304_NOT_MODIFIED, headers=headers)
    response.headers.update(headers)
    return bundle


@sensor.post("/events", response_model=IngestResult)
def ingest_events(body: EventBatch, request: Request, device: CurrentDevice, db: DbSession) -> IngestResult:
    _check_batch(request, body.events)
    _check_owner(device, body.events)
    now = utcnow()
    seen = _existing_ids(db, EventRow.event_id, [e.event_id for e in body.events])
    accepted = 0
    for ev in body.events:
        if ev.event_id in seen:
            continue
        seen.add(ev.event_id)
        # Sensors redact already; doing it again here is cheap defence in depth (idempotent).
        stored = redact_event(ev).model_copy(update={"received_ts": now})
        db.add(
            EventRow(
                event_id=stored.event_id,
                device_id=device.device_id,
                ts=stored.ts,
                received_ts=now,
                kind=str(stored.kind),
                user_id=stored.principal.user_id,
                agent_type=str(stored.agent.type),
                session_id=stored.agent.session_id,
                sensor=str(stored.source.sensor),
                doc=stored.model_dump(mode="json"),
            )
        )
        accepted += 1
    device.last_seen = now
    db.commit()
    # A version no manifest covers yet: verify it in the background (M5d). The next policy sync
    # brings the digests to every sensor running it.
    manifests.schedule_verification(request.app, db, manifests.wanted_specs(body.events))
    return IngestResult(accepted=accepted, duplicates=len(body.events) - accepted)


@sensor.post("/findings", response_model=IngestResult)
def ingest_findings(
    body: FindingBatch, request: Request, device: CurrentDevice, db: DbSession
) -> IngestResult:
    _check_batch(request, body.findings)
    _check_owner(device, body.findings)
    now = utcnow()
    seen = _existing_ids(db, FindingRow.finding_id, [f.finding_id for f in body.findings])
    accepted = 0
    for f in body.findings:
        if f.finding_id in seen:
            continue
        seen.add(f.finding_id)
        if f.explanation:
            f = f.model_copy(update={"explanation": redact_text(f.explanation)})
        db.add(
            FindingRow(
                finding_id=f.finding_id,
                device_id=device.device_id,
                ts=f.ts,
                received_ts=now,
                rule_id=f.rule_id,
                severity=str(f.severity),
                category=str(f.category),
                user_id=f.principal.user_id,
                agent_type=str(f.agent.type),
                session_id=f.agent.session_id,
                doc=f.model_dump(mode="json"),
            )
        )
        accepted += 1
    device.last_seen = now
    db.commit()
    return IngestResult(accepted=accepted, duplicates=len(body.findings) - accepted)


# ── admin routes ────────────────────────────────────────────────────────────

admin = APIRouter(prefix="/v1/admin", tags=["admin"], dependencies=[Depends(require_admin)])


@admin.post("/enrollment-tokens", response_model=EnrollmentTokenResponse, status_code=201)
def create_enrollment_token(body: EnrollmentTokenRequest, db: DbSession) -> EnrollmentTokenResponse:
    if body.group is not None and db.get(Group, body.group) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"no such group: {body.group}")
    token = new_token(ENROLL_PREFIX)
    expires_at = utcnow() + timedelta(hours=body.ttl_hours)
    db.add(
        EnrollmentToken(
            token_hash=hash_token(token),
            label=body.label,
            max_uses=body.max_uses,
            expires_at=expires_at,
            group_name=body.group,
        )
    )
    db.commit()
    return EnrollmentTokenResponse(
        token=token, label=body.label, max_uses=body.max_uses, expires_at=expires_at, group=body.group
    )


@admin.get("/devices", response_model=list[DeviceOut])
def list_devices(request: Request, db: DbSession) -> list[DeviceOut]:
    rows = db.scalars(select(Device).order_by(Device.device_id))
    return [
        DeviceOut(
            device_id=d.device_id,
            hostname=d.hostname,
            os=d.os,
            sensor_version=d.sensor_version,
            enrolled_at=d.enrolled_at,
            last_seen=d.last_seen,
            policy_version=d.policy_version,
            policy_current=d.policy_version == policy_admin.policy_for(request.app, d.group_name).version,
            group=d.group_name,
        )
        for d in rows
    ]


@admin.get("/events", response_model=list[AgentEvent])
def list_events(
    db: DbSession,
    device_id: str | None = None,
    user_id: str | None = None,
    session_id: str | None = None,
    kind: str | None = None,
    limit: Limit = 100,
    offset: Offset = 0,
) -> list[dict[str, Any]]:
    """Newest first."""
    q = select(EventRow.doc)
    for col, val in (
        (EventRow.device_id, device_id),
        (EventRow.user_id, user_id),
        (EventRow.session_id, session_id),
        (EventRow.kind, kind),
    ):
        if val is not None:
            q = q.where(col == val)
    q = q.order_by(EventRow.ts.desc(), EventRow.event_id).limit(limit).offset(offset)
    return list(db.scalars(q))


@admin.get("/findings", response_model=list[Finding])
def list_findings(
    db: DbSession,
    device_id: str | None = None,
    user_id: str | None = None,
    session_id: str | None = None,
    rule_id: str | None = None,
    category: str | None = None,
    severity: Severity | None = None,
    min_severity: Severity | None = None,
    limit: Limit = 100,
    offset: Offset = 0,
) -> list[dict[str, Any]]:
    """Newest first. ``severity=high`` returns exactly high; ``min_severity=high`` high and critical."""
    q = select(FindingRow.doc)
    for col, val in (
        (FindingRow.device_id, device_id),
        (FindingRow.user_id, user_id),
        (FindingRow.session_id, session_id),
        (FindingRow.rule_id, rule_id),
        (FindingRow.category, category),
        (FindingRow.severity, str(severity) if severity else None),
    ):
        if val is not None:
            q = q.where(col == val)
    if min_severity is not None:
        q = q.where(FindingRow.severity.in_([str(s) for s in Severity if s.at_least(min_severity)]))
    q = q.order_by(FindingRow.ts.desc(), FindingRow.finding_id).limit(limit).offset(offset)
    return list(db.scalars(q))


@admin.get("/policy", response_model=PolicyInfo)
def policy_info(request: Request) -> PolicyInfo:
    return _policy_info(request)


@admin.post("/policy/reload", response_model=PolicyInfo)
def reload_policy(request: Request) -> PolicyInfo:
    """Re-read ``rules/`` from disk. An invalid rule file is rejected and the old policy stays."""
    try:
        bundle = _load_signed_policy(request.app)
    except ValueError as e:  # RuleLoadError is a ValueError
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(e)) from e
    request.app.state.policy = bundle
    return _policy_info(request)


# ── app factory ─────────────────────────────────────────────────────────────


def create_app(settings: Settings, verify_package: Any = None) -> FastAPI:
    """``verify_package(spec) -> supply.VerifiedPackage``: injected by tests; default npm + Sigstore."""
    if not settings.admin_token:
        raise ValueError("admin_token is required (set SGA_ADMIN_TOKEN)")

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.db.create_all()
        yield
        app.state.db.engine.dispose()

    app = FastAPI(title="sg-advance control plane", version=__version__, lifespan=lifespan)
    app.state.settings = settings
    app.state.db = Database(settings.db_url)
    app.state.signing_key = load_or_create_signing_key(settings.signing_key_path)
    app.state.verify_package = verify_package or _default_package_verifier(settings)
    app.state.verifying = set()
    app.state.verify_lock = threading.Lock()
    app.state.verify_queue = queue.Queue()
    app.state.verify_worker = None
    app.state.db.create_all()  # manifests live in the DB and are part of the policy
    app.state.refresh_policy = lambda: setattr(app.state, "policy", _load_signed_policy(app))
    # Fail fast on a broken rules/ directory instead of serving an empty policy.
    app.state.policy = _load_signed_policy(app)

    @app.get("/healthz", tags=["ops"])
    def healthz() -> dict[str, str]:
        return {
            "status": "ok",
            "policy_version": app.state.policy.version,
            "policy_key_id": app.state.policy.key_id,
        }

    app.include_router(sensor)
    app.include_router(admin)
    app.include_router(manifests.router)
    app.include_router(audit.router)
    app.include_router(dashboard.router)
    app.include_router(policy_admin.router)
    _mount_dashboard(app, settings)
    return app


# Same origin as the API (no CORS). Only our own files: scripts, styles and API calls from 'self'.
DASHBOARD_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


def _mount_dashboard(app: FastAPI, settings: Settings) -> None:
    """Serve the built SGA-Dashboard (``dashboard/dist``) at /dashboard when configured."""
    root = settings.dashboard_dir
    if root is None:
        return
    if not (root / "index.html").is_file():
        # Compose mounts dashboard/dist even before anyone built it: keep the API up, say why.
        log.warning("SGA_DASHBOARD_DIR=%s has no index.html (npm run build in dashboard/): not served", root)
        return
    from fastapi.responses import RedirectResponse
    from fastapi.staticfiles import StaticFiles

    app.mount("/dashboard", StaticFiles(directory=root, html=True), name="dashboard")

    @app.get("/", include_in_schema=False)
    def to_dashboard() -> RedirectResponse:
        return RedirectResponse("/dashboard/")

    @app.middleware("http")
    async def dashboard_headers(request: Request, call_next: Any) -> Response:
        response: Response = await call_next(request)
        if request.url.path.startswith("/dashboard"):
            response.headers.update(DASHBOARD_HEADERS)
        return response
