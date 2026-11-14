"""Security approval queue (M11): a tool call waits on its device until security decides.

A rule (or a policy override) with ``response: security_approval`` makes the gateway plugin hold
the call. The sensor registers it here and polls for a decision about every second; security
approves or denies in the console (or ``sga-server security``). Nobody decides within the wait
(5 minutes, decision 2026-11-12) → the device denies the call. The sensor reports what actually
happened (``outcome``), because a decision can land after the device stopped waiting.

Sensor: ``POST /v1/security-approvals``, ``GET /v1/security-approvals/decisions``,
``POST /v1/security-approvals/{id}/outcome``. Admin: ``GET /v1/admin/security-approvals``,
``POST /v1/admin/security-approvals/{id}/decision`` (admin token only).
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import or_, select

from ..redact import redact_text
from . import audit_chain
from .auth import DbSession, require_admin, require_device
from .db import Device, SecurityApproval, utcnow

MAX_WAIT_SECONDS = 900
# Review 2026-11-15: a decision handed out but not yet answered by an outcome goes out again after this,
# so a lost response cannot lose security's decision (the device ignores holds it no longer has).
DECISION_LEASE = timedelta(seconds=15)
OUTCOMES = ("allowed", "denied", "timeout", "cancelled", "unreachable", "mismatch", "rechecked")

admin = APIRouter(prefix="/v1/admin", tags=["security-approval"], dependencies=[Depends(require_admin)])
sensor = APIRouter(prefix="/v1", tags=["sensor"])
CurrentDevice = Annotated[Device, Depends(require_device)]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HoldCreate(_Model):
    id: str = Field(pattern=r"^[0-9a-f]{32}$")
    tool: str = Field(max_length=200)
    arguments_preview: str = Field(default="", max_length=4000)
    reason: str = Field(default="", max_length=1000)
    rule_ids: list[str] = Field(default_factory=list, max_length=50)
    severity: str | None = None
    user_id: str = Field(max_length=200)
    session_id: str = Field(max_length=200)
    event_id: str | None = None
    finding_ids: list[str] = Field(default_factory=list, max_length=50)
    wait_seconds: int = Field(ge=1, le=MAX_WAIT_SECONDS)
    request_digest: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$", description="The exact request the approval is for"
    )


class HoldCreated(_Model):
    id: str
    expires_at: datetime


class Decision(_Model):
    id: str
    decision: Literal["approved", "denied"]
    by: str
    reason: str
    request_digest: str | None = None  # the device runs the call only if this names its held request


class OutcomeIn(_Model):
    # mismatch: the approval named another request; rechecked: a blocking condition appeared while waiting
    outcome: Literal["allowed", "denied", "timeout", "cancelled", "unreachable", "mismatch", "rechecked"]


class DecisionIn(_Model):
    decision: Literal["approve", "deny"]
    by: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=1000)


class ApprovalOut(_Model):
    id: str
    device_id: str
    status: str  # pending | approved | denied | expired (pending past its deadline)
    created_at: datetime
    expires_at: datetime
    user_id: str
    session_id: str
    tool: str
    arguments_preview: str
    reason: str
    rule_ids: list[str]
    severity: str | None
    event_id: str | None
    finding_ids: list[str]
    decided_at: datetime | None
    decided_by: str | None
    decision_reason: str | None
    delivered_at: datetime | None
    outcome: str | None
    outcome_at: datetime | None
    request_digest: str | None = None


def shown_status(a: SecurityApproval, now: datetime) -> str:
    if a.status == "pending" and (a.outcome is not None or now >= a.expires_at):
        return "expired"  # the device stopped waiting; a late decision would change nothing
    return a.status


def _out(a: SecurityApproval, now: datetime) -> ApprovalOut:
    out = ApprovalOut.model_validate(a, from_attributes=True)
    return out.model_copy(update={"status": shown_status(a, now)})


# ── sensor ──────────────────────────────────────────────────────────────────


@sensor.post("/security-approvals", response_model=HoldCreated, status_code=status.HTTP_201_CREATED)
def create_hold(body: HoldCreate, device: CurrentDevice, db: DbSession) -> HoldCreated:
    existing = db.get(SecurityApproval, body.id)
    if existing is not None:
        if existing.device_id != device.device_id:
            raise HTTPException(status.HTTP_409_CONFLICT, "id in use")
        return HoldCreated(id=existing.id, expires_at=existing.expires_at)  # a retried request
    now = utcnow()
    row = SecurityApproval(
        id=body.id,
        device_id=device.device_id,
        status="pending",
        created_at=now,
        expires_at=now + timedelta(seconds=body.wait_seconds),
        user_id=body.user_id,
        session_id=body.session_id,
        tool=body.tool,
        # Sensors redact already; again here (defence in depth), then cap for the console.
        arguments_preview=redact_text(body.arguments_preview)[:2000],
        reason=body.reason,
        rule_ids=body.rule_ids,
        severity=body.severity,
        event_id=body.event_id,
        finding_ids=body.finding_ids,
        request_digest=body.request_digest,
    )
    db.add(row)
    db.commit()
    return HoldCreated(id=row.id, expires_at=row.expires_at)


@sensor.get("/security-approvals/decisions", response_model=list[Decision])
def decisions(device: CurrentDevice, db: DbSession) -> list[Decision]:
    """Decisions on this device's holds: not handed out yet, or handed out more than DECISION_LEASE ago
    with no outcome reported while the hold is still open (the first answer may have been lost)."""
    now = utcnow()
    rows = list(
        db.scalars(
            select(SecurityApproval).where(
                SecurityApproval.device_id == device.device_id,
                SecurityApproval.status.in_(("approved", "denied")),
                or_(
                    SecurityApproval.delivered_at.is_(None),
                    (SecurityApproval.delivered_at < now - DECISION_LEASE)
                    & SecurityApproval.outcome.is_(None)
                    & (SecurityApproval.expires_at > now),
                ),
            )
        )
    )
    for a in rows:
        a.delivered_at = now
    db.commit()
    return [
        Decision(
            id=a.id,
            decision=a.status,  # type: ignore[arg-type]
            by=a.decided_by or "",
            reason=a.decision_reason or "",
            request_digest=a.request_digest,
        )
        for a in rows
    ]


@sensor.post("/security-approvals/{hold_id}/outcome", status_code=status.HTTP_204_NO_CONTENT)
def report_outcome(hold_id: str, body: OutcomeIn, device: CurrentDevice, db: DbSession) -> None:
    a = db.get(SecurityApproval, hold_id)
    if a is None or a.device_id != device.device_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    a.outcome, a.outcome_at = body.outcome, utcnow()
    db.commit()


# ── admin ───────────────────────────────────────────────────────────────────


@admin.get("/security-approvals", response_model=list[ApprovalOut])
def list_approvals(
    db: DbSession,
    status_: Annotated[str | None, Query(alias="status")] = None,
    device_id: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[ApprovalOut]:
    """Newest first. ``status=pending`` lists only what security can still decide."""
    now = utcnow()
    q = select(SecurityApproval)
    if device_id:
        q = q.where(SecurityApproval.device_id == device_id)
    if status_ == "pending":
        q = q.where(
            SecurityApproval.status == "pending",
            SecurityApproval.outcome.is_(None),
            SecurityApproval.expires_at > now,
        )
    elif status_:
        q = q.where(SecurityApproval.status == status_) if status_ != "expired" else q
    rows = [_out(a, now) for a in db.scalars(q.order_by(SecurityApproval.created_at.desc()).limit(limit))]
    return [r for r in rows if status_ != "expired" or r.status == "expired"]


@admin.post("/security-approvals/{hold_id}/decision", response_model=ApprovalOut)
def decide(hold_id: str, body: DecisionIn, request: Request, db: DbSession) -> ApprovalOut:
    if request.state.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "deciding needs the admin token")
    a = db.get(SecurityApproval, hold_id)
    if a is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    now = utcnow()
    current = shown_status(a, now)
    if current != "pending":
        raise HTTPException(status.HTTP_409_CONFLICT, f"already {current}")
    a.status = "approved" if body.decision == "approve" else "denied"
    a.decided_at, a.decided_by, a.decision_reason = now, body.by, body.reason
    audit_chain.append(
        db,
        "security_decision",
        a.id,
        {"status": a.status, "by": a.decided_by, "reason": a.decision_reason, "at": now, "user_id": a.user_id,
         "tool": a.tool, "rule_ids": a.rule_ids, "request_digest": a.request_digest},
    )  # fmt: skip
    db.commit()
    return _out(a, now)
