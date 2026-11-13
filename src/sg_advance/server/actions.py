"""Remote response (M11): security asks a device to act; the sensor picks it up and reports back.

There is no push channel: sensors poll ``GET /v1/actions`` every few seconds (the flush interval),
run what they can and ``POST /v1/actions/{id}/result``. Statuses: pending → delivered → done | failed.

Actions (decision 2026-11-12: enforce through the gateway plugin; the sensor gets no OpenClaw admin):

- ``block_session`` / ``unblock_session``: every further tool call of that conversation (and of the
  sub-agent conversations it delegated) is blocked (rule ``remote-blocked-session``).
- ``block_user`` / ``unblock_user``: the same for every conversation attributed to that person.
- ``abort_session``: ask the gateway to stop the running turn. Without ``operator.admin`` a v4 gateway
  refuses runs started by others; the refusal is reported, not hidden.
- ``disable_plugin`` / ``disable_skill``: quarantine on that device (``openclaw plugins disable`` /
  ``skills.entries.<key>.enabled=false``).

The table is the audit trail (who, why, delivered, result). Creating needs the admin token.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from . import audit_chain
from .auth import DbSession, require_admin, require_device
from .db import Device, RemoteAction, utcnow

ACTIONS = (
    "block_session",
    "unblock_session",
    "block_user",
    "unblock_user",
    "abort_session",
    "disable_plugin",
    "disable_skill",
)
ActionName = Literal[
    "block_session",
    "unblock_session",
    "block_user",
    "unblock_user",
    "abort_session",
    "disable_plugin",
    "disable_skill",
]

admin = APIRouter(prefix="/v1/admin", tags=["response"], dependencies=[Depends(require_admin)])
sensor = APIRouter(prefix="/v1", tags=["sensor"])
CurrentDevice = Annotated[Device, Depends(require_device)]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ActionCreate(_Model):
    device_id: str
    action: ActionName
    target: str = Field(
        min_length=1, max_length=300, description="session id, user id, plugin id or skill key"
    )
    finding_id: str | None = Field(default=None, description="The finding that prompted it, if any")
    by: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=1000)


class ActionOut(_Model):
    id: str
    device_id: str
    action: str
    target: str
    finding_id: str | None
    status: str
    created_at: datetime
    created_by: str
    reason: str
    delivered_at: datetime | None
    result_at: datetime | None
    result_detail: str | None


class ActionForSensor(_Model):
    id: str
    action: str
    target: str


class ActionResult(_Model):
    ok: bool
    detail: str = Field(default="", max_length=1000)


def _out(a: RemoteAction) -> ActionOut:
    return ActionOut.model_validate(a, from_attributes=True)


@admin.post("/actions", response_model=ActionOut, status_code=status.HTTP_201_CREATED)
def create_action(body: ActionCreate, request: Request, db: DbSession) -> ActionOut:
    if request.state.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "remote response needs the admin token")
    if db.get(Device, body.device_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")
    row = RemoteAction(
        id=uuid4().hex,
        device_id=body.device_id,
        action=body.action,
        target=body.target,
        finding_id=body.finding_id,
        status="pending",
        created_at=utcnow(),
        created_by=body.by,
        reason=body.reason,
    )
    db.add(row)
    audit_chain.append(db, "remote_action", row.id, _out(row).model_dump(mode="json"))
    db.commit()
    return _out(row)


@admin.get("/actions", response_model=list[ActionOut])
def list_actions(
    db: DbSession,
    device_id: str | None = None,
    status_: Annotated[str | None, Query(alias="status")] = None,
    target: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[ActionOut]:
    """Newest first."""
    q = select(RemoteAction)
    if device_id:
        q = q.where(RemoteAction.device_id == device_id)
    if status_:
        q = q.where(RemoteAction.status == status_)
    if target:
        q = q.where(RemoteAction.target == target)
    return [_out(a) for a in db.scalars(q.order_by(RemoteAction.created_at.desc()).limit(limit))]


@sensor.get("/actions", response_model=list[ActionForSensor])
def pending_actions(device: CurrentDevice, db: DbSession) -> list[ActionForSensor]:
    """This device's pending actions, oldest first; they become ``delivered``."""
    rows = list(
        db.scalars(
            select(RemoteAction)
            .where(RemoteAction.device_id == device.device_id, RemoteAction.status == "pending")
            .order_by(RemoteAction.created_at)
        )
    )
    now = utcnow()
    for a in rows:
        a.status, a.delivered_at = "delivered", now
    db.commit()
    return [ActionForSensor(id=a.id, action=a.action, target=a.target) for a in rows]


@sensor.post("/actions/{action_id}/result", status_code=status.HTTP_204_NO_CONTENT)
def action_result(action_id: str, body: ActionResult, device: CurrentDevice, db: DbSession) -> None:
    a = db.get(RemoteAction, action_id)
    if a is None or a.device_id != device.device_id:  # a device reports only on its own actions
        raise HTTPException(status.HTTP_404_NOT_FOUND, "action not found")
    a.status = "done" if body.ok else "failed"
    a.result_at = utcnow()
    a.result_detail = body.detail
    audit_chain.append(
        db, "remote_action_result", a.id, {"status": a.status, "detail": a.result_detail, "at": a.result_at}
    )
    db.commit()
