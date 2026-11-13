"""People's risk for zero-trust access decisions (2026-11-13, KISA agentic AI ZT guide P1-4, C1-7).

A person is *elevated* while their recent findings say so: at least one critical, or three high,
in the last 24 hours, counting only findings about what their agent *did* (tool calls and results,
prompts, replies, approvals). Device configuration findings (install, config, inventory, integrity,
egress seen at the network) are about the PC, not the person: device posture handles them
(``sensitive-resource-from-degraded-device``). Live 2026-11-13, before this filter, configuration
alerts alone made five people elevated, among them the team gateway's service account.
Medium and lower never count, so the zero-trust rules' own findings (medium) cannot feed back
into the score. It decays by itself when the window moves on.

Sensors poll ``GET /v1/risk`` on their flush tick and keep the answer as the
``elevated_risk_users`` set (rules/zero_trust.yaml). A device only learns about people who used it
(events from that device in the last week): the list of risky people is not broadcast.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from .auth import DbSession, require_admin, require_device
from .db import Device, EventRow, FindingRow, utcnow

WINDOW = timedelta(hours=24)
SEEN_WINDOW = timedelta(days=7)
ACTION_KINDS = (
    "tool.call",
    "tool.result",
    "prompt.user",
    "message.assistant",
    "approval.resolved",
    "llm.call",
)
CRITICAL_AT = 1
HIGH_AT = 3

admin = APIRouter(prefix="/v1/admin", tags=["risk"], dependencies=[Depends(require_admin)])
sensor = APIRouter(prefix="/v1", tags=["sensor"])
CurrentDevice = Annotated[Device, Depends(require_device)]


class PersonRisk(BaseModel):
    model_config = ConfigDict(extra="forbid")
    user_id: str
    critical: int
    high: int
    elevated: bool


class SensorRisk(BaseModel):
    model_config = ConfigDict(extra="forbid")
    elevated_users: list[str]
    window_hours: int


def scores(db: Session, now: datetime | None = None) -> dict[str, PersonRisk]:
    since = (now or utcnow()) - WINDOW
    rows = db.execute(
        select(FindingRow.user_id, FindingRow.severity, FindingRow.doc).where(
            FindingRow.ts >= since, FindingRow.severity.in_(("critical", "high"))
        )
    ).all()
    evidence = {i for r in rows for i in r.doc.get("evidence_event_ids") or ()}
    actions = set(
        db.scalars(
            select(EventRow.event_id).where(EventRow.event_id.in_(evidence), EventRow.kind.in_(ACTION_KINDS))
        )
    )
    counts: dict[str, Counter[str]] = {}
    for user, sev, doc in rows:
        if user and user != "unknown" and any(i in actions for i in doc.get("evidence_event_ids") or ()):
            counts.setdefault(user, Counter())[sev] += 1
    return {
        u: PersonRisk(
            user_id=u,
            critical=c["critical"],
            high=c["high"],
            elevated=c["critical"] >= CRITICAL_AT or c["high"] >= HIGH_AT,
        )
        for u, c in counts.items()
    }


def elevated_for_device(db: Session, device_id: str, now: datetime | None = None) -> list[str]:
    now = now or utcnow()
    elevated = {u for u, r in scores(db, now).items() if r.elevated}
    if not elevated:
        return []
    seen = set(
        db.scalars(
            select(EventRow.user_id)
            .where(
                EventRow.device_id == device_id,
                EventRow.ts >= now - SEEN_WINDOW,
                EventRow.user_id.in_(elevated),
            )
            .distinct()
        )
    )
    return sorted(seen)


@sensor.get("/risk", response_model=SensorRisk)
def device_risk(device: CurrentDevice, db: DbSession) -> SensorRisk:
    return SensorRisk(
        elevated_users=elevated_for_device(db, device.device_id),
        window_hours=int(WINDOW.total_seconds() // 3600),
    )


@admin.get("/risk", response_model=list[PersonRisk])
def people_risk(db: DbSession) -> list[PersonRisk]:
    """Everyone with a high or critical finding in the window, riskiest first."""
    return sorted(scores(db).values(), key=lambda r: (-r.elevated, -r.critical, -r.high, r.user_id))
