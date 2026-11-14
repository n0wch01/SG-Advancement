"""People's risk for zero-trust access decisions (2026-11-13, KISA agentic AI ZT guide P1-4, C1-7).

A person is *elevated* while their recent findings say so: at least one critical, or three high,
in the last 24 hours, counting only findings about what their agent *did* (tool calls and results,
prompts, replies, approvals). Device configuration findings (install, config, inventory, integrity,
egress seen at the network) are about the PC, not the person: device posture handles them
(``sensitive-resource-from-degraded-device``). Live 2026-11-13, before this filter, configuration
alerts alone made five people elevated, among them the team gateway's service account.
Medium and lower never count, so the zero-trust rules' own findings (medium) cannot feed back
into the score. It decays by itself when the window moves on.

Each person also gets a **score** from 0 to 100 (2026-11-14, KISA P1-4: a continuous value rather
than yes/no): critical counts 60, high 20, each weighted by how recent it is (1.0 now, falling
linearly to 0.5 at the edge of the window), capped at 100. The score ranks people and shows how
risky someone is right now. **Access decisions still use ``elevated``** (the thresholds above):
using the score for them would change who is blocked, which is a rule-tuning decision for the user.

Sensors poll ``GET /v1/risk`` on their flush tick and keep the answer as the
``elevated_risk_users`` set (rules/zero_trust.yaml). A device only learns about people who used it
(events from that device in the last week): the list of risky people is not broadcast.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta
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
WEIGHTS = {"critical": 60.0, "high": 20.0}
OLDEST_WEIGHT = 0.5  # a finding at the edge of the window counts half
SCORE_MAX = 100

admin = APIRouter(prefix="/v1/admin", tags=["risk"], dependencies=[Depends(require_admin)])
sensor = APIRouter(prefix="/v1", tags=["sensor"])
CurrentDevice = Annotated[Device, Depends(require_device)]


class PersonRisk(BaseModel):
    model_config = ConfigDict(extra="forbid")
    user_id: str
    critical: int
    high: int
    elevated: bool
    score: int = 0
    last_ts: datetime | None = None


class SensorRisk(BaseModel):
    model_config = ConfigDict(extra="forbid")
    elevated_users: list[str]
    window_hours: int


def _aware(ts: datetime) -> datetime:
    return ts if ts.tzinfo else ts.replace(tzinfo=UTC)


def score_of(found: list[tuple[str, datetime]], now: datetime) -> int:
    """0..100 from (severity, ts) pairs inside the window: severity weight × recency, capped."""
    total = 0.0
    for sev, ts in found:
        age = min(max((now - _aware(ts)) / WINDOW, 0.0), 1.0)
        total += WEIGHTS.get(sev, 0.0) * (1.0 - (1.0 - OLDEST_WEIGHT) * age)
    return min(SCORE_MAX, round(total))


def scores(db: Session, now: datetime | None = None) -> dict[str, PersonRisk]:
    now = now or utcnow()
    since = now - WINDOW
    rows = db.execute(
        select(FindingRow.user_id, FindingRow.severity, FindingRow.ts, FindingRow.doc).where(
            FindingRow.ts >= since, FindingRow.severity.in_(("critical", "high"))
        )
    ).all()
    evidence = {i for r in rows for i in r.doc.get("evidence_event_ids") or ()}
    actions = set(
        db.scalars(
            select(EventRow.event_id).where(EventRow.event_id.in_(evidence), EventRow.kind.in_(ACTION_KINDS))
        )
    )
    found: dict[str, list[tuple[str, datetime]]] = {}
    for user, sev, ts, doc in rows:
        if user and user != "unknown" and any(i in actions for i in doc.get("evidence_event_ids") or ()):
            found.setdefault(user, []).append((sev, ts))
    out = {}
    for u, items in found.items():
        c = Counter(sev for sev, _ in items)
        out[u] = PersonRisk(
            user_id=u,
            critical=c["critical"],
            high=c["high"],
            elevated=c["critical"] >= CRITICAL_AT or c["high"] >= HIGH_AT,
            score=score_of(items, now),
            last_ts=max(_aware(ts) for _, ts in items),
        )
    return out


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
    """Everyone with a high or critical finding in the window, riskiest first (elevated, then score)."""
    return sorted(scores(db).values(), key=lambda r: (-r.elevated, -r.score, -r.critical, -r.high, r.user_id))
