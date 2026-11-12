"""SGA-Dashboard API (M7): what the web console needs beyond the plain lists.

- ``GET /v1/admin/whoami``: the role of the presented token (``admin`` or read-only ``viewer``).
- ``GET /v1/admin/summary``: counts for the overview (findings by severity / rule / person, events,
  devices) and the latest findings, optionally since a point in time.
- ``GET /v1/admin/findings/{finding_id}``: one finding with its evidence events, the conversation's
  surrounding events and the other findings of that conversation.

All routes are reads, so the read-only dashboard token can use them (``auth.require_admin``).
Events and findings are stored already masked by the sensors; nothing here unmasks anything.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy import func, select

from ..schema import Severity
from .auth import DbSession, require_admin
from .db import Device, EventRow, FindingRow

router = APIRouter(prefix="/v1/admin", tags=["dashboard"], dependencies=[Depends(require_admin)])

ACTIVE_WINDOW = timedelta(minutes=15)  # a device that synced within this is "active"
SEVERITY_ORDER = [str(s) for s in Severity]  # low → critical


class WhoAmI(BaseModel):
    role: str


class RuleCount(BaseModel):
    rule_id: str
    title: str
    severity: str
    count: int
    last_ts: datetime


class UserCount(BaseModel):
    user_id: str
    count: int
    max_severity: str
    last_ts: datetime


class FindingStats(BaseModel):
    total: int
    by_severity: dict[str, int]
    by_category: dict[str, int]
    top_rules: list[RuleCount]
    top_users: list[UserCount]


class EventStats(BaseModel):
    total: int
    by_kind: dict[str, int]


class DeviceStats(BaseModel):
    total: int
    active: int
    policy_current: int


class Summary(BaseModel):
    since: datetime | None
    generated_at: datetime
    findings: FindingStats
    events: EventStats
    devices: DeviceStats
    recent: list[dict[str, Any]]


class FindingDetail(BaseModel):
    finding: dict[str, Any]
    evidence: list[dict[str, Any]]
    session_events: list[dict[str, Any]]
    session_findings: list[dict[str, Any]]


@router.get("/whoami", response_model=WhoAmI)
def whoami(request: Request) -> WhoAmI:
    return WhoAmI(role=request.state.role)


def _max_severity(values: list[str]) -> str:
    return max(values, key=lambda s: SEVERITY_ORDER.index(s) if s in SEVERITY_ORDER else -1)


@router.get("/summary", response_model=Summary)
def summary(
    request: Request,
    db: DbSession,
    since: datetime | None = None,
    top: Annotated[int, Query(ge=1, le=50)] = 8,
    recent: Annotated[int, Query(ge=0, le=50)] = 10,
) -> Summary:
    now = datetime.now(UTC)
    fwhere = [FindingRow.ts >= since] if since else []
    ewhere = [EventRow.ts >= since] if since else []

    def counts(column: Any, model: Any, where: list[Any]) -> dict[str, int]:
        q = select(column, func.count()).select_from(model).where(*where).group_by(column)
        return {k: n for k, n in db.execute(q)}

    by_severity = {s: 0 for s in reversed(SEVERITY_ORDER)} | counts(FindingRow.severity, FindingRow, fwhere)
    by_rule = db.execute(
        select(FindingRow.rule_id, func.count(), func.max(FindingRow.ts))
        .where(*fwhere)
        .group_by(FindingRow.rule_id)
        .order_by(func.count().desc(), FindingRow.rule_id)
        .limit(top)
    ).all()
    top_rules = []
    for rule_id, n, last in by_rule:
        doc = db.scalar(
            select(FindingRow.doc)
            .where(FindingRow.rule_id == rule_id)
            .order_by(FindingRow.ts.desc())
            .limit(1)
        )
        top_rules.append(
            RuleCount(rule_id=rule_id, title=doc["title"], severity=doc["severity"], count=n, last_ts=last)
        )
    per_user: dict[str, dict[str, Any]] = {}
    for user, sev, n, last in db.execute(
        select(FindingRow.user_id, FindingRow.severity, func.count(), func.max(FindingRow.ts))
        .where(*fwhere)
        .group_by(FindingRow.user_id, FindingRow.severity)
    ):
        row = per_user.setdefault(user, {"count": 0, "severities": [], "last_ts": last})
        row["count"] += n
        row["severities"].append(sev)
        row["last_ts"] = max(row["last_ts"], last)
    top_users = sorted(
        (
            UserCount(
                user_id=u,
                count=r["count"],
                max_severity=_max_severity(r["severities"]),
                last_ts=r["last_ts"],
            )
            for u, r in per_user.items()
        ),
        key=lambda u: (-SEVERITY_ORDER.index(u.max_severity), -u.count, u.user_id),
    )[:top]

    current = request.app.state.policy.version
    devices = list(db.scalars(select(Device)))
    active_after = now - ACTIVE_WINDOW
    latest = db.scalars(
        select(FindingRow.doc)
        .where(*fwhere)
        .order_by(FindingRow.ts.desc(), FindingRow.finding_id)
        .limit(recent)
    )
    by_kind = counts(EventRow.kind, EventRow, ewhere)
    return Summary(
        since=since,
        generated_at=now,
        findings=FindingStats(
            total=sum(by_severity.values()),
            by_severity=by_severity,
            by_category=counts(FindingRow.category, FindingRow, fwhere),
            top_rules=top_rules,
            top_users=top_users,
        ),
        events=EventStats(total=sum(by_kind.values()), by_kind=by_kind),
        devices=DeviceStats(
            total=len(devices),
            active=sum(1 for d in devices if d.last_seen and _aware(d.last_seen) >= active_after),
            policy_current=sum(1 for d in devices if d.policy_version == current),
        ),
        recent=list(latest),
    )


def _aware(ts: datetime) -> datetime:
    return ts if ts.tzinfo else ts.replace(tzinfo=UTC)


@router.get("/findings/{finding_id}", response_model=FindingDetail)
def finding_detail(
    finding_id: str,
    db: DbSession,
    context: Annotated[int, Query(ge=0, le=200)] = 40,
) -> FindingDetail:
    row = db.get(FindingRow, finding_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    doc = row.doc
    ids = list(doc.get("evidence_event_ids") or [])
    evidence = {e.event_id: e.doc for e in db.scalars(select(EventRow).where(EventRow.event_id.in_(ids)))}
    # The conversation around it: the latest events up to the finding, oldest first.
    same = (EventRow.device_id == row.device_id, EventRow.session_id == row.session_id)
    window = list(
        db.scalars(
            select(EventRow.doc)
            .where(*same, EventRow.ts <= row.ts)
            .order_by(EventRow.ts.desc(), EventRow.event_id)
            .limit(context)
        )
    )
    others = db.scalars(
        select(FindingRow.doc)
        .where(
            FindingRow.device_id == row.device_id,
            FindingRow.session_id == row.session_id,
            FindingRow.finding_id != finding_id,
        )
        .order_by(FindingRow.ts.desc())
        .limit(50)
    )
    return FindingDetail(
        finding=doc,
        evidence=[evidence[i] for i in ids if i in evidence],
        session_events=list(reversed(window)),
        session_findings=list(others),
    )
