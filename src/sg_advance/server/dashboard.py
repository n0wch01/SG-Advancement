"""SGA-Dashboard API (M7): what the web console needs beyond the plain lists.

- ``GET /v1/admin/whoami``: the role of the presented token (``admin`` or read-only ``viewer``).
- ``GET /v1/admin/summary``: counts for the overview (findings by severity / rule / person, events,
  devices) and the latest findings, optionally since a point in time.
- ``GET /v1/admin/findings/{finding_id}``: one finding with its evidence events, the conversation's
  surrounding events and the other findings of that conversation.
- ``GET /v1/admin/inventory``: per device, the latest state snapshots the sensors sent: agent installs
  (``install.snapshot``), agents (``inventory.snapshot``), config baseline and code integrity.
- ``GET /v1/admin/timeline``: one person's activity, or one conversation with every sub-agent
  conversation delegated from it (T18 delegation tree), as events + findings in time order.

All routes are reads, so the read-only dashboard token can use them (``auth.require_admin``).
Events and findings are stored already masked by the sensors; nothing here unmasks anything.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy import func, or_, select

from ..schema import Severity
from .auth import DbSession, require_admin
from .db import Device, EventRow, FindingRow
from .policy_admin import policy_for

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
            policy_current=sum(
                1 for d in devices if d.policy_version == policy_for(request.app, d.group_name).version
            ),
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


SNAPSHOT_KINDS = ("install.snapshot", "inventory.snapshot", "config.snapshot", "integrity.report")


class Snapshot(BaseModel):
    ts: datetime
    user_id: str
    session_id: str
    payload: dict[str, Any]


class DeviceInventory(BaseModel):
    device_id: str
    hostname: str | None
    sensor_version: str | None
    enrolled_at: datetime
    last_seen: datetime | None
    policy_current: bool
    installs: list[Snapshot]
    agents: list[Snapshot]
    configs: list[Snapshot]
    integrity: list[Snapshot]
    open_findings: dict[str, int]  # findings per severity, last 7 days


@router.get("/inventory", response_model=list[DeviceInventory])
def inventory(request: Request, db: DbSession) -> list[DeviceInventory]:
    """Latest snapshot per (device, kind, session): one row per install instance, per agent, ..."""
    latest = (
        select(EventRow.device_id, EventRow.kind, EventRow.session_id, func.max(EventRow.ts).label("ts"))
        .where(EventRow.kind.in_(SNAPSHOT_KINDS))
        .group_by(EventRow.device_id, EventRow.kind, EventRow.session_id)
        .subquery()
    )
    rows = db.scalars(
        select(EventRow).join(
            latest,
            (EventRow.device_id == latest.c.device_id)
            & (EventRow.kind == latest.c.kind)
            & (EventRow.session_id == latest.c.session_id)
            & (EventRow.ts == latest.c.ts),
        )
    )
    per: dict[str, dict[str, dict[str, Snapshot]]] = {}
    for r in rows:
        snap = Snapshot(ts=r.ts, user_id=r.user_id, session_id=r.session_id, payload=r.doc["payload"])
        per.setdefault(r.device_id, {}).setdefault(r.kind, {})[r.session_id] = snap  # ts ties: keep one
    week = datetime.now(UTC) - timedelta(days=7)
    sev: dict[str, dict[str, int]] = {}
    for device, severity, n in db.execute(
        select(FindingRow.device_id, FindingRow.severity, func.count())
        .where(FindingRow.ts >= week)
        .group_by(FindingRow.device_id, FindingRow.severity)
    ):
        sev.setdefault(device, {})[severity] = n

    def snaps(device: str, kind: str) -> list[Snapshot]:
        return sorted(per.get(device, {}).get(kind, {}).values(), key=lambda x: x.session_id)

    return [
        DeviceInventory(
            device_id=d.device_id,
            hostname=d.hostname,
            sensor_version=d.sensor_version,
            enrolled_at=d.enrolled_at,
            last_seen=d.last_seen,
            policy_current=d.policy_version == policy_for(request.app, d.group_name).version,
            installs=snaps(d.device_id, "install.snapshot"),
            agents=snaps(d.device_id, "inventory.snapshot"),
            configs=snaps(d.device_id, "config.snapshot"),
            integrity=snaps(d.device_id, "integrity.report"),
            open_findings=sev.get(d.device_id, {}),
        )
        for d in db.scalars(select(Device).order_by(Device.device_id))
    ]


# State snapshots are per device/agent, not something a person did in a conversation.
NOT_ACTIVITY = (*SNAPSHOT_KINDS, "sensor.health")


class SessionNode(BaseModel):
    session_id: str
    device_ids: list[str]  # gateway and audit proxy both record a team conversation
    agent_type: str
    parent_session_id: str | None
    root_session_id: str | None
    spawn_depth: int | None
    user_ids: list[str]
    first_ts: datetime
    last_ts: datetime
    events: int
    findings: int
    max_severity: str | None


class Timeline(BaseModel):
    user_id: str | None
    session_id: str | None
    truncated: bool
    sessions: list[SessionNode]
    events: list[dict[str, Any]]
    findings: list[dict[str, Any]]


def _lineage(column: Any, key: str) -> Any:
    return column["agent"][key].as_string()


@router.get("/timeline", response_model=Timeline)
def timeline(
    db: DbSession,
    user_id: str | None = None,
    session_id: str | None = None,
    since: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=2000)] = 500,
) -> Timeline:
    """Oldest first. ``session_id``: that conversation and its delegation tree (children found by
    ``agent.parent_session_id`` / ``root_session_id``). ``user_id``: everything attributed to that person.
    Both: the person's part of that tree. The newest ``limit`` events are kept (``truncated``)."""
    if not (user_id or session_id):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "give user_id or session_id")
    ev_where: list[Any] = [EventRow.kind.not_in(NOT_ACTIVITY)]
    f_where: list[Any] = []
    if session_id:
        # Walk down the delegation tree: children name their parent (and the root) on every event.
        tree = {session_id}
        frontier = {session_id}
        while frontier and len(tree) < 200:
            kids = set(
                db.scalars(
                    select(EventRow.session_id)
                    .where(
                        or_(
                            _lineage(EventRow.doc, "parent_session_id").in_(frontier),
                            _lineage(EventRow.doc, "root_session_id").in_(frontier),
                        )
                    )
                    .distinct()
                )
            )
            frontier = kids - tree
            tree |= kids
        ev_where.append(EventRow.session_id.in_(tree))
        f_where.append(FindingRow.session_id.in_(tree))
    if user_id:
        ev_where.append(EventRow.user_id == user_id)
        f_where.append(FindingRow.user_id == user_id)
    if since:
        ev_where.append(EventRow.ts >= since)
        f_where.append(FindingRow.ts >= since)

    rows = list(
        db.scalars(
            select(EventRow).where(*ev_where).order_by(EventRow.ts.desc(), EventRow.event_id).limit(limit + 1)
        )
    )
    truncated = len(rows) > limit
    rows = rows[:limit]
    oldest = rows[-1].ts if (truncated and rows) else None
    if oldest is not None:
        f_where.append(FindingRow.ts >= oldest)
    findings = list(
        db.scalars(select(FindingRow).where(*f_where).order_by(FindingRow.ts, FindingRow.finding_id))
    )

    nodes: dict[str, dict[str, Any]] = {}
    for r in reversed(rows):
        agent = r.doc["agent"]
        n = nodes.setdefault(
            r.session_id,
            {
                "session_id": r.session_id,
                "device_ids": [],
                "agent_type": r.agent_type,
                "parent_session_id": None,
                "root_session_id": None,
                "spawn_depth": None,
                "user_ids": [],
                "first_ts": r.ts,
                "last_ts": r.ts,
                "events": 0,
                "findings": 0,
                "max_severity": None,
            },
        )
        for key in ("parent_session_id", "root_session_id", "spawn_depth"):
            if agent.get(key) is not None:
                n[key] = agent[key]
        if r.user_id not in n["user_ids"]:
            n["user_ids"].append(r.user_id)
        if r.device_id not in n["device_ids"]:
            n["device_ids"].append(r.device_id)
        n["last_ts"] = r.ts
        n["events"] += 1
    for f in findings:
        n = nodes.get(f.session_id)
        if n is None:
            continue
        n["findings"] += 1
        n["max_severity"] = _max_severity([x for x in (n["max_severity"], f.severity) if x])
    return Timeline(
        user_id=user_id,
        session_id=session_id,
        truncated=truncated,
        sessions=[SessionNode(**n) for n in sorted(nodes.values(), key=lambda n: n["first_ts"])],
        events=[r.doc for r in reversed(rows)],
        findings=[f.doc for f in findings],
    )
