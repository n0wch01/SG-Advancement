"""Approval-fatigue metrics (2026-11-13).

KISA 「에이전틱 AI 제로트러스트 안내서」 C2: 승인 소요 시간, 동일 유형 요청의 반복 빈도, 반려율 등
승인 피로를 나타내는 측정값이 있어야 개입 수준을 최적화할 수 있다. 금융보안원 ⑭ 인적 개입 과부하 방지.

Two channels: the person in the agent's own prompt (``approval.resolved`` with via=user) and security
in the console (security approvals). Per channel: how many, how long people took, how often they
said no, and how many approvals came faster than anyone can read (``FAST_SECONDS``). Repeated request
types (same rules + tool) that are almost always approved are *automation candidates*: the rule may
deserve tuning so people only see what matters. The metrics advise; the rules stay the user's call.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta
from statistics import median
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from .auth import DbSession, require_admin
from .db import EventRow, SecurityApproval, utcnow
from .security_approvals import shown_status

router = APIRouter(prefix="/v1/admin", tags=["audit"], dependencies=[Depends(require_admin)])

FAST_SECONDS = 5.0  # approved before anyone could have read the request
CANDIDATE_MIN = 5  # a request type seen at least this often…
CANDIDATE_RATE = 0.95  # …and approved this often is worth a look


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ChannelStats(_Model):
    requests: int
    approved: int
    denied: int
    unanswered: int  # timed out, cancelled, expired
    rejection_rate: float | None  # denied / (approved + denied)
    median_wait_s: float | None
    p90_wait_s: float | None
    fast_approvals: int
    fast_approval_rate: float | None  # fast / approved


class RepeatedType(_Model):
    channel: str
    tool: str
    rule_ids: list[str]
    requests: int
    approval_rate: float
    people: int
    automation_candidate: bool


class PersonLoad(_Model):
    user_id: str
    requests: int
    busiest_day: int
    fast_approval_rate: float | None


class ApprovalMetrics(_Model):
    window_days: int
    since: datetime
    user: ChannelStats
    security: ChannelStats
    repeated: list[RepeatedType]
    people: list[PersonLoad]


def _p90(xs: list[float]) -> float | None:
    if not xs:
        return None
    s = sorted(xs)
    return round(s[min(len(s) - 1, int(0.9 * len(s)))], 1)


def _stats(rows: list[dict[str, Any]]) -> ChannelStats:
    approved = [r for r in rows if r["outcome"] == "approved"]
    denied = sum(r["outcome"] == "denied" for r in rows)
    waits = [r["wait_s"] for r in rows if r["wait_s"] is not None and r["outcome"] != "unanswered"]
    fast = sum(1 for r in approved if r["wait_s"] is not None and r["wait_s"] < FAST_SECONDS)
    decided = len(approved) + denied
    return ChannelStats(
        requests=len(rows),
        approved=len(approved),
        denied=denied,
        unanswered=len(rows) - decided,
        rejection_rate=round(denied / decided, 3) if decided else None,
        median_wait_s=round(median(waits), 1) if waits else None,
        p90_wait_s=_p90(waits),
        fast_approvals=fast,
        fast_approval_rate=round(fast / len(approved), 3) if approved else None,
    )


def collect(db: Session, since: datetime, now: datetime) -> list[dict[str, Any]]:
    """One row per answered-or-not approval request, both channels."""
    rows: list[dict[str, Any]] = []
    q = select(EventRow).where(EventRow.kind == "approval.resolved", EventRow.ts >= since)
    for e in db.scalars(q):
        p = e.doc["payload"]
        if p.get("via", "user") != "user":
            continue  # security's answers are counted from the approvals table below
        outcome = "approved" if p["approved"] else "denied" if p["decision"] == "deny" else "unanswered"
        rows.append(
            {
                "channel": "user", "user": e.user_id, "day": e.ts.date(), "tool": p["tool"],
                "rules": tuple(p.get("rule_ids") or ()), "outcome": outcome,
                "wait_s": p["wait_ms"] / 1000 if p.get("wait_ms") is not None else None,
            }
        )  # fmt: skip
    for a in db.scalars(select(SecurityApproval).where(SecurityApproval.created_at >= since)):
        status = shown_status(a, now)
        if status == "pending":
            continue
        outcome = status if status in ("approved", "denied") else "unanswered"
        wait = (a.decided_at - a.created_at).total_seconds() if a.decided_at else None
        rows.append(
            {
                "channel": "security", "user": a.user_id, "day": a.created_at.date(), "tool": a.tool,
                "rules": tuple(a.rule_ids or ()), "outcome": outcome, "wait_s": wait,
            }
        )  # fmt: skip
    return rows


def metrics(db: Session, days: int = 7, now: datetime | None = None) -> ApprovalMetrics:
    now = now or utcnow()
    since = now - timedelta(days=days)
    rows = collect(db, since, now)
    by_type: dict[tuple[str, str, tuple[str, ...]], list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        by_type[(r["channel"], r["tool"], r["rules"])].append(r)
    repeated = []
    for (channel, tool, rules), rs in by_type.items():
        approved = sum(r["outcome"] == "approved" for r in rs)
        rate = approved / len(rs)
        repeated.append(
            RepeatedType(
                channel=channel, tool=tool, rule_ids=list(rules), requests=len(rs),
                approval_rate=round(rate, 3), people=len({r["user"] for r in rs}),
                automation_candidate=len(rs) >= CANDIDATE_MIN and rate >= CANDIDATE_RATE,
            )
        )  # fmt: skip
    repeated.sort(key=lambda t: (-t.requests, t.tool))
    people = []
    user_rows = [r for r in rows if r["channel"] == "user"]
    for user in {r["user"] for r in user_rows}:
        mine = [r for r in user_rows if r["user"] == user]
        per_day = Counter(r["day"] for r in mine)
        people.append(
            PersonLoad(
                user_id=user, requests=len(mine), busiest_day=max(per_day.values()),
                fast_approval_rate=_stats(mine).fast_approval_rate,
            )
        )  # fmt: skip
    people.sort(key=lambda p: (-p.requests, p.user_id))
    return ApprovalMetrics(
        window_days=days,
        since=since,
        user=_stats(user_rows),
        security=_stats([r for r in rows if r["channel"] == "security"]),
        repeated=repeated[:10],
        people=people[:10],
    )


@router.get("/approvals/metrics", response_model=ApprovalMetrics)
def approval_metrics(db: DbSession, days: Annotated[int, Query(ge=1, le=90)] = 7) -> ApprovalMetrics:
    return metrics(db, days)
