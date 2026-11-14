"""Approval audit (C): what people allowed their agents to do, for after-the-fact review.

Policy decision (2026-11-11): users approve risky actions themselves; security audits afterwards and
acts on anything odd. This view joins each ``approval.resolved`` event with

- the held ``tool.call`` (tool, redacted arguments) and the findings that asked for approval,
- the audit findings it raised (``user-approved-high-risk``, ``approval-fatigue``),
- who actually pressed the button: the audit proxy's ``operator.action`` for the same tool call
  (team gateway, M5b). Without it ``approver`` is whatever the agent reported, usually nothing.

The console (M7) renders this endpoint; ``sga-server audit approvals`` prints it.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from . import audit_chain
from .auth import DbSession, require_admin
from .db import ApprovalReview, EventRow, FindingRow, utcnow

router = APIRouter(prefix="/v1/admin", tags=["admin"], dependencies=[Depends(require_admin)])
AUDIT_RULES = ("user-approved-high-risk", "approval-fatigue")
# Decision 2026-11-14: the person approves first; security reviews every approval of a high or critical
# call afterwards (the review queue). Only very high risk is blocked outright by the rules.
REVIEW_SEVERITIES = ("high", "critical")
ReviewFilter = Literal["pending", "ok", "problem"]
_ACTION_SLACK = timedelta(hours=1)  # the person's answer is recorded before the plugin's own event


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HeldCall(_Model):
    event_id: str
    ts: datetime
    tool: str
    arguments: dict[str, Any]


class FindingRef(_Model):
    finding_id: str
    rule_id: str
    severity: str
    title: str


class ReviewOut(_Model):
    status: str  # ok | problem
    by: str
    reason: str
    at: datetime


class ReviewIn(_Model):
    status: Literal["ok", "problem"]
    by: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=1000)


class ApprovalOut(_Model):
    event_id: str
    ts: datetime
    device_id: str
    user_id: str
    session_id: str
    call_id: str
    tool: str
    decision: str
    approved: bool
    judged_by: str
    rule_ids: list[str]
    max_severity: str | None
    wait_ms: int | None
    requester: dict[str, str]  # channel / sender id that started the run
    approver: str | None
    approver_source: str | None  # "audit_proxy" (identity-proxy header) or "agent" (self-reported)
    held_call: HeldCall | None
    asked_by: list[FindingRef]  # findings that put the call on hold
    flagged: list[FindingRef]  # audit findings raised by this answer
    needs_review: bool = False  # approved, high or critical: on security's review queue
    review: ReviewOut | None = None


def needs_review(payload: dict[str, Any]) -> bool:
    return payload.get("approved") is True and payload.get("max_severity") in REVIEW_SEVERITIES


def _review_out(r: ApprovalReview) -> ReviewOut:
    return ReviewOut(status=r.status, by=r.reviewed_by, reason=r.reason, at=r.reviewed_at)


def _ref(doc: dict[str, Any]) -> FindingRef:
    return FindingRef(
        finding_id=doc["finding_id"], rule_id=doc["rule_id"], severity=doc["severity"], title=doc["title"]
    )


@router.get("/approvals", response_model=list[ApprovalOut])
def list_approvals(
    db: DbSession,
    user_id: str | None = None,
    device_id: str | None = None,
    decision: str | None = None,
    approved: bool | None = None,
    since: datetime | None = None,
    review: ReviewFilter | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[ApprovalOut]:
    """Newest first. ``approved=true`` is the usual audit view; ``review=pending`` is security's queue
    (approved high/critical calls nobody has reviewed yet)."""
    q = select(EventRow).where(EventRow.kind == "approval.resolved")
    for col, val in ((EventRow.user_id, user_id), (EventRow.device_id, device_id)):
        if val is not None:
            q = q.where(col == val)
    if since is not None:
        q = q.where(EventRow.ts >= since)
    rows = list(db.scalars(q.order_by(EventRow.ts.desc(), EventRow.event_id)))
    docs = [r.doc for r in rows]
    if decision is not None:
        docs = [d for d in docs if d["payload"]["decision"] == decision]
    if approved is not None:
        docs = [d for d in docs if d["payload"]["approved"] is approved]
    reviews = {
        r.approval_event_id: r
        for r in db.scalars(
            select(ApprovalReview).where(ApprovalReview.approval_event_id.in_([d["event_id"] for d in docs]))
        )
    }
    if review == "pending":
        docs = [d for d in docs if needs_review(d["payload"]) and d["event_id"] not in reviews]
    elif review is not None:
        docs = [d for d in docs if (r := reviews.get(d["event_id"])) is not None and r.status == review]
    docs = docs[offset : offset + limit]
    if not docs:
        return []

    held_ids = [d["payload"]["request_event_id"] for d in docs if d["payload"].get("request_event_id")]
    held = {e.event_id: e.doc for e in db.scalars(select(EventRow).where(EventRow.event_id.in_(held_ids)))}
    asked_ids = [fid for d in docs for fid in d["payload"].get("finding_ids", [])]
    asked = {
        f.finding_id: f.doc
        for f in db.scalars(select(FindingRow).where(FindingRow.finding_id.in_(asked_ids)))
    }
    devices = {d["endpoint"]["device_id"] for d in docs}
    flags: dict[str, list[FindingRef]] = {}
    audit_q = select(FindingRow).where(FindingRow.rule_id.in_(AUDIT_RULES), FindingRow.device_id.in_(devices))
    for f in db.scalars(audit_q):
        for eid in f.doc.get("evidence_event_ids", []):
            flags.setdefault(eid, []).append(_ref(f.doc))

    # Who answered: the audit proxy saw the person's own client send the decision.
    call_ids = {d["payload"]["call_id"] for d in docs}
    oldest = min(datetime.fromisoformat(str(d["ts"]).replace("Z", "+00:00")) for d in docs)
    actions: dict[tuple[str, str], str] = {}
    action_q = select(EventRow).where(
        EventRow.kind == "operator.action", EventRow.ts >= oldest - _ACTION_SLACK
    )
    for a in db.scalars(action_q.order_by(EventRow.ts)):
        ap = a.doc["payload"]
        if (
            ap.get("action") == "approval.resolve"
            and ap.get("call_id") in call_ids
            and ap.get("ok") is not False
        ):
            actions[(ap["call_id"], ap.get("decision") or "")] = a.doc["principal"]["user_id"]

    out = []
    for d in docs:
        p = d["payload"]
        operator = actions.get((p["call_id"], p["decision"]))
        h = held.get(p.get("request_event_id") or "")
        out.append(
            ApprovalOut(
                event_id=d["event_id"],
                ts=d["ts"],
                device_id=d["endpoint"]["device_id"],
                user_id=d["principal"]["user_id"],
                session_id=d["agent"]["session_id"],
                call_id=p["call_id"],
                tool=p["tool"],
                decision=p["decision"],
                approved=p["approved"],
                judged_by=p.get("judged_by", "daemon"),
                rule_ids=list(p.get("rule_ids", [])),
                max_severity=p.get("max_severity"),
                wait_ms=p.get("wait_ms"),
                requester={
                    k.removeprefix("requester_"): v
                    for k, v in d.get("labels", {}).items()
                    if k.startswith("requester_")
                },
                approver=operator or p.get("approver"),
                approver_source="audit_proxy" if operator else ("agent" if p.get("approver") else None),
                held_call=HeldCall(
                    event_id=h["event_id"],
                    ts=h["ts"],
                    tool=h["payload"]["tool"],
                    arguments=h["payload"]["arguments"],
                )
                if h
                else None,
                asked_by=[_ref(asked[i]) for i in p.get("finding_ids", []) if i in asked],
                flagged=flags.get(d["event_id"], []),
                needs_review=needs_review(p),
                review=_review_out(r) if (r := reviews.get(d["event_id"])) else None,
            )
        )
    return out


@router.get("/approvals/review-count")
def review_count(db: DbSession) -> dict[str, int]:
    """Approved high/critical calls security has not reviewed yet (the console's overview tile)."""
    reviewed = set(db.scalars(select(ApprovalReview.approval_event_id)))
    rows = db.scalars(select(EventRow).where(EventRow.kind == "approval.resolved"))
    return {"pending": sum(1 for r in rows if needs_review(r.doc["payload"]) and r.event_id not in reviewed)}


@router.post("/approvals/{event_id}/review", response_model=ReviewOut)
def review_approval(event_id: str, body: ReviewIn, request: Request, db: DbSession) -> ReviewOut:
    """Security's verdict on a person's approval. ``problem`` is followed by a response (block the person
    or conversation from the finding page); the review itself changes nothing on the device."""
    if request.state.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "reviewing needs the admin token")
    row = db.get(EventRow, event_id)
    if row is None or row.kind != "approval.resolved":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "approval not found")
    if db.get(ApprovalReview, event_id) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "already reviewed")
    r = ApprovalReview(
        approval_event_id=event_id,
        user_id=row.doc["principal"]["user_id"],
        status=body.status,
        reviewed_by=body.by,
        reason=body.reason,
        reviewed_at=utcnow(),
    )
    db.add(r)
    p = row.doc["payload"]
    audit_chain.append(
        db,
        "approval_review",
        event_id,
        {
            "status": r.status,
            "by": r.reviewed_by,
            "reason": r.reason,
            "at": r.reviewed_at,
            "user_id": r.user_id,
            "tool": p.get("tool"),
            "rule_ids": p.get("rule_ids", []),
            "call_id": p.get("call_id"),
        },
    )
    db.commit()
    return _review_out(r)
