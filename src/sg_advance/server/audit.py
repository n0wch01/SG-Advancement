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
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select

from .auth import DbSession, require_admin
from .db import EventRow, FindingRow

router = APIRouter(prefix="/v1/admin", tags=["admin"], dependencies=[Depends(require_admin)])
AUDIT_RULES = ("user-approved-high-risk", "approval-fatigue")
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
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[ApprovalOut]:
    """Newest first. ``approved=true`` is the usual audit view."""
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
            )
        )
    return out
