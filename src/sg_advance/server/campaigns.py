"""Campaign detection (M11): the same threat reaching several people.

A finding of a rule tagged ``campaign`` carries what matched as ``labels.indicator`` (the
detection engine fills it: a host, a plugin id, an injection phrase…). When the same rule and the
same indicator show up for at least ``MIN_USERS`` distinct people within ``WINDOW``, the control
plane records one central finding (``detector: central``, rule ``multi-user-campaign``).

Decision 2026-11-12: 3 people within 24 hours, severity at least high. One campaign finding per
(rule, indicator) per window; people who join later show up in its member list
(``GET /v1/admin/findings/{id}/campaign``), not as new findings.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..detect.engine import INDICATOR
from ..schema import Finding, Severity
from .db import FindingIndicator, FindingRow

RULE_ID = "multi-user-campaign"
MIN_USERS = 3
WINDOW = timedelta(hours=24)
MAX_EVIDENCE = 50
# Not a person: the same "unknown" on many devices is not many people.
NOT_A_PERSON = {"", "unknown"}


def indicators(f: Finding) -> list[str]:
    return [v for v in f.labels.get(INDICATOR, "").split("\n") if v]


def record(db: Session, f: Finding) -> None:
    """Index the indicators of a finding a sensor just sent (its FindingRow is in the session)."""
    for value in indicators(f):
        db.add(
            FindingIndicator(
                finding_id=f.finding_id,
                rule_id=f.rule_id,
                indicator=value,
                user_id=f.principal.user_id,
                ts=f.ts,
            )
        )


def members(
    db: Session, rule_id: str, indicator: str, start: datetime, end: datetime
) -> list[FindingIndicator]:
    return list(
        db.scalars(
            select(FindingIndicator)
            .where(
                FindingIndicator.rule_id == rule_id,
                FindingIndicator.indicator == indicator,
                FindingIndicator.ts >= start,
                FindingIndicator.ts <= end,
            )
            .order_by(FindingIndicator.ts)
        )
    )


def people(rows: Sequence[FindingIndicator]) -> list[str]:
    return sorted({r.user_id for r in rows} - NOT_A_PERSON)


def _already_reported(db: Session, rule_id: str, indicator: str, since: datetime) -> bool:
    for doc in db.scalars(
        select(FindingRow.doc).where(FindingRow.rule_id == RULE_ID, FindingRow.ts >= since)
    ):
        labels = doc.get("labels") or {}
        if labels.get("source_rule") == rule_id and labels.get(INDICATOR) == indicator:
            return True
    return False


def detect(db: Session, new: Sequence[tuple[str, Finding]]) -> list[tuple[str, Finding]]:
    """Campaign findings the batch ``new`` ((device_id, finding), already flushed) completes."""
    latest: dict[tuple[str, str], tuple[str, Finding]] = {}
    for device_id, f in new:
        for value in indicators(f):
            key = (f.rule_id, value)
            if key not in latest or f.ts >= latest[key][1].ts:
                latest[key] = (device_id, f)
    out: list[tuple[str, Finding]] = []
    for (rule_id, value), (device_id, trigger) in sorted(latest.items()):
        rows = members(db, rule_id, value, trigger.ts - WINDOW, trigger.ts)
        who = people(rows)
        if len(who) < MIN_USERS or _already_reported(db, rule_id, value, trigger.ts - WINDOW):
            continue
        out.append((device_id, _campaign(db, trigger, value, who, rows)))
    return out


def _campaign(
    db: Session, trigger: Finding, value: str, who: list[str], rows: Sequence[FindingIndicator]
) -> Finding:
    ids = list(dict.fromkeys(r.finding_id for r in rows))
    evidence: list[str] = []
    for doc in db.scalars(select(FindingRow.doc).where(FindingRow.finding_id.in_(ids))):
        evidence.extend(doc.get("evidence_event_ids") or ())
    severity = max(Severity.HIGH, Severity(trigger.severity), key=lambda s: s.rank)
    return Finding(
        ts=trigger.ts,
        rule_id=RULE_ID,
        severity=severity,
        category=trigger.category,
        title=f"여러 사람에게 같은 위협: {trigger.title}",
        message=f"{int(WINDOW.total_seconds() // 3600)}시간 안에 {len(who)}명에게 같은 지표가 나타났습니다.",
        recommended_action=(
            "지표(호스트·문서·플러그인 등)의 출처를 확인하고 막으세요. 영향받은 사람들의 Finding에서 "
            "대화나 사람을 차단할 수 있습니다."
        ),
        explanation=f"{trigger.rule_id}: «{value}» — {len(who)} people: {', '.join(who)}",
        detector="central",
        evidence_event_ids=tuple(dict.fromkeys(evidence))[:MAX_EVIDENCE],
        endpoint=trigger.endpoint,
        principal=trigger.principal,
        agent=trigger.agent,
        tags=tuple(dict.fromkeys((*trigger.tags, "campaign"))),
        labels={
            "source_rule": trigger.rule_id,
            INDICATOR: value,
            "people": ",".join(who),
            "people_count": str(len(who)),
            "findings": ",".join(ids),
        },
    )
