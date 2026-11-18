"""Shared redacted event/finding storage for sensors and protected-resource enforcement."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.orm import Session

from ..redact import redact_event, redact_text
from ..schema import AgentEvent, Finding
from . import audit_chain
from .access import collection_identity
from .db import Device, EventRow, FindingRow


def store_event(
    db: Session, device: Device, event: AgentEvent, now: datetime, *, server_built: bool = False
) -> AgentEvent:
    stored = redact_event(event).model_copy(update={"received_ts": now})
    stored, project_id, actor_id = collection_identity(db, device, stored, server_built=server_built)
    db.add(
        EventRow(
            event_id=stored.event_id,
            device_id=device.device_id,
            ts=stored.ts,
            received_ts=now,
            kind=str(stored.kind),
            user_id=stored.principal.user_id,
            agent_type=str(stored.agent.type),
            session_id=stored.agent.session_id,
            sensor=str(stored.source.sensor),
            project_id=project_id,
            actor_id=actor_id,
            doc=stored.model_dump(mode="json"),
        )
    )
    return stored


def store_finding(
    db: Session, device_id: str, f: Finding, now: datetime, *, server_built: bool = False
) -> Finding:
    if f.explanation:
        f = f.model_copy(update={"explanation": redact_text(f.explanation)})
    device = db.get(Device, device_id)
    assert device is not None
    f, project_id, actor_id = collection_identity(db, device, f, server_built=server_built)
    if f.detector != "local":
        # Cross-project campaign aggregates need a separate scoped derivation before disclosure.
        project_id, actor_id = None, None
    db.add(
        FindingRow(
            finding_id=f.finding_id,
            device_id=device_id,
            ts=f.ts,
            received_ts=now,
            rule_id=f.rule_id,
            severity=str(f.severity),
            category=str(f.category),
            user_id=f.principal.user_id,
            agent_type=str(f.agent.type),
            session_id=f.agent.session_id,
            project_id=project_id,
            actor_id=actor_id,
            doc=f.model_dump(mode="json"),
        )
    )
    audit_chain.append(db, "finding", f.finding_id, f.model_dump(mode="json"), snapshot=False)
    return f
