"""Tamper-evident audit trail (2026-11-13). KISA 「에이전틱 AI 제로트러스트 안내서」 C1-6: audit logs must
resist tampering or let tampering be verified; 금융보안원 ⑰ 로깅 및 감사체계.

What is chained: findings, remote actions (and their results), security-approval decisions and
policy changes. Each is appended inside the request's own transaction with a sha256 ``digest`` of
its canonical JSON; ``seal`` then links unsealed rows in ``seq`` order under a lock:

    hash = sha256(prev_hash | seq | kind | ref_id | digest | ts)

``verify`` recomputes every link and every digest (findings against the stored finding, the others
against the snapshot kept in the row). Changing, deleting or reordering any record or chain row
breaks the chain from there on. Limit: cutting rows off the *end* leaves a shorter valid chain;
security keeps the head (``GET /v1/admin/audit/chain``) elsewhere, e.g. in a ticket or the SIEM,
and compares (``verify?expect_head=``).
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .auth import DbSession, require_admin
from .db import AuditEntry, FindingRow, utcnow

GENESIS = "0" * 64
_seal_lock = threading.Lock()

router = APIRouter(prefix="/v1/admin/audit", tags=["audit"], dependencies=[Depends(require_admin)])


def canonical(doc: Any) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode()


def digest(doc: Any) -> str:
    return hashlib.sha256(canonical(doc)).hexdigest()


def link(prev: str, e: AuditEntry) -> str:
    ts = e.ts.isoformat() if isinstance(e.ts, datetime) else str(e.ts)
    return hashlib.sha256(f"{prev}|{e.seq}|{e.kind}|{e.ref_id}|{e.digest}|{ts}".encode()).hexdigest()


def append(db: Session, kind: str, ref_id: str, doc: Any, *, snapshot: bool = True) -> None:
    """Record one audited thing in the caller's transaction. ``snapshot=False`` when the source row
    is immutable and verified in place (findings)."""
    doc = json.loads(canonical(doc))  # plain JSON (datetimes as strings), as stored and as re-hashed
    db.add(
        AuditEntry(
            ts=utcnow(), kind=kind, ref_id=str(ref_id)[:64], digest=digest(doc), doc=doc if snapshot else None
        )
    )


def seal(db: Session) -> int:
    """Chain every unsealed row, in order. Returns how many were sealed."""
    with _seal_lock:
        head = db.scalar(
            select(AuditEntry.hash).where(AuditEntry.hash.is_not(None)).order_by(AuditEntry.seq.desc())
        )
        prev = head or GENESIS
        rows = list(db.scalars(select(AuditEntry).where(AuditEntry.hash.is_(None)).order_by(AuditEntry.seq)))
        for e in rows:
            e.prev_hash = prev
            e.hash = prev = link(prev, e)
        db.commit()
        return len(rows)


class ChainHead(BaseModel):
    model_config = ConfigDict(extra="forbid")
    entries: int
    head: str
    head_seq: int | None


class Problem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    seq: int
    kind: str
    ref_id: str
    problem: str


class Verification(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ok: bool
    entries: int
    head: str
    problems: list[Problem]


def head(db: Session) -> ChainHead:
    seal(db)
    last = db.scalars(select(AuditEntry).order_by(AuditEntry.seq.desc()).limit(1)).first()
    return ChainHead(
        entries=db.scalar(select(func.count()).select_from(AuditEntry)) or 0,
        head=last.hash if last and last.hash else GENESIS,
        head_seq=last.seq if last else None,
    )


def verify(db: Session, expect_head: str | None = None) -> Verification:
    seal(db)
    problems: list[Problem] = []

    def bad(e: AuditEntry, what: str) -> None:
        problems.append(Problem(seq=e.seq, kind=e.kind, ref_id=e.ref_id, problem=what))

    prev = GENESIS
    count = 0
    for e in db.scalars(select(AuditEntry).order_by(AuditEntry.seq)):
        count += 1
        if e.prev_hash != prev:
            bad(e, "chain broken before this entry (a row was removed, inserted or reordered)")
        if e.hash != link(e.prev_hash or GENESIS, e):
            bad(e, "entry changed after sealing")
        if e.kind == "finding":
            row = db.get(FindingRow, e.ref_id)
            if row is None:
                bad(e, "finding deleted")
            elif digest(row.doc) != e.digest:
                bad(e, "finding changed")
        elif e.doc is None or digest(e.doc) != e.digest:
            bad(e, "recorded snapshot changed")
        prev = e.hash or prev
    if expect_head is not None and expect_head != prev:
        problems.append(
            Problem(
                seq=0, kind="chain", ref_id="", problem="head differs from the one kept outside (tail cut?)"
            )
        )
    return Verification(ok=not problems, entries=count, head=prev, problems=problems)


@router.get("/chain", response_model=ChainHead)
def chain_head(db: DbSession) -> ChainHead:
    """The current head: keep it outside the control plane to detect a cut-off tail later."""
    return head(db)


@router.get("/chain/verify", response_model=Verification)
def chain_verify(
    db: DbSession, expect_head: str | None = Query(default=None, pattern="^[0-9a-f]{64}$")
) -> Verification:
    return verify(db, expect_head)
