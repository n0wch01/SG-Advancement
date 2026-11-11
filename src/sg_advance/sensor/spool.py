"""Durable outbound queue (stdlib sqlite3).

Everything the sensor wants to send goes here first, so nothing is lost while the control plane
is down. ``flush`` ships it in batches; because the server deduplicates on event_id/finding_id,
re-sending a batch after a lost response is harmless.

Items carry a priority (priority.py): a full spool evicts low priority first, and a flush sends
high priority first, so the evidence that matters survives a long outage. When a finding is
queued, its cited evidence *and* the same session's preceding events (``context_seconds``) are
promoted: incidents start from content the agent read, which rarely matches a rule by itself.

Several short-lived processes (one per Claude Code hook call, for example) may write at the same
time, so the DB runs in WAL mode with a busy timeout.
"""

from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from ..schema import AgentEvent, Finding
from .client import ControlPlaneClient, Offline
from .priority import Priority

Kind = Literal["event", "finding"]
_ENDPOINT: dict[Kind, tuple[str, str]] = {
    "event": ("/v1/events", "events"),
    "finding": ("/v1/findings", "findings"),
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS outbox (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    kind       TEXT NOT NULL,
    item_id    TEXT NOT NULL,
    doc        TEXT NOT NULL,
    created    REAL NOT NULL,
    attempts   INTEGER NOT NULL DEFAULT 0,
    dead       INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    priority   INTEGER NOT NULL DEFAULT 1,
    session    TEXT,
    ts         REAL,
    UNIQUE (kind, item_id)
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
"""
_INDEXES = (
    "CREATE INDEX IF NOT EXISTS outbox_send_order ON outbox (dead, priority, kind, id)",
    "CREATE INDEX IF NOT EXISTS outbox_session ON outbox (session, ts)",
)
# Columns added after the first release; old spool files get them on open.
_ADDED_COLUMNS = {
    "priority": "INTEGER NOT NULL DEFAULT 1",
    "session": "TEXT",
    "ts": "REAL",
    "retry_after": "REAL",
}
# A 422 means the server rejected what this sensor's own models accepted: almost always a server
# older than the sensor (a new event kind or field). Hold such rows and retry with backoff instead
# of dropping them, so upgrading the sensor first loses nothing. Give up after HOLD_SECONDS.
HOLD_SECONDS = 7 * 24 * 3600
HOLD_BACKOFF_MAX = 3600.0


def _session_key(item: AgentEvent | Finding) -> str:
    return f"{item.endpoint.device_id}\x1f{item.agent.session_id}"


@dataclass
class FlushResult:
    sent: int = 0
    duplicates: int = 0
    dead: int = 0
    held: int = 0  # rejected with 422, kept for a later retry
    remaining: int = 0
    error: str | None = None  # why flushing stopped early (offline, auth failure)

    @property
    def ok(self) -> bool:
        return self.error is None


class AuthRejected(Exception):
    """The server no longer accepts this device token (revoked / DB reset). Re-enroll."""


class Spool:
    def __init__(
        self, path: Path, max_items: int = 50_000, batch_size: int = 200, context_seconds: float = 600
    ) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.max_items = max_items
        self.batch_size = batch_size
        self.context_seconds = context_seconds
        with self._db() as db:
            db.executescript(_SCHEMA)
            cols = {row[1] for row in db.execute("PRAGMA table_info(outbox)")}
            for name, decl in _ADDED_COLUMNS.items():
                if name not in cols:
                    db.execute(f"ALTER TABLE outbox ADD COLUMN {name} {decl}")
            for stmt in _INDEXES:
                db.execute(stmt)

    @contextmanager
    def _db(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            yield conn
        finally:
            conn.close()

    # ── enqueue ──────────────────────────────────────────────────────────────

    def add(self, items: list[AgentEvent | Finding], priority: Priority = Priority.NORMAL) -> None:
        """Queue events at ``priority``; findings are always CRITICAL and promote their evidence
        plus the session context that led up to them."""
        rows = []
        evidence: list[str] = []
        contexts: list[tuple[str, float, float]] = []  # (session, from_ts, to_ts)
        now = time.time()
        for it in items:
            ts = it.ts.timestamp()
            if isinstance(it, AgentEvent):
                kind, item_id, prio = "event", it.event_id, int(priority)
            else:
                kind, item_id, prio = "finding", it.finding_id, int(Priority.CRITICAL)
                evidence.extend(it.evidence_event_ids)
                contexts.append((_session_key(it), ts - self.context_seconds, ts))
            rows.append((kind, item_id, it.model_dump_json(), now, prio, _session_key(it), ts))
        crit = int(Priority.CRITICAL)
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.executemany(
                "INSERT OR IGNORE INTO outbox (kind, item_id, doc, created, priority, session, ts) "
                "VALUES (?,?,?,?,?,?,?)",
                rows,
            )
            if evidence:
                db.executemany(
                    "UPDATE outbox SET priority = ? WHERE kind = 'event' AND item_id = ?",
                    [(crit, e) for e in evidence],
                )
            if contexts:
                db.executemany(
                    "UPDATE outbox SET priority = ? WHERE kind = 'event' AND dead = 0 "
                    "AND session = ? AND ts BETWEEN ? AND ?",
                    [(crit, *c) for c in contexts],
                )
            self._enforce_cap(db)
            db.execute("COMMIT")

    def _enforce_cap(self, db: sqlite3.Connection) -> None:
        """Bounded disk use while offline: evict events, lowest priority first, oldest first within
        a level. Findings are never evicted (they are few, and they are the point)."""
        (n,) = db.execute("SELECT COUNT(*) FROM outbox WHERE dead = 0").fetchone()
        excess = n - self.max_items
        if excess <= 0:
            return
        victims = db.execute(
            "SELECT id, priority FROM outbox WHERE kind = 'event' AND dead = 0 ORDER BY priority, id LIMIT ?",
            (excess,),
        ).fetchall()
        db.executemany("DELETE FROM outbox WHERE id = ?", [(v[0],) for v in victims])
        dropped: dict[int, int] = {}
        for _, prio in victims:
            dropped[prio] = dropped.get(prio, 0) + 1
        db.executemany(
            "INSERT INTO meta (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = value + excluded.value",
            [(f"dropped_p{prio}", count) for prio, count in dropped.items()],
        )

    # ── inspect ──────────────────────────────────────────────────────────────

    def stats(self) -> dict[str, int]:
        with self._db() as db:
            pending = dict(
                db.execute("SELECT kind, COUNT(*) FROM outbox WHERE dead = 0 GROUP BY kind").fetchall()
            )
            (dead,) = db.execute("SELECT COUNT(*) FROM outbox WHERE dead = 1").fetchone()
            meta = dict(db.execute("SELECT key, value FROM meta WHERE key LIKE 'dropped_p%'").fetchall())
        by_level = {f"dropped_{p.name.lower()}": meta.get(f"dropped_p{int(p)}", 0) for p in Priority}
        return {
            "pending_events": pending.get("event", 0),
            "pending_findings": pending.get("finding", 0),
            "dead": dead,
            "dropped_events": sum(by_level.values()),
            **by_level,
        }

    def dead_letters(self) -> list[tuple[str, str, str]]:
        with self._db() as db:
            return db.execute(
                "SELECT kind, item_id, last_error FROM outbox WHERE dead = 1 ORDER BY id"
            ).fetchall()

    # ── ship ─────────────────────────────────────────────────────────────────

    def flush(self, client: ControlPlaneClient) -> FlushResult:
        """Send everything pending, highest priority first. Within a level events go before
        findings so the console can resolve evidence."""
        result = FlushResult()
        try:
            for prio in sorted(Priority, reverse=True):
                for kind in ("event", "finding"):
                    self._flush_kind(client, kind, int(prio), result)
        except Offline as e:
            result.error = f"offline: {e}"
        except AuthRejected as e:
            result.error = f"auth rejected: {e}"
        s = self.stats()
        result.remaining = s["pending_events"] + s["pending_findings"]
        return result

    def _flush_kind(self, client: ControlPlaneClient, kind: Kind, prio: int, result: FlushResult) -> None:
        path, field = _ENDPOINT[kind]
        size = self.batch_size
        while True:
            with self._db() as db:
                rows = db.execute(
                    "SELECT id, doc FROM outbox WHERE dead = 0 AND priority = ? AND kind = ? "
                    "AND (retry_after IS NULL OR retry_after <= ?) ORDER BY id LIMIT ?",
                    (prio, kind, time.time(), size),
                ).fetchall()
            if not rows:
                return
            ids = [r[0] for r in rows]
            try:
                resp = client.post(path, {field: [json.loads(r[1]) for r in rows]})
            except Offline:
                self._bump(ids, "offline")
                raise
            status = resp["status"]
            if status == 200:
                self._delete(ids)
                result.sent += resp["body"]["accepted"]
                result.duplicates += resp["body"]["duplicates"]
                size = self.batch_size
            elif status == 401:
                self._bump(ids, "401")
                raise AuthRejected(str(resp["body"]))
            elif status in (408, 429):
                self._bump(ids, str(status))
                raise Offline(f"HTTP {status}")
            elif status == 413 and size > 1:
                size = max(1, size // 2)
            else:
                # 400/403/413/422: the same bytes will not succeed now. Split a batch down to the bad
                # item, then park it: 422 is held for a retry (version skew), the rest is dead.
                if len(rows) > 1:
                    size = max(1, len(rows) // 2)
                    continue
                if status == 422 and self._hold(ids[0], f"HTTP 422: {resp['body']}"):
                    result.held += 1
                    size = self.batch_size
                    continue
                self._mark_dead(ids, f"HTTP {status}: {resp['body']}")
                result.dead += len(ids)

    def _delete(self, ids: list[int]) -> None:
        with self._db() as db:
            db.executemany("DELETE FROM outbox WHERE id = ?", [(i,) for i in ids])

    def _bump(self, ids: list[int], err: str) -> None:
        with self._db() as db:
            db.executemany(
                "UPDATE outbox SET attempts = attempts + 1, last_error = ? WHERE id = ?",
                [(err, i) for i in ids],
            )

    def _hold(self, row_id: int, err: str) -> bool:
        """Back off a 422-rejected row. False once it has been held for HOLD_SECONDS (then it dies)."""
        with self._db() as db:
            created, attempts = db.execute(
                "SELECT created, attempts FROM outbox WHERE id = ?", (row_id,)
            ).fetchone()
            now = time.time()
            if now - created > HOLD_SECONDS:
                return False
            delay = min(HOLD_BACKOFF_MAX, 60.0 * 2**attempts)
            db.execute(
                "UPDATE outbox SET attempts = attempts + 1, last_error = ?, retry_after = ? WHERE id = ?",
                (f"held (server may be older than this sensor): {err}", now + delay, row_id),
            )
        return True

    def _mark_dead(self, ids: list[int], err: str) -> None:
        with self._db() as db:
            db.executemany("UPDATE outbox SET dead = 1, last_error = ? WHERE id = ?", [(err, i) for i in ids])
