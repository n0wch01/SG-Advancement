"""Durable outbound queue (stdlib sqlite3).

Everything the sensor wants to send goes here first, so nothing is lost while the control plane
is down. ``flush`` ships it in batches; because the server deduplicates on event_id/finding_id,
re-sending a batch after a lost response is harmless.

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
    UNIQUE (kind, item_id)
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
"""


@dataclass
class FlushResult:
    sent: int = 0
    duplicates: int = 0
    dead: int = 0
    remaining: int = 0
    error: str | None = None  # why flushing stopped early (offline, auth failure)

    @property
    def ok(self) -> bool:
        return self.error is None


class AuthRejected(Exception):
    """The server no longer accepts this device token (revoked / DB reset). Re-enroll."""


class Spool:
    def __init__(self, path: Path, max_items: int = 50_000, batch_size: int = 200) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.max_items = max_items
        self.batch_size = batch_size
        with self._db() as db:
            db.executescript(_SCHEMA)

    @contextmanager
    def _db(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            yield conn
        finally:
            conn.close()

    # ── enqueue ──────────────────────────────────────────────────────────────

    def add(self, items: list[AgentEvent | Finding]) -> None:
        rows = []
        for it in items:
            if isinstance(it, AgentEvent):
                rows.append(("event", it.event_id, it.model_dump_json(), time.time()))
            else:
                rows.append(("finding", it.finding_id, it.model_dump_json(), time.time()))
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.executemany(
                "INSERT OR IGNORE INTO outbox (kind, item_id, doc, created) VALUES (?,?,?,?)", rows
            )
            self._enforce_cap(db)
            db.execute("COMMIT")

    def _enforce_cap(self, db: sqlite3.Connection) -> None:
        """Bounded disk use while offline: drop the oldest *events* first; findings are kept."""
        (n,) = db.execute("SELECT COUNT(*) FROM outbox WHERE dead = 0").fetchone()
        excess = n - self.max_items
        if excess <= 0:
            return
        cur = db.execute(
            "DELETE FROM outbox WHERE id IN "
            "(SELECT id FROM outbox WHERE kind = 'event' AND dead = 0 ORDER BY id LIMIT ?)",
            (excess,),
        )
        db.execute(
            "INSERT INTO meta (key, value) VALUES ('dropped_events', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = value + excluded.value",
            (cur.rowcount,),
        )

    # ── inspect ──────────────────────────────────────────────────────────────

    def stats(self) -> dict[str, int]:
        with self._db() as db:
            pending = dict(
                db.execute("SELECT kind, COUNT(*) FROM outbox WHERE dead = 0 GROUP BY kind").fetchall()
            )
            (dead,) = db.execute("SELECT COUNT(*) FROM outbox WHERE dead = 1").fetchone()
            dropped = db.execute("SELECT value FROM meta WHERE key = 'dropped_events'").fetchone()
        return {
            "pending_events": pending.get("event", 0),
            "pending_findings": pending.get("finding", 0),
            "dead": dead,
            "dropped_events": dropped[0] if dropped else 0,
        }

    def dead_letters(self) -> list[tuple[str, str, str]]:
        with self._db() as db:
            return db.execute(
                "SELECT kind, item_id, last_error FROM outbox WHERE dead = 1 ORDER BY id"
            ).fetchall()

    # ── ship ─────────────────────────────────────────────────────────────────

    def flush(self, client: ControlPlaneClient) -> FlushResult:
        """Send everything pending. Events go before findings so the console can resolve evidence."""
        result = FlushResult()
        try:
            for kind in ("event", "finding"):
                self._flush_kind(client, kind, result)
        except Offline as e:
            result.error = f"offline: {e}"
        except AuthRejected as e:
            result.error = f"auth rejected: {e}"
        s = self.stats()
        result.remaining = s["pending_events"] + s["pending_findings"]
        return result

    def _flush_kind(self, client: ControlPlaneClient, kind: Kind, result: FlushResult) -> None:
        path, field = _ENDPOINT[kind]
        size = self.batch_size
        while True:
            with self._db() as db:
                rows = db.execute(
                    "SELECT id, doc FROM outbox WHERE kind = ? AND dead = 0 ORDER BY id LIMIT ?", (kind, size)
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
                # 400/403/413/422: retrying the same bytes will never succeed. Park the rows
                # (a batch that contains one bad item is split down to find it).
                if len(rows) > 1:
                    size = max(1, len(rows) // 2)
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

    def _mark_dead(self, ids: list[int], err: str) -> None:
        with self._db() as db:
            db.executemany("UPDATE outbox SET dead = 1, last_error = ? WHERE id = ?", [(err, i) for i in ids])
