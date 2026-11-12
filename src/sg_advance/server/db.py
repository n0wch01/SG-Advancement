"""Storage layer (SQLAlchemy 2.0). SQLite by default; Postgres by changing the URL only.

Each event / finding is stored as its full JSON document plus a few indexed columns the console
filters on. Keep column types portable: no SQLite-only or Postgres-only features.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    create_engine,
    event,
    inspect,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.types import TypeDecorator


class UTCDateTime(TypeDecorator[datetime]):
    """Always stores UTC and always returns timezone-aware values.
    SQLite drops tzinfo on the way back; Postgres keeps it. This hides the difference."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetime; use timezone-aware values")
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


BASELINE_REVISION = "0001"  # the schema as M3-M7 created it without migrations


class EnrollmentToken(Base):
    """Issued by an admin, handed to whoever installs a sensor. Only the hash is stored."""

    __tablename__ = "enrollment_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    label: Mapped[str | None] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    max_uses: Mapped[int] = mapped_column(Integer, default=1)
    uses: Mapped[int] = mapped_column(Integer, default=0)
    group_name: Mapped[str | None] = mapped_column(
        String(64), nullable=True, doc="Devices enrolled with this token join this group (M9)"
    )


class Device(Base):
    __tablename__ = "devices"

    device_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    hostname: Mapped[str | None] = mapped_column(String(255))
    os: Mapped[str | None] = mapped_column(String(100))
    sensor_version: Mapped[str | None] = mapped_column(String(50))
    enrolled_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    enrolled_with: Mapped[int | None] = mapped_column(ForeignKey("enrollment_tokens.id"))
    last_seen: Mapped[datetime | None] = mapped_column(UTCDateTime)
    policy_version: Mapped[str | None] = mapped_column(String(64), doc="Last policy the sensor pulled")
    group_name: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        index=True,
        doc="Policy group: common policy + this group's stricter overrides",
    )


class EventRow(Base):
    __tablename__ = "events"

    event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.device_id"), index=True)
    ts: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    received_ts: Mapped[datetime] = mapped_column(UTCDateTime)
    kind: Mapped[str] = mapped_column(String(40), index=True)
    user_id: Mapped[str] = mapped_column(String(200), index=True)
    agent_type: Mapped[str] = mapped_column(String(40), index=True)
    session_id: Mapped[str] = mapped_column(String(200), index=True)
    sensor: Mapped[str] = mapped_column(String(40))
    doc: Mapped[dict[str, Any]] = mapped_column(JSON)


class FindingRow(Base):
    __tablename__ = "findings"

    finding_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.device_id"), index=True)
    ts: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    received_ts: Mapped[datetime] = mapped_column(UTCDateTime)
    rule_id: Mapped[str] = mapped_column(String(200), index=True)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    category: Mapped[str] = mapped_column(String(40), index=True)
    user_id: Mapped[str] = mapped_column(String(200), index=True)
    agent_type: Mapped[str] = mapped_column(String(40), index=True)
    session_id: Mapped[str] = mapped_column(String(200), index=True)
    doc: Mapped[dict[str, Any]] = mapped_column(JSON)


class PackageManifestRow(Base):
    """Known-good digests of one published package version (M5d), or why it failed verification.

    ``approved`` / ``revoked`` are security decisions; otherwise trust follows the release cooldown
    (integrity.effective_status). ``error`` set means verification failed: shipped as "rejected"."""

    __tablename__ = "package_manifests"

    spec: Mapped[str] = mapped_column(String(300), primary_key=True)  # "<package>@<version>"
    package: Mapped[str] = mapped_column(String(214), index=True)
    version: Mapped[str] = mapped_column(String(80))
    integrity: Mapped[str | None] = mapped_column(String(200), nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    source_repo: Mapped[str | None] = mapped_column(String(200), nullable=True)
    components: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    approved: Mapped[bool] = mapped_column(default=False)
    revoked: Mapped[bool] = mapped_column(default=False)
    decided_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    verified_at: Mapped[datetime] = mapped_column(UTCDateTime)
    error: Mapped[str | None] = mapped_column(String(1000), nullable=True)


class Group(Base):
    """A team whose devices get the common policy plus stricter overrides (M9)."""

    __tablename__ = "policy_groups"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    description: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    created_by: Mapped[str | None] = mapped_column(String(200), nullable=True)


class PolicyOverride(Base):
    """The current override of one rule in one scope ("common" or a group name). Unset fields
    leave the rule as the layer below has it."""

    __tablename__ = "policy_overrides"
    __table_args__ = (UniqueConstraint("scope", "rule_id", name="uq_policy_overrides_scope_rule"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scope: Mapped[str] = mapped_column(String(64), index=True)
    rule_id: Mapped[str] = mapped_column(String(200))
    enabled: Mapped[bool | None] = mapped_column(nullable=True)
    response: Mapped[str | None] = mapped_column(String(30), nullable=True)
    allow: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    reason: Mapped[str] = mapped_column(String(1000), default="")


class PolicyChange(Base):
    """Append-only audit log of policy edits. ``id`` doubles as the policy revision number."""

    __tablename__ = "policy_changes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(200))
    role: Mapped[str] = mapped_column(String(20))
    action: Mapped[str] = mapped_column(
        String(40)
    )  # override.set | override.clear | group.create | device.assign
    scope: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    rule_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    target: Mapped[str | None] = mapped_column(String(200), nullable=True)  # device id for device.assign
    before: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    after: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    reason: Mapped[str] = mapped_column(String(1000), default="")


def make_engine(url: str) -> Engine:
    if url.startswith("sqlite"):
        path = url.split("///", 1)[-1]
        in_memory = path in ("", ":memory:") or url == "sqlite://"
        if not in_memory:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        engine = create_engine(
            url,
            connect_args={"check_same_thread": False},
            # In-memory DBs vanish per connection; share one so tests see the same data.
            poolclass=StaticPool if in_memory else None,
        )

        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_conn: Any, _: Any) -> None:
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            if not in_memory:
                cur.execute("PRAGMA journal_mode=WAL")  # readers don't block the single writer
            cur.close()

        return engine
    return create_engine(url, pool_pre_ping=True)


class Database:
    def __init__(self, url: str) -> None:
        self.engine = make_engine(url)
        self._sessions = sessionmaker(self.engine, expire_on_commit=False)

    def create_all(self) -> None:
        """Bring the schema to the latest migration (M9: Alembic, server/migrations).

        A database made before migrations existed (tables created directly by M3-M7) is stamped
        as the baseline first, so its data is kept and only the newer migrations run."""
        from alembic import command
        from alembic.config import Config

        cfg = Config()
        cfg.set_main_option("script_location", str(Path(__file__).parent / "migrations"))
        with self.engine.begin() as conn:
            cfg.attributes["connection"] = conn
            tables = set(inspect(conn).get_table_names())
            if "devices" in tables and "alembic_version" not in tables:
                command.stamp(cfg, BASELINE_REVISION)
            command.upgrade(cfg, "head")

    def session(self) -> Iterator[Session]:
        with self._sessions() as s:
            yield s
