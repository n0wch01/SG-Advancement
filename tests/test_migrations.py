"""Schema migrations (M9, Alembic): fresh databases and databases made before migrations existed."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import inspect, text

from sg_advance.server import db as db_module
from sg_advance.server.db import Base, Database


def test_migrations_produce_exactly_the_models(tmp_path) -> None:
    db = Database(f"sqlite:///{tmp_path / 'fresh.db'}")
    db.create_all()
    with db.engine.connect() as conn:
        ctx = MigrationContext.configure(conn, opts={"compare_type": True})
        assert compare_metadata(ctx, Base.metadata) == []
        assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar() == "0003"
    db.create_all()  # idempotent on every start


def test_a_database_from_before_migrations_keeps_its_data(tmp_path) -> None:
    url = f"sqlite:///{tmp_path / 'old.db'}"
    old = Database(url)
    # What M3-M7 left behind: the baseline tables, created directly, with no alembic_version.
    cfg = Config()
    cfg.set_main_option("script_location", str(Path(db_module.__file__).parent / "migrations"))
    with old.engine.begin() as conn:
        cfg.attributes["connection"] = conn
        command.upgrade(cfg, "0001")
        conn.execute(text("DROP TABLE alembic_version"))
        conn.execute(
            text("INSERT INTO devices (device_id, token_hash, enrolled_at) VALUES ('dev-1', 'h', :ts)"),
            {"ts": datetime.now(UTC).isoformat()},
        )
    assert "group_name" not in {c["name"] for c in inspect(old.engine).get_columns("devices")}
    old.engine.dispose()

    db = Database(url)
    db.create_all()
    with db.engine.connect() as conn:
        assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar() == "0003"
        assert conn.execute(text("SELECT device_id, group_name FROM devices")).all() == [("dev-1", None)]
        assert {"policy_groups", "policy_overrides", "policy_changes"} <= set(inspect(conn).get_table_names())
