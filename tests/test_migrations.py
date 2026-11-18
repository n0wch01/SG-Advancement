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
        assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar() == "0014"
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
        assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar() == "0014"
        assert conn.execute(text("SELECT device_id, group_name FROM devices")).all() == [("dev-1", None)]
        assert {"policy_groups", "policy_overrides", "policy_changes"} <= set(inspect(conn).get_table_names())


def test_rbac_upgrade_preserves_referenced_device_events_and_findings(tmp_path) -> None:
    db = Database(f"sqlite:///{tmp_path / 'populated.db'}")
    cfg = Config()
    cfg.set_main_option("script_location", str(Path(db_module.__file__).parent / "migrations"))
    with db.engine.begin() as conn:
        cfg.attributes["connection"] = conn
        command.upgrade(cfg, "0011")
        conn.execute(text(
            "INSERT INTO devices (device_id, token_hash, enrolled_at) VALUES ('device', 'hash', :ts)"
        ), {"ts": datetime.now(UTC).isoformat()})
        conn.execute(text(
            "INSERT INTO events (event_id, device_id, ts, received_ts, kind, user_id, agent_type, "
            "session_id, sensor, doc) VALUES ('event', 'device', :ts, :ts, 'tool.call', 'claimed', "
            "'codex_cli', 'session', 'codex_cli_hook', '{}')"
        ), {"ts": datetime.now(UTC).isoformat()})
        conn.execute(text(
            "INSERT INTO findings (finding_id, device_id, ts, received_ts, rule_id, severity, "
            "category, user_id, agent_type, session_id, doc) VALUES ('finding', 'device', :ts, :ts, "
            "'rule', 'high', 'tool_misuse', 'claimed', 'codex_cli', 'session', '{}')"
        ), {"ts": datetime.now(UTC).isoformat()})
    db.create_all()
    with db.engine.connect() as conn:
        assert conn.execute(text("PRAGMA foreign_key_check")).all() == []
        for table in ("events", "findings"):
            assert conn.execute(text(f"SELECT project_id, actor_id FROM {table}")).all() == [(None, None)]
        assert conn.execute(text("SELECT owner_user_id FROM devices")).all() == [(None,)]


def test_existing_review_roles_get_finding_triage_and_lose_it_on_downgrade(tmp_path) -> None:
    """0014: roles seeded before it (soc, security_admin) gain findings.triage; other roles do not."""
    db = Database(f"sqlite:///{tmp_path / 'roles.db'}")
    cfg = Config()
    cfg.set_main_option("script_location", str(Path(db_module.__file__).parent / "migrations"))

    def roles(conn) -> dict[str, list[str]]:
        import json

        return {r: json.loads(p) for r, p in conn.execute(text("SELECT role_id, permissions FROM roles"))}

    with db.engine.begin() as conn:
        cfg.attributes["connection"] = conn
        command.upgrade(cfg, "0013")
        for role, permissions in (("soc", '["response.manage"]'), ("developer", '["source.write"]')):
            conn.execute(text("INSERT INTO roles (role_id, permissions) VALUES (:r, :p)"),
                         {"r": role, "p": permissions})  # fmt: skip
        command.upgrade(cfg, "0014")
        assert roles(conn) == {"soc": ["findings.triage", "response.manage"], "developer": ["source.write"]}
        command.downgrade(cfg, "0013")
        assert roles(conn) == {"soc": ["response.manage"], "developer": ["source.write"]}
