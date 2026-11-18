"""Individual identity, scoped roles and immutable collection-time project attribution.

Revision ID: 0012
Revises: 0011
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def ref(name: str, target: str, *, nullable: bool = False, primary: bool = False) -> sa.Column:
    return sa.Column(name, sa.String(100), sa.ForeignKey(target), nullable=nullable, primary_key=primary)


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("user_id", sa.String(100), primary_key=True),
        sa.Column("display_name", sa.String(200), nullable=False),
        sa.Column("disabled_at", sa.DateTime(timezone=True)),
    )
    op.create_table(
        "user_tokens",
        sa.Column("token_id", sa.String(64), primary_key=True),
        ref("user_id", "users.user_id"),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_user_tokens_user_id", "user_tokens", ["user_id"])
    op.create_table(
        "teams",
        sa.Column("team_id", sa.String(100), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
    )
    op.create_table(
        "team_members",
        ref("team_id", "teams.team_id", primary=True),
        ref("user_id", "users.user_id", primary=True),
    )
    op.create_table(
        "projects",
        sa.Column("project_id", sa.String(100), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("workspace_root", sa.String(1000)),
        sa.Column("environments", sa.JSON(), nullable=False),
        sa.Column("disabled_at", sa.DateTime(timezone=True)),
    )
    op.create_table(
        "roles",
        sa.Column("role_id", sa.String(100), primary_key=True),
        sa.Column("permissions", sa.JSON(), nullable=False),
    )
    op.create_table(
        "role_bindings",
        sa.Column("binding_id", sa.String(64), primary_key=True),
        ref("role_id", "roles.role_id"),
        ref("user_id", "users.user_id", nullable=True),
        ref("team_id", "teams.team_id", nullable=True),
        ref("project_id", "projects.project_id", nullable=True),
        sa.Column("environment", sa.String(40), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint(
            "(user_id IS NOT NULL AND team_id IS NULL) OR (user_id IS NULL AND team_id IS NOT NULL)",
            name="ck_role_subject",
        ),
    )
    for column in ("user_id", "team_id", "project_id"):
        op.create_index(f"ix_role_bindings_{column}", "role_bindings", [column])
    op.create_table(
        "agent_session_bindings",
        sa.Column("binding_id", sa.String(64), primary_key=True),
        ref("device_id", "devices.device_id"),
        sa.Column("agent_type", sa.String(40), nullable=False),
        sa.Column("session_id", sa.String(200), nullable=False),
        ref("project_id", "projects.project_id"),
        ref("user_id", "users.user_id"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("device_id", "agent_type", "session_id"),
    )
    for column in ("device_id", "project_id", "user_id"):
        op.create_index(f"ix_agent_session_bindings_{column}", "agent_session_bindings", [column])
    for table, fields in SCOPED_COLUMNS.items():
        for column, target in fields.items():
            constraint = f"fk_{table}_{column}"
            if op.get_bind().dialect.name == "sqlite":
                # ADD COLUMN can add a nullable REFERENCES column without rebuilding a parent
                # table. Batch copying devices/events would fail with foreign_keys=ON and data.
                op.execute(
                    sa.text(
                        f"ALTER TABLE {table} ADD COLUMN {column} VARCHAR(100) "
                        f"CONSTRAINT {constraint} REFERENCES {target[0]} ({target[1]})"
                    )
                )
            else:
                op.add_column(
                    table,
                    sa.Column(
                        column,
                        sa.String(100),
                        sa.ForeignKey(f"{target[0]}.{target[1]}", name=constraint),
                        nullable=True,
                    ),
                )
            if column != "owner_user_id":
                op.create_index(f"ix_{table}_{column}", table, [column])
    # Existing records deliberately remain NULL: neither paths nor self-reported users prove scope.


SCOPED_COLUMNS = {
    "devices": {"owner_user_id": ("users", "user_id")},
    "events": {"project_id": ("projects", "project_id"), "actor_id": ("users", "user_id")},
    "findings": {"project_id": ("projects", "project_id"), "actor_id": ("users", "user_id")},
    "remote_actions": {"project_id": ("projects", "project_id")},
}


def downgrade() -> None:
    for table, fields in reversed(SCOPED_COLUMNS.items()):
        for column in reversed(fields):
            if column != "owner_user_id":
                op.drop_index(f"ix_{table}_{column}", table_name=table)
            if op.get_bind().dialect.name != "sqlite":
                op.drop_constraint(f"fk_{table}_{column}", table, type_="foreignkey")
            op.drop_column(table, column)
    for table in (
        "agent_session_bindings",
        "role_bindings",
        "roles",
        "projects",
        "team_members",
        "teams",
        "user_tokens",
        "users",
    ):
        op.drop_table(table)
