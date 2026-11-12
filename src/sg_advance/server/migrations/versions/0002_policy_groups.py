"""M9 policy management: groups, per-scope rule overrides, policy change log.

Revision ID: 0002
Revises: 0001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "policy_groups",
        sa.Column("name", sa.String(64), primary_key=True),
        sa.Column("description", sa.String(500)),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("created_by", sa.String(200)),
    )
    with op.batch_alter_table("devices") as b:
        b.add_column(sa.Column("group_name", sa.String(64), nullable=True))
        b.create_index("ix_devices_group_name", ["group_name"])
    with op.batch_alter_table("enrollment_tokens") as b:
        b.add_column(sa.Column("group_name", sa.String(64), nullable=True))
    op.create_table(
        "policy_overrides",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("scope", sa.String(64), nullable=False),
        sa.Column("rule_id", sa.String(200), nullable=False),
        sa.Column("enabled", sa.Boolean()),
        sa.Column("response", sa.String(30)),
        sa.Column("allow", sa.JSON()),
        sa.Column("updated_at", TS, nullable=False),
        sa.Column("updated_by", sa.String(200)),
        sa.Column("reason", sa.String(1000), nullable=False),
        sa.UniqueConstraint("scope", "rule_id", name="uq_policy_overrides_scope_rule"),
    )
    op.create_index("ix_policy_overrides_scope", "policy_overrides", ["scope"])
    op.create_table(
        "policy_changes",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("ts", TS, nullable=False),
        sa.Column("actor", sa.String(200), nullable=False),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("action", sa.String(40), nullable=False),
        sa.Column("scope", sa.String(64)),
        sa.Column("rule_id", sa.String(200)),
        sa.Column("target", sa.String(200)),
        sa.Column("before", sa.JSON()),
        sa.Column("after", sa.JSON()),
        sa.Column("reason", sa.String(1000), nullable=False),
    )
    op.create_index("ix_policy_changes_ts", "policy_changes", ["ts"])
    op.create_index("ix_policy_changes_scope", "policy_changes", ["scope"])


def downgrade() -> None:
    op.drop_table("policy_changes")
    op.drop_table("policy_overrides")
    with op.batch_alter_table("enrollment_tokens") as b:
        b.drop_column("group_name")
    with op.batch_alter_table("devices") as b:
        b.drop_index("ix_devices_group_name")
        b.drop_column("group_name")
    op.drop_table("policy_groups")
