"""Baseline: the schema M3-M7 created without migrations.

Revision ID: 0001
Revises:
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "enrollment_tokens",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("label", sa.String(200)),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("expires_at", TS),
        sa.Column("max_uses", sa.Integer(), nullable=False),
        sa.Column("uses", sa.Integer(), nullable=False),
    )
    op.create_table(
        "devices",
        sa.Column("device_id", sa.String(100), primary_key=True),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("hostname", sa.String(255)),
        sa.Column("os", sa.String(100)),
        sa.Column("sensor_version", sa.String(50)),
        sa.Column("enrolled_at", TS, nullable=False),
        sa.Column("enrolled_with", sa.Integer(), sa.ForeignKey("enrollment_tokens.id")),
        sa.Column("last_seen", TS),
        sa.Column("policy_version", sa.String(64)),
    )
    op.create_table(
        "events",
        sa.Column("event_id", sa.String(64), primary_key=True),
        sa.Column("device_id", sa.String(100), sa.ForeignKey("devices.device_id"), nullable=False),
        sa.Column("ts", TS, nullable=False),
        sa.Column("received_ts", TS, nullable=False),
        sa.Column("kind", sa.String(40), nullable=False),
        sa.Column("user_id", sa.String(200), nullable=False),
        sa.Column("agent_type", sa.String(40), nullable=False),
        sa.Column("session_id", sa.String(200), nullable=False),
        sa.Column("sensor", sa.String(40), nullable=False),
        sa.Column("doc", sa.JSON(), nullable=False),
    )
    for col in ("device_id", "ts", "kind", "user_id", "agent_type", "session_id"):
        op.create_index(f"ix_events_{col}", "events", [col])
    op.create_table(
        "findings",
        sa.Column("finding_id", sa.String(64), primary_key=True),
        sa.Column("device_id", sa.String(100), sa.ForeignKey("devices.device_id"), nullable=False),
        sa.Column("ts", TS, nullable=False),
        sa.Column("received_ts", TS, nullable=False),
        sa.Column("rule_id", sa.String(200), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("category", sa.String(40), nullable=False),
        sa.Column("user_id", sa.String(200), nullable=False),
        sa.Column("agent_type", sa.String(40), nullable=False),
        sa.Column("session_id", sa.String(200), nullable=False),
        sa.Column("doc", sa.JSON(), nullable=False),
    )
    for col in ("device_id", "ts", "rule_id", "severity", "category", "user_id", "agent_type", "session_id"):
        op.create_index(f"ix_findings_{col}", "findings", [col])
    op.create_table(
        "package_manifests",
        sa.Column("spec", sa.String(300), primary_key=True),
        sa.Column("package", sa.String(214), nullable=False),
        sa.Column("version", sa.String(80), nullable=False),
        sa.Column("integrity", sa.String(200)),
        sa.Column("published_at", TS),
        sa.Column("source_repo", sa.String(200)),
        sa.Column("components", sa.JSON(), nullable=False),
        sa.Column("approved", sa.Boolean(), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False),
        sa.Column("decided_by", sa.String(200)),
        sa.Column("decided_at", TS),
        sa.Column("verified_at", TS, nullable=False),
        sa.Column("error", sa.String(1000)),
    )
    op.create_index("ix_package_manifests_package", "package_manifests", ["package"])


def downgrade() -> None:
    for t in ("package_manifests", "findings", "events", "devices", "enrollment_tokens"):
        op.drop_table(t)
