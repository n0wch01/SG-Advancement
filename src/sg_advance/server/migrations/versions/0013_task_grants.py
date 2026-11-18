"""Revocable task capabilities and separately authenticated sensor posture reports.

Revision ID: 0013
Revises: 0012
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "task_grants",
        sa.Column("grant_id", sa.String(64), primary_key=True),
        sa.Column("user_id", sa.String(100), sa.ForeignKey("users.user_id"), nullable=False),
        sa.Column("device_id", sa.String(100), sa.ForeignKey("devices.device_id"), nullable=False),
        sa.Column("project_id", sa.String(100), sa.ForeignKey("projects.project_id"), nullable=False),
        sa.Column(
            "binding_id", sa.String(64), sa.ForeignKey("agent_session_bindings.binding_id"), nullable=False
        ),
        sa.Column("origin_token_id", sa.String(64), sa.ForeignKey("user_tokens.token_id"), nullable=False),
        sa.Column("parent_id", sa.String(64), sa.ForeignKey("task_grants.grant_id")),
        sa.Column("claims", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
    )
    for column in ("user_id", "device_id", "project_id", "expires_at"):
        op.create_index(f"ix_task_grants_{column}", "task_grants", [column])
    op.create_table(
        "device_posture",
        sa.Column("device_id", sa.String(100), sa.ForeignKey("devices.device_id"), primary_key=True),
        sa.Column("checks", sa.JSON(), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("device_posture")
    op.drop_table("task_grants")
