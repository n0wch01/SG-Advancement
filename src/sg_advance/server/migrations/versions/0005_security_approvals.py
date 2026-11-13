"""M11 security approval queue: tool calls held on a device until security decides.

Revision ID: 0005
Revises: 0004
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None

TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "security_approvals",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("device_id", sa.String(100), sa.ForeignKey("devices.device_id"), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("expires_at", TS, nullable=False),
        sa.Column("user_id", sa.String(200), nullable=False),
        sa.Column("session_id", sa.String(200), nullable=False),
        sa.Column("tool", sa.String(200), nullable=False),
        sa.Column("arguments_preview", sa.String(2000), nullable=False),
        sa.Column("reason", sa.String(1000), nullable=False),
        sa.Column("rule_ids", sa.JSON, nullable=False),
        sa.Column("severity", sa.String(20)),
        sa.Column("event_id", sa.String(64)),
        sa.Column("finding_ids", sa.JSON, nullable=False),
        sa.Column("decided_at", TS),
        sa.Column("decided_by", sa.String(200)),
        sa.Column("decision_reason", sa.String(1000)),
        sa.Column("delivered_at", TS),
        sa.Column("outcome", sa.String(20)),
        sa.Column("outcome_at", TS),
    )
    op.create_index("ix_security_approvals_device_id", "security_approvals", ["device_id"])
    op.create_index("ix_security_approvals_status", "security_approvals", ["status"])
    op.create_index("ix_security_approvals_created_at", "security_approvals", ["created_at"])
    op.create_index("ix_security_approvals_user_id", "security_approvals", ["user_id"])


def downgrade() -> None:
    op.drop_table("security_approvals")
