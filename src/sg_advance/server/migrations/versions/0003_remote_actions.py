"""M11 remote response: actions security sends to a device and their results.

Revision ID: 0003
Revises: 0002
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "remote_actions",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("device_id", sa.String(100), sa.ForeignKey("devices.device_id"), nullable=False),
        sa.Column("action", sa.String(40), nullable=False),
        sa.Column("target", sa.String(300), nullable=False),
        sa.Column("finding_id", sa.String(64)),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("created_by", sa.String(200), nullable=False),
        sa.Column("reason", sa.String(1000), nullable=False),
        sa.Column("delivered_at", TS),
        sa.Column("result_at", TS),
        sa.Column("result_detail", sa.String(1000)),
    )
    op.create_index("ix_remote_actions_device_id", "remote_actions", ["device_id"])
    op.create_index("ix_remote_actions_status", "remote_actions", ["status"])
    op.create_index("ix_remote_actions_created_at", "remote_actions", ["created_at"])


def downgrade() -> None:
    op.drop_table("remote_actions")
