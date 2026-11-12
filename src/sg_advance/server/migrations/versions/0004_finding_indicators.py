"""M11 campaign detection: per-finding indicators, indexed by (rule, indicator, time).

Revision ID: 0004
Revises: 0003
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "finding_indicators",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("finding_id", sa.String(64), sa.ForeignKey("findings.finding_id"), nullable=False),
        sa.Column("rule_id", sa.String(200), nullable=False),
        sa.Column("indicator", sa.String(200), nullable=False),
        sa.Column("user_id", sa.String(200), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_finding_indicators_finding_id", "finding_indicators", ["finding_id"])
    op.create_index("ix_finding_indicators_lookup", "finding_indicators", ["rule_id", "indicator", "ts"])


def downgrade() -> None:
    op.drop_table("finding_indicators")
