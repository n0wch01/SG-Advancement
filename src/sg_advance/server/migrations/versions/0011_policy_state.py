"""Persist the published base policy and staged rollout across workers and restarts.

Revision ID: 0011
Revises: 0010
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "policy_state",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("base_rules", sa.JSON(), nullable=False),
        sa.Column("effective_from", sa.DateTime(timezone=True), nullable=True),
        sa.Column("staged", sa.JSON(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("policy_state")
