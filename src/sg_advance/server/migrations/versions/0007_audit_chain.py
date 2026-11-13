"""Zero trust (2026-11-13): tamper-evident audit chain.

Revision ID: 0007
Revises: 0006
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "audit_chain",
        sa.Column("seq", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("kind", sa.String(40), nullable=False),
        sa.Column("ref_id", sa.String(64), nullable=False),
        sa.Column("digest", sa.String(64), nullable=False),
        sa.Column("doc", sa.JSON, nullable=True),
        sa.Column("prev_hash", sa.String(64), nullable=True),
        sa.Column("hash", sa.String(64), nullable=True),
        sqlite_autoincrement=True,  # a deleted tail row's seq is never reused
    )
    op.create_index("ix_audit_chain_kind", "audit_chain", ["kind"])
    op.create_index("ix_audit_chain_ref_id", "audit_chain", ["ref_id"])
    op.create_index("ix_audit_chain_hash", "audit_chain", ["hash"])


def downgrade() -> None:
    op.drop_table("audit_chain")
