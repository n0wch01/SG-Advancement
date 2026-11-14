"""Phase 1 (2026-11-13): approvals bound to the exact request; remote actions redelivered until
acknowledged, with what was actually applied.

Revision ID: 0008
Revises: 0007
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("security_approvals") as b:
        b.add_column(sa.Column("request_digest", sa.String(64)))
    with op.batch_alter_table("remote_actions") as b:
        b.add_column(sa.Column("attempts", sa.Integer, nullable=False, server_default="0"))
        b.add_column(sa.Column("lease_until", sa.DateTime(timezone=True)))
        b.add_column(sa.Column("applied", sa.String(30)))


def downgrade() -> None:
    with op.batch_alter_table("remote_actions") as b:
        for c in ("applied", "lease_until", "attempts"):
            b.drop_column(c)
    with op.batch_alter_table("security_approvals") as b:
        b.drop_column("request_digest")
