"""M12 multi-host: device client certificates and revocation.

Revision ID: 0006
Revises: 0005
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None

TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    with op.batch_alter_table("devices") as b:
        b.add_column(sa.Column("cert_fingerprint", sa.String(64)))
        b.add_column(sa.Column("cert_not_after", TS))
        b.add_column(sa.Column("revoked_at", TS))
        b.add_column(sa.Column("revoked_by", sa.String(200)))
        b.add_column(sa.Column("revoke_reason", sa.String(1000)))
    with op.batch_alter_table("enrollment_tokens") as b:
        b.add_column(sa.Column("revoked_at", TS))


def downgrade() -> None:
    with op.batch_alter_table("enrollment_tokens") as b:
        b.drop_column("revoked_at")
    with op.batch_alter_table("devices") as b:
        for c in ("revoke_reason", "revoked_by", "revoked_at", "cert_not_after", "cert_fingerprint"):
            b.drop_column(c)
