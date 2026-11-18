"""Reviewers mark findings as false positives; those stop counting toward people's risk (2026-11-18).

Also grants the new ``findings.triage`` permission to the built-in ``soc`` and ``security_admin`` roles
that already exist (new deployments get it from the role defaults).

Revision ID: 0014
Revises: 0013
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None

PERMISSION = "findings.triage"
ROLES = ("soc", "security_admin")
roles = sa.table("roles", sa.column("role_id", sa.String), sa.column("permissions", sa.JSON))


def _set(add: bool) -> None:
    bind = op.get_bind()
    for role_id, permissions in bind.execute(sa.select(roles.c.role_id, roles.c.permissions)):
        if role_id not in ROLES:
            continue
        current = set(permissions or ())
        changed = sorted(current | {PERMISSION}) if add else sorted(current - {PERMISSION})
        if changed != sorted(current):
            bind.execute(roles.update().where(roles.c.role_id == role_id).values(permissions=changed))


def upgrade() -> None:
    op.create_table(
        "finding_dispositions",
        sa.Column("finding_id", sa.String(64), sa.ForeignKey("findings.finding_id"), primary_key=True),
        sa.Column("status", sa.String(20), nullable=False, index=True),
        sa.Column("user_id", sa.String(200), nullable=False, index=True),
        sa.Column("decided_by", sa.String(200), nullable=False),
        sa.Column("reason", sa.String(1000), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False, index=True),
    )
    _set(add=True)


def downgrade() -> None:
    _set(add=False)
    op.drop_table("finding_dispositions")
