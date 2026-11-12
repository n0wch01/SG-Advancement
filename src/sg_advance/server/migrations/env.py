"""Alembic environment for the control plane (M9).

Run from code (``Database.create_all`` passes an open connection), so there is no alembic.ini
and no URL here. New revision: ``uv run alembic -c <tmp ini> revision`` is not needed for simple
changes; copy the latest file in versions/ and bump ``revision`` / ``down_revision``.
"""

from __future__ import annotations

from alembic import context

from sg_advance.server.db import Base

connection = context.config.attributes["connection"]
context.configure(
    connection=connection,
    target_metadata=Base.metadata,
    render_as_batch=True,  # SQLite cannot ALTER most things; batch mode recreates the table
    compare_type=True,
)
with context.begin_transaction():
    context.run_migrations()
