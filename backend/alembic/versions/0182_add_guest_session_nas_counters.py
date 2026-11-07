"""Per-NAS-session byte baselines on guest sessions (Aruba Instant On).

Adds nullable JSONB ``guest_sessions.nas_counters``. Existing rows stay NULL,
which the accounting path reads as "nothing tracked yet" (the old behaviour).

Revision ID: 0182_add_guest_session_nas_counters
Revises: 0181_add_router_local_admin_password
Create Date: 2026-11-07
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0182_add_guest_session_nas_counters"
down_revision = "0181_add_router_local_admin_password"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "guest_sessions",
        sa.Column("nas_counters", postgresql.JSONB(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("guest_sessions", "nas_counters")
