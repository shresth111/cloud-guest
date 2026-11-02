"""Optional per-login session timeout on voucher batches.

Adds nullable ``voucher_batches.session_timeout_minutes``. Every existing row
stays NULL, which means "the validity", as before.

Revision ID: 0178_add_voucher_batch_session_timeout
Revises: 0177_add_radius_nas_last_activity
Create Date: 2026-11-02
"""

import sqlalchemy as sa

from alembic import op

revision = "0178_add_voucher_batch_session_timeout"
down_revision = "0177_add_radius_nas_last_activity"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "voucher_batches",
        sa.Column("session_timeout_minutes", sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("voucher_batches", "session_timeout_minutes")
