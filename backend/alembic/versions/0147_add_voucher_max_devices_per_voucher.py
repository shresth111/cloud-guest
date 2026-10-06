"""Per-voucher device allowance.

Adds ``voucher_batches.max_devices_per_voucher`` (NOT NULL, default 1): how
many distinct devices one code admits. Existing batches are backfilled from
``max_uses_per_voucher`` -- the number the venue typed as "Max Uses" -- so a
single-use code stays a single-device code and a 5-use shared code admits 5
devices. Nothing else changes for them, except that a device that already
signed in with a code may sign in again with it while it is valid.

Revision ID: 0147_add_voucher_max_devices_per_voucher
Revises: 0146_add_radius_nas_last_activity
Create Date: 2026-10-06
"""

import sqlalchemy as sa

from alembic import op

revision = "0147_add_voucher_max_devices_per_voucher"
down_revision = "0146_add_radius_nas_last_activity"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "voucher_batches",
        sa.Column(
            "max_devices_per_voucher",
            sa.Integer(),
            nullable=False,
            server_default="1",
        ),
    )
    op.execute(
        "UPDATE voucher_batches SET max_devices_per_voucher = "
        "GREATEST(max_uses_per_voucher, 1)"
    )


def downgrade() -> None:
    op.drop_column("voucher_batches", "max_devices_per_voucher")
