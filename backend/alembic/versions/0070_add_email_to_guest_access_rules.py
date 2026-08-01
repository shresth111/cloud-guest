"""Add email to guest_access_rules and device_access_rules.

The customer dashboard's Whitelist form (WhiteList.tsx) has always
collected and validated a required contact email alongside the
number/MAC being allow-listed, but neither ``GuestAccessRuleCreate`` nor
``DeviceAccessRuleCreate`` had anywhere to put it -- the value was
validated client-side and then silently dropped before the API call ever
went out. Nullable: rules created any other way (API, future bulk
import) never required one, and existing rows have none.

Revision ID: 0070_add_email_to_guest_access_rules
Revises: 0069_add_email_to_guests
Create Date: 2026-08-01
"""

import sqlalchemy as sa

from alembic import op

revision = "0070_add_email_to_guest_access_rules"
down_revision = "0069_add_email_to_guests"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "guest_access_rules",
        sa.Column("email", sa.String(255), nullable=True),
    )
    op.add_column(
        "device_access_rules",
        sa.Column("email", sa.String(255), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("device_access_rules", "email")
    op.drop_column("guest_access_rules", "email")
