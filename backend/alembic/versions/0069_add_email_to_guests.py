"""Add email to guests for the post-OTP "tell us about yourself" prompt
(a new, first-login-only, skippable Name + Email step shown right after a
guest's first mobile-OTP verification) -- distinct from `identifier`,
which for an SMS-OTP guest is their phone number, not an email address.

Nullable and never required to obtain network access -- written only by
GuestService.update_guest_profile, itself only reachable with proof of a
just-completed, still-ACTIVE OTP-authenticated GuestSession (same pattern
0064_add_guest_hashed_password's set_guest_password flow already uses).

Revision ID: 0069_add_email_to_guests
Revises: 0068_add_business_hours_to_captive_portal_configs
Create Date: 2026-08-01
"""

import sqlalchemy as sa

from alembic import op

revision = "0069_add_email_to_guests"
down_revision = "0068_add_business_hours_to_captive_portal_configs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "guests",
        sa.Column("email", sa.String(255), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("guests", "email")
