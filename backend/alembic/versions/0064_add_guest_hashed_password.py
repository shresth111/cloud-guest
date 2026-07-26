"""Add hashed_password to guests -- returning-guest phone/email + password
login, following a first-time OTP verification.

Nullable: every existing ``Guest`` row (and every brand-new one, until they
opt in via ``POST /guest/set-password``) has never set a password -- ``NULL``
means "OTP/voucher only" for that guest, exactly the same "additive, opt-in
column" posture ``0063_add_background_image_to_brandings``'s own
``background_image_key`` just established. Hashed with
``app.domains.auth.password.PasswordManager`` (Argon2id) -- same
``String(255)`` width as ``AuthUser.password_hash``, the platform-user
account column this reuses the hashing convention from.

Revision ID: 0064_add_guest_hashed_password
Revises: 0063_add_background_image_to_brandings
Create Date: 2026-07-26
"""

import sqlalchemy as sa

from alembic import op

revision = "0064_add_guest_hashed_password"
down_revision = "0063_add_background_image_to_brandings"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "guests",
        sa.Column("hashed_password", sa.String(255), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("guests", "hashed_password")
