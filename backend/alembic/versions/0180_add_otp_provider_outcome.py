"""What the provider call did for each OTP request.

Adds nullable ``otp_requests.provider_outcome``, ``provider_name`` and
``provider_response_ms``. Existing rows stay NULL. None of this is carrier
delivery: no receipt is received.

Revision ID: 0180_add_otp_provider_outcome
Revises: 0179_retire_birthday_marketing_template
Create Date: 2026-11-03
"""

import sqlalchemy as sa

from alembic import op

revision = "0180_add_otp_provider_outcome"
down_revision = "0179_retire_birthday_marketing_template"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "otp_requests", sa.Column("provider_outcome", sa.String(20), nullable=True)
    )
    op.add_column(
        "otp_requests", sa.Column("provider_name", sa.String(40), nullable=True)
    )
    op.add_column(
        "otp_requests", sa.Column("provider_response_ms", sa.Integer(), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("otp_requests", "provider_response_ms")
    op.drop_column("otp_requests", "provider_name")
    op.drop_column("otp_requests", "provider_outcome")
