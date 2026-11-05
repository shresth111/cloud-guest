"""The password of a router's own local admin account.

Adds nullable ``routers.local_admin_password_encrypted``,
``local_admin_password_status`` and ``local_admin_password_verified_at``.
Existing rows stay NULL, which means "none issued yet".

Revision ID: 0181_add_router_local_admin_password
Revises: 0180_add_otp_provider_outcome
Create Date: 2026-11-05
"""

import sqlalchemy as sa

from alembic import op

revision = "0181_add_router_local_admin_password"
down_revision = "0180_add_otp_provider_outcome"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "routers", sa.Column("local_admin_password_encrypted", sa.Text(), nullable=True)
    )
    op.add_column(
        "routers",
        sa.Column("local_admin_password_status", sa.String(20), nullable=True),
    )
    op.add_column(
        "routers",
        sa.Column(
            "local_admin_password_verified_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("routers", "local_admin_password_verified_at")
    op.drop_column("routers", "local_admin_password_status")
    op.drop_column("routers", "local_admin_password_encrypted")
