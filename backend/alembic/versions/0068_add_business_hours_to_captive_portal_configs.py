"""Add business_hours_* columns to captive_portal_configs -- backs a real
guest-facing "business is closed" screen instead of the previous fake
Business Hours "Apply" button (toast-only, never persisted anywhere).

Revision ID: 0068_add_business_hours_to_captive_portal_configs
Revises: 0067_add_tokens_invalidated_at_to_users
Create Date: 2026-07-30
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0068_add_business_hours_to_captive_portal_configs"
down_revision = "0067_add_tokens_invalidated_at_to_users"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "captive_portal_configs",
        sa.Column(
            "business_hours_enabled", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
    )
    op.add_column(
        "captive_portal_configs",
        sa.Column(
            "business_hours_timezone",
            sa.String(64),
            nullable=False,
            server_default="UTC",
        ),
    )
    op.add_column(
        "captive_portal_configs",
        sa.Column(
            "business_hours_schedule",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="{}",
        ),
    )
    op.add_column(
        "captive_portal_configs",
        sa.Column("business_hours_closed_message", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("captive_portal_configs", "business_hours_closed_message")
    op.drop_column("captive_portal_configs", "business_hours_schedule")
    op.drop_column("captive_portal_configs", "business_hours_timezone")
    op.drop_column("captive_portal_configs", "business_hours_enabled")
