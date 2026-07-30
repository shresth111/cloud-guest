"""Add tokens_invalidated_at to users -- backs a real admin "force logout"
action: revoking refresh tokens/sessions alone only stops a *new* access
token being minted, an already-issued one keeps working until its normal
15-minute expiry. This column lets dependencies.py reject any access
token whose own `iat` predates it, on the very next authenticated
request, regardless of how much of its expiry window is left.

Revision ID: 0067_add_tokens_invalidated_at_to_users
Revises: 0066_add_port_mode_and_hotspot_to_vlans
Create Date: 2026-07-30
"""

import sqlalchemy as sa

from alembic import op

revision = "0067_add_tokens_invalidated_at_to_users"
down_revision = "0066_add_port_mode_and_hotspot_to_vlans"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("tokens_invalidated_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("users", "tokens_invalidated_at")
