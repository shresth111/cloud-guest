"""RADIUS liveness for NAS-only (Aruba Instant On) NAS rows.

Adds nullable ``radius_nas_clients.last_request_at`` / ``last_accounting_at``,
stamped only by the shared Aruba listener. Every existing row stays NULL;
nothing about MikroTik or Omada NAS rows changes.

Revision ID: 0146_add_radius_nas_last_activity
Revises: 0145_create_aruba_access_points
Create Date: 2026-10-04
"""

import sqlalchemy as sa

from alembic import op

revision = "0146_add_radius_nas_last_activity"
down_revision = "0145_create_aruba_access_points"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "radius_nas_clients",
        sa.Column("last_request_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "radius_nas_clients",
        sa.Column("last_accounting_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("radius_nas_clients", "last_accounting_at")
    op.drop_column("radius_nas_clients", "last_request_at")
