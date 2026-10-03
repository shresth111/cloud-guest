"""Aruba AP + MikroTik gateway hybrid: ``location_speed_gateways``.

One live row per NAS-only (Aruba Instant On) router, naming the Wyfy-managed
MikroTik at the same location that enforces per-guest speed for the guests
that access point authorizes. See
``app.domains.queue_management.speed_gateway``.

New and empty; nothing to backfill. Nothing reads it unless
``CLOUDGUEST_ARUBA_HYBRID_SPEED_GATEWAY_ENABLED`` is true, so this migration
changes no venue's behaviour.

Downgrade drops the table.

Revision ID: 0144_create_location_speed_gateways
Revises: 0143_create_location_ssid_tiers
Create Date: 2026-10-03
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0144_create_location_speed_gateways"
down_revision = "0143_create_location_ssid_tiers"
branch_labels = None
depends_on = None

_TABLE = "location_speed_gateways"
_BASE_INDEXED = ("created_at", "deleted_at", "is_deleted", "created_by", "updated_by")


def upgrade() -> None:
    op.create_table(
        _TABLE,
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "is_deleted", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("updated_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "location_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("locations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "nas_router_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("routers.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "gateway_router_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("routers.id", ondelete="CASCADE"),
            nullable=False,
        ),
    )
    for column in _BASE_INDEXED:
        op.create_index(f"ix_{_TABLE}_{column}", _TABLE, [column])
    op.create_index(f"ix_{_TABLE}_organization_id", _TABLE, ["organization_id"])
    op.create_index(f"ix_{_TABLE}_location_id", _TABLE, ["location_id"])
    op.create_index(f"ix_{_TABLE}_gateway_router_id", _TABLE, ["gateway_router_id"])
    op.create_index(
        f"uq_{_TABLE}_nas_router_id",
        _TABLE,
        ["nas_router_id"],
        unique=True,
        postgresql_where=sa.text("is_deleted = false"),
    )


def downgrade() -> None:
    op.drop_index(f"uq_{_TABLE}_nas_router_id", table_name=_TABLE)
    op.drop_index(f"ix_{_TABLE}_gateway_router_id", table_name=_TABLE)
    op.drop_index(f"ix_{_TABLE}_location_id", table_name=_TABLE)
    op.drop_index(f"ix_{_TABLE}_organization_id", table_name=_TABLE)
    for column in reversed(_BASE_INDEXED):
        op.drop_index(f"ix_{_TABLE}_{column}", table_name=_TABLE)
    op.drop_table(_TABLE)
