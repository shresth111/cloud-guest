"""Speed tiers by WiFi network (SSID) at Aruba Instant On venues:
``location_ssid_tiers``.

One row per guest SSID of a location: the tier it stands for, the per-guest
speed Instant On caps that SSID at, and whether joining it needs an
entitlement (voucher pass / Access Tier). New and empty; a location with no
rows behaves exactly as before (see ``app.domains.guest.ssid_tiers``).

Downgrade drops the table.

Revision ID: 0143_create_location_ssid_tiers
Revises: 0142_create_instant_on_poller_tables
Create Date: 2026-10-03
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0143_create_location_ssid_tiers"
down_revision = "0142_create_instant_on_poller_tables"
branch_labels = None
depends_on = None

_BASE_INDEXED = ("created_at", "deleted_at", "is_deleted", "created_by", "updated_by")


def _base_columns() -> list[sa.Column]:
    return [
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
    ]


def _base_indexes(table: str) -> None:
    for column in _BASE_INDEXED:
        op.create_index(f"ix_{table}_{column}", table, [column])


def _drop_base_indexes(table: str) -> None:
    for column in reversed(_BASE_INDEXED):
        op.drop_index(f"ix_{table}_{column}", table_name=table)


def upgrade() -> None:
    op.create_table(
        "location_ssid_tiers",
        *_base_columns(),
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
        sa.Column("ssid", sa.String(length=32), nullable=False),
        sa.Column("tier_name", sa.String(length=100), nullable=False),
        sa.Column(
            "requires_entitlement",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "policy_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("policies.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "voucher_plan_ids",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("download_mbps", sa.Integer(), nullable=True),
        sa.Column("upload_mbps", sa.Integer(), nullable=True),
        sa.Column("sort_order", sa.Integer(), nullable=False, server_default="0"),
    )
    _base_indexes("location_ssid_tiers")
    op.create_index(
        "ix_location_ssid_tiers_organization_id",
        "location_ssid_tiers",
        ["organization_id"],
    )
    op.create_index(
        "ix_location_ssid_tiers_location_id", "location_ssid_tiers", ["location_id"]
    )
    op.create_index(
        "uq_location_ssid_tiers_location_ssid",
        "location_ssid_tiers",
        ["location_id", sa.text("lower(ssid)")],
        unique=True,
        postgresql_where=sa.text("is_deleted = false"),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_location_ssid_tiers_location_ssid", table_name="location_ssid_tiers"
    )
    op.drop_index(
        "ix_location_ssid_tiers_location_id", table_name="location_ssid_tiers"
    )
    op.drop_index(
        "ix_location_ssid_tiers_organization_id", table_name="location_ssid_tiers"
    )
    _drop_base_indexes("location_ssid_tiers")
    op.drop_table("location_ssid_tiers")
