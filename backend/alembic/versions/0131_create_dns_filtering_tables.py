"""Cloudflare Gateway DNS filtering: profiles, policies, router locations.

Three new tables, additive only (see ``app.domains.dns_filtering.models``
for why there are three owners):

* ``dns_filtering_profiles`` -- platform-owned, one per distinct category
  set, one Gateway DNS rule each. Shared across venues and organizations so
  the account's 500-policy ceiling grows with distinct choices, not venues.
* ``dns_filtering_policies`` -- a tenant's choice, per organization
  (``location_id IS NULL``) or per venue.
* ``dns_filtering_router_locations`` -- a router's Gateway DNS location,
  its pre-switch DNS snapshot, and its push state.

Nothing to backfill: no router has ever been pointed at Gateway.

**Head coordination.** Based on
``0130_add_device_push_columns_to_firewall_rules`` (PR #304, merged first),
so the chain keeps a single head.

Downgrade drops all three. Any router still switched to Gateway keeps its
DoH setting on the device and loses the snapshot that would restore it --
disable every router first.

Revision ID: 0131_create_dns_filtering_tables
Revises: 0130_add_device_push_columns_to_firewall_rules
Create Date: 2026-09-23
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0131_create_dns_filtering_tables"
down_revision = "0130_add_device_push_columns_to_firewall_rules"
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


def upgrade() -> None:
    op.create_table(
        "dns_filtering_profiles",
        *_base_columns(),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("category_ids", postgresql.JSONB(), nullable=False),
        sa.Column("cf_rule_id", sa.String(length=64), nullable=True),
        sa.Column("rule_precedence", sa.Integer(), nullable=False),
        sa.Column(
            "sync_status",
            sa.String(length=20),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("sync_error", sa.Text(), nullable=True),
        sa.Column("synced_at", sa.DateTime(timezone=True), nullable=True),
    )
    _base_indexes("dns_filtering_profiles")
    op.create_index(
        "uq_dns_filtering_profiles_fingerprint",
        "dns_filtering_profiles",
        ["fingerprint"],
        unique=True,
        postgresql_where=sa.text("is_deleted = false"),
    )
    op.create_index(
        "uq_dns_filtering_profiles_rule_precedence",
        "dns_filtering_profiles",
        ["rule_precedence"],
        unique=True,
    )

    op.create_table(
        "dns_filtering_policies",
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
            nullable=True,
        ),
        sa.Column("category_ids", postgresql.JSONB(), nullable=False),
        sa.Column(
            "profile_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("dns_filtering_profiles.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    _base_indexes("dns_filtering_policies")
    op.create_index(
        "ix_dns_filtering_policies_organization_id",
        "dns_filtering_policies",
        ["organization_id"],
    )
    op.create_index(
        "uq_dns_filtering_policies_org_default",
        "dns_filtering_policies",
        ["organization_id"],
        unique=True,
        postgresql_where=sa.text("location_id IS NULL AND is_deleted = false"),
    )
    op.create_index(
        "uq_dns_filtering_policies_location",
        "dns_filtering_policies",
        ["location_id"],
        unique=True,
        postgresql_where=sa.text("location_id IS NOT NULL AND is_deleted = false"),
    )

    op.create_table(
        "dns_filtering_router_locations",
        *_base_columns(),
        sa.Column(
            "router_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("routers.id", ondelete="CASCADE"),
            nullable=False,
        ),
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
        sa.Column("cf_location_name", sa.String(length=100), nullable=False),
        sa.Column("cf_location_id", sa.String(length=64), nullable=True),
        sa.Column("doh_subdomain", sa.String(length=64), nullable=True),
        sa.Column(
            "applied_profile_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("dns_filtering_profiles.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "state", sa.String(length=20), nullable=False, server_default="pending"
        ),
        sa.Column("dns_snapshot", postgresql.JSONB(), nullable=True),
        sa.Column("routeros_version", sa.String(length=64), nullable=True),
        sa.Column(
            "device_push_status",
            sa.String(length=20),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("device_push_error", sa.Text(), nullable=True),
        sa.Column("device_pushed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "bypass_hardening_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "bypass_hardening_status",
            sa.String(length=20),
            nullable=False,
            server_default="off",
        ),
        sa.Column("bypass_hardening_error", sa.Text(), nullable=True),
    )
    _base_indexes("dns_filtering_router_locations")
    op.create_index(
        "uq_dns_filtering_router_locations_router_id",
        "dns_filtering_router_locations",
        ["router_id"],
        unique=True,
        postgresql_where=sa.text("is_deleted = false"),
    )
    for column in ("organization_id", "location_id", "applied_profile_id"):
        op.create_index(
            f"ix_dns_filtering_router_locations_{column}",
            "dns_filtering_router_locations",
            [column],
        )


def downgrade() -> None:
    op.drop_table("dns_filtering_router_locations")
    op.drop_table("dns_filtering_policies")
    op.drop_table("dns_filtering_profiles")
