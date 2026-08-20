"""Router fleet redesign Wave 1: ``router_snapshots``.

Point-in-time, read-only discovery captures of a MikroTik's sanitized
RouterOS state (interfaces, bridges, DHCP, routes, firewall/NAT
*summaries*, hotspot, packages, …). One new table, additive only:

* ``router_snapshots`` -- append-only history of discovery runs. Never
  mutates an existing row; a fresh discover always inserts. Soft-delete
  columns come from ``BaseModel`` for consistency with every other domain
  table, even though Wave 1 never soft-deletes snapshots in practice.

JSONB section columns deliberately store **summaries / sanitized rows**,
never secret-bearing rule bodies (passwords, WireGuard private keys,
RADIUS secrets, scheduler ``on-event`` with agent credentials). Those are
stripped at the ``ReadOnlyDeviceReader`` boundary and again defensively
in the collector before persistence.

No RBAC schema change -- discovery reuses the already-seeded
``routers.read`` / ``routers.manage`` permission keys.

Revision ID: 0091_create_router_snapshots_table
Revises: 0090_add_powered_by_enabled_to_captive_portal_configs
Create Date: 2026-08-20
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0091_create_router_snapshots_table"
down_revision = "0090_add_powered_by_enabled_to_captive_portal_configs"
branch_labels = None
depends_on = None


def _base_model_columns() -> list[sa.Column]:
    """Columns provided by ``app.database.base.BaseModel`` for every table."""
    return [
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "is_deleted", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("updated_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
    ]


def _create_base_model_indexes(table_name: str) -> None:
    op.create_index(f"ix_{table_name}_created_at", table_name, ["created_at"])
    op.create_index(f"ix_{table_name}_deleted_at", table_name, ["deleted_at"])
    op.create_index(f"ix_{table_name}_is_deleted", table_name, ["is_deleted"])
    op.create_index(f"ix_{table_name}_created_by", table_name, ["created_by"])
    op.create_index(f"ix_{table_name}_updated_by", table_name, ["updated_by"])


def _drop_base_model_indexes(table_name: str) -> None:
    op.drop_index(f"ix_{table_name}_updated_by", table_name=table_name)
    op.drop_index(f"ix_{table_name}_created_by", table_name=table_name)
    op.drop_index(f"ix_{table_name}_is_deleted", table_name=table_name)
    op.drop_index(f"ix_{table_name}_deleted_at", table_name=table_name)
    op.drop_index(f"ix_{table_name}_created_at", table_name=table_name)


def _jsonb_array_column(name: str) -> sa.Column:
    return sa.Column(
        name,
        postgresql.JSONB(),
        nullable=False,
        server_default=sa.text("'[]'::jsonb"),
    )


def _jsonb_object_column(name: str) -> sa.Column:
    return sa.Column(
        name,
        postgresql.JSONB(),
        nullable=False,
        server_default=sa.text("'{}'::jsonb"),
    )


def upgrade() -> None:
    op.create_table(
        "router_snapshots",
        *_base_model_columns(),
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
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("trigger", sa.String(30), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("model", sa.String(100), nullable=True),
        sa.Column("routeros_version", sa.String(50), nullable=True),
        sa.Column("architecture", sa.String(50), nullable=True),
        sa.Column("total_memory_bytes", sa.BigInteger(), nullable=True),
        sa.Column("free_memory_bytes", sa.BigInteger(), nullable=True),
        sa.Column("free_storage_bytes", sa.BigInteger(), nullable=True),
        _jsonb_array_column("interfaces"),
        _jsonb_array_column("bridges"),
        _jsonb_array_column("ip_addresses"),
        _jsonb_array_column("dhcp_clients"),
        _jsonb_array_column("dhcp_servers"),
        _jsonb_array_column("routes"),
        _jsonb_object_column("dns_config"),
        _jsonb_object_column("firewall_summary"),
        _jsonb_object_column("nat_summary"),
        _jsonb_object_column("hotspot_state"),
        _jsonb_array_column("vlans"),
        _jsonb_array_column("services"),
        _jsonb_array_column("packages"),
        sa.Column("error_detail", sa.Text(), nullable=True),
    )
    _create_base_model_indexes("router_snapshots")
    op.create_index("ix_router_snapshots_router_id", "router_snapshots", ["router_id"])
    op.create_index(
        "ix_router_snapshots_captured_at", "router_snapshots", ["captured_at"]
    )
    op.create_index(
        "ix_router_snapshots_organization_id", "router_snapshots", ["organization_id"]
    )


def downgrade() -> None:
    op.drop_index(
        "ix_router_snapshots_organization_id", table_name="router_snapshots"
    )
    op.drop_index("ix_router_snapshots_captured_at", table_name="router_snapshots")
    op.drop_index("ix_router_snapshots_router_id", table_name="router_snapshots")
    _drop_base_model_indexes("router_snapshots")
    op.drop_table("router_snapshots")
