"""DHCP Pool Management domain: ``dhcp_pools``.

New domain (``app.domains.dhcp``), a per-router DHCP pool inventory (see
``service.py``'s own module docstring). One new table, additive only:

* ``dhcp_pools`` -- one row per DHCP address pool a router serves. No
  database-level range-overlap constraint -- see ``models.py``'s own
  module docstring for why conflict detection is a service-layer check
  only (a real, honest gap, not silently assumed away).

A pure rules/inventory domain -- no live device push, no history table:
a row's own state *is* its current state, and real RouterOS DHCP server/
pool provisioning is deferred to the not-yet-built Network Configuration
Management domain's own provisioning-integration layer.

No RBAC schema change beyond a brand-new, additive
``PermissionModule.DHCP`` seeded module (``rbac/enums.py``/
``rbac/seed.py``) plus additive ``AuditAction`` enum values
(``DHCP_POOL_CREATED``/``DHCP_POOL_UPDATED``/``DHCP_POOL_DELETED``) -- no
migration needed for any of those (``permission_groups``/``permissions``/
``permission_scopes``/``role_permissions`` rows are all seeded
idempotently at application/CLI startup by ``seed_rbac``, never by a
migration, per this codebase's own established convention -- see e.g.
migration ``0038``'s identical note).

Revision ID: 0039_create_dhcp_pool_tables
Revises: 0038_create_vlan_tables
Create Date: 2026-07-21
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0039_create_dhcp_pool_tables"
down_revision = "0038_create_vlan_tables"
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


def upgrade() -> None:
    op.create_table(
        "dhcp_pools",
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
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("interface", sa.String(100), nullable=True),
        sa.Column("address_range_start", sa.String(45), nullable=False),
        sa.Column("address_range_end", sa.String(45), nullable=False),
        sa.Column("gateway_ip_address", sa.String(45), nullable=True),
        sa.Column("dns_primary", sa.String(45), nullable=True),
        sa.Column("dns_secondary", sa.String(45), nullable=True),
        sa.Column(
            "lease_time_seconds", sa.Integer(), nullable=False, server_default="86400"
        ),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    _create_base_model_indexes("dhcp_pools")
    op.create_index("ix_dhcp_pools_router_id", "dhcp_pools", ["router_id"])
    op.create_index("ix_dhcp_pools_organization_id", "dhcp_pools", ["organization_id"])
    op.create_index("ix_dhcp_pools_location_id", "dhcp_pools", ["location_id"])
    op.create_index("ix_dhcp_pools_interface", "dhcp_pools", ["interface"])
    op.create_index("ix_dhcp_pools_is_enabled", "dhcp_pools", ["is_enabled"])


def downgrade() -> None:
    op.drop_index("ix_dhcp_pools_is_enabled", table_name="dhcp_pools")
    op.drop_index("ix_dhcp_pools_interface", table_name="dhcp_pools")
    op.drop_index("ix_dhcp_pools_location_id", table_name="dhcp_pools")
    op.drop_index("ix_dhcp_pools_organization_id", table_name="dhcp_pools")
    op.drop_index("ix_dhcp_pools_router_id", table_name="dhcp_pools")
    _drop_base_model_indexes("dhcp_pools")
    op.drop_table("dhcp_pools")
