"""VLAN Management domain: ``vlans``.

New domain (``app.domains.vlan``), a per-router VLAN inventory (see
``service.py``'s own module docstring). One new table, additive only:

* ``vlans`` -- one row per VLAN a router carries. A partial unique index
  (``uq_vlans_router_id_vlan_id``) enforces "a router may not hold two
  non-deleted VLANs with the same vlan_id" at the database level,
  mirroring migration ``0036``'s (``isp_links``) identical
  partial-unique-index precedent.

A pure rules/inventory domain -- no live device push, no history table
(see ``models.py``'s own module docstring): a row's own state *is* its
current state, and real RouterOS VLAN interface + IP address provisioning
is deferred to the not-yet-built Network Configuration Management
domain's own provisioning-integration layer.

No RBAC schema change beyond a brand-new, additive
``PermissionModule.VLAN`` seeded module (``rbac/enums.py``/
``rbac/seed.py``) plus additive ``AuditAction`` enum values
(``VLAN_CREATED``/``VLAN_UPDATED``/``VLAN_DELETED``) -- no migration
needed for any of those (``permission_groups``/``permissions``/
``permission_scopes``/``role_permissions`` rows are all seeded
idempotently at application/CLI startup by ``seed_rbac``, never by a
migration, per this codebase's own established convention -- see e.g.
migration ``0037``'s identical note).

Revision ID: 0038_create_vlan_tables
Revises: 0037_create_isp_routing_tables
Create Date: 2026-07-21
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0038_create_vlan_tables"
down_revision = "0037_create_isp_routing_tables"
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
        "vlans",
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
        sa.Column("vlan_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("gateway_ip_address", sa.String(45), nullable=True),
        sa.Column("cidr", sa.String(64), nullable=True),
        sa.Column("interface", sa.String(100), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    _create_base_model_indexes("vlans")
    op.create_index("ix_vlans_router_id", "vlans", ["router_id"])
    op.create_index("ix_vlans_organization_id", "vlans", ["organization_id"])
    op.create_index("ix_vlans_location_id", "vlans", ["location_id"])
    op.create_index("ix_vlans_is_enabled", "vlans", ["is_enabled"])
    op.create_index(
        "uq_vlans_router_id_vlan_id",
        "vlans",
        ["router_id", "vlan_id"],
        unique=True,
        postgresql_where=sa.text("is_deleted = false"),
    )


def downgrade() -> None:
    op.drop_index("uq_vlans_router_id_vlan_id", table_name="vlans")
    op.drop_index("ix_vlans_is_enabled", table_name="vlans")
    op.drop_index("ix_vlans_location_id", table_name="vlans")
    op.drop_index("ix_vlans_organization_id", table_name="vlans")
    op.drop_index("ix_vlans_router_id", table_name="vlans")
    _drop_base_model_indexes("vlans")
    op.drop_table("vlans")
