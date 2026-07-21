"""Network Device (NAC) domain: ``network_devices``.

New domain (``app.domains.network_device``) -- a device identity/
compliance registry, distinct from ``app.domains.guest_access
.DeviceAccessRule`` (an allow/deny decision) and
``app.domains.connected_devices`` (live/recent presence telemetry). One
new table, additive only.

``router_id`` is nullable (a device can be pre-registered before it has
ever been seen on any specific router, and may roam across routers at one
location) -- see ``models.NetworkDevice``'s own module docstring.

New RBAC module -- ``PermissionModule.NETWORK_DEVICE`` (scope
``LOCATION``, actions CREATE/READ/UPDATE/DELETE/MANAGE) and four additive
``AuditAction`` enum values need no migration (seeded idempotently by
``seed_rbac``/written directly by the service, never by a migration, per
this codebase's own established convention).

Revision ID: 0054_create_network_device_tables
Revises: 0053_create_firewall_tables
Create Date: 2026-07-21
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0054_create_network_device_tables"
down_revision = "0053_create_firewall_tables"
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
        "network_devices",
        *_base_model_columns(),
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
            "router_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("routers.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("mac_address", sa.String(17), nullable=False),
        sa.Column("vendor", sa.String(100), nullable=True),
        sa.Column("device_type", sa.String(100), nullable=True),
        sa.Column(
            "compliance_status",
            sa.String(20),
            nullable=False,
            server_default="unknown",
        ),
        sa.Column("compliance_notes", sa.Text(), nullable=True),
        sa.Column("last_reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column(
            "is_active", sa.Boolean(), nullable=False, server_default=sa.true()
        ),
    )
    _create_base_model_indexes("network_devices")
    op.create_index(
        "ix_network_devices_organization_id", "network_devices", ["organization_id"]
    )
    op.create_index(
        "ix_network_devices_location_id", "network_devices", ["location_id"]
    )
    op.create_index("ix_network_devices_router_id", "network_devices", ["router_id"])
    op.create_index(
        "ix_network_devices_mac_address", "network_devices", ["mac_address"]
    )
    op.create_index(
        "ix_network_devices_compliance_status",
        "network_devices",
        ["compliance_status"],
    )
    op.create_index(
        "ix_network_devices_is_active", "network_devices", ["is_active"]
    )


def downgrade() -> None:
    op.drop_index("ix_network_devices_is_active", table_name="network_devices")
    op.drop_index(
        "ix_network_devices_compliance_status", table_name="network_devices"
    )
    op.drop_index("ix_network_devices_mac_address", table_name="network_devices")
    op.drop_index("ix_network_devices_router_id", table_name="network_devices")
    op.drop_index("ix_network_devices_location_id", table_name="network_devices")
    op.drop_index(
        "ix_network_devices_organization_id", table_name="network_devices"
    )
    _drop_base_model_indexes("network_devices")
    op.drop_table("network_devices")
