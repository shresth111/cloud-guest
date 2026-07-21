"""Connected Device Management domain: ``connected_devices``.

New domain (``app.domains.connected_devices``), a per-router inventory
of every device seen on the network via real DHCP-lease/ARP/wireless
registration-table sync (see ``service.py``'s own module docstring). One
new table, additive only:

* ``connected_devices`` -- one row per device seen on a router. A
  partial unique index (``uq_connected_devices_router_id_mac_address``)
  enforces "a router may not hold two non-deleted rows for the same MAC
  address" at the database level, mirroring migration ``0038``'s
  (``vlans``) identical partial-unique-index precedent. ``guest_id``/
  ``guest_session_id`` are nullable FKs to ``guests``/``guest_sessions``
  -- a synced snapshot of a read-only cross-reference against
  ``app.domains.guest``, never authoritative itself (see ``models.py``'s
  own module docstring).

No history table -- a row's own state *is* its most recently synced
state; a device that drops off the router's own tables has
``is_active`` flipped to ``False``, never soft-deleted by the sync
itself.

No RBAC schema change beyond a brand-new, additive
``PermissionModule.CONNECTED_DEVICES`` seeded module (``rbac/enums.py``/
``rbac/seed.py``) plus additive ``AuditAction`` enum values
(``CONNECTED_DEVICE_DISCONNECTED``/``_DELETED``/``_COMMENT_ADDED``/
``_BLOCKED``/``_UNBLOCKED``/``_WHITELISTED``) -- no migration needed for
any of those (``permission_groups``/``permissions``/
``permission_scopes``/``role_permissions`` rows are all seeded
idempotently at application/CLI startup by ``seed_rbac``, never by a
migration, per this codebase's own established convention -- see e.g.
migration ``0041``'s identical note).

Revision ID: 0042_create_connected_devices_tables
Revises: 0041_create_mac_authorization_tables
Create Date: 2026-07-21
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0042_create_connected_devices_tables"
down_revision = "0041_create_mac_authorization_tables"
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
        "connected_devices",
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
        sa.Column("mac_address", sa.String(17), nullable=False),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("hostname", sa.String(255), nullable=True),
        sa.Column("vendor", sa.String(100), nullable=True),
        sa.Column(
            "connection_type", sa.String(10), nullable=False, server_default="unknown"
        ),
        sa.Column("interface", sa.String(100), nullable=True),
        sa.Column("signal_strength_dbm", sa.Integer(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("connected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column(
            "guest_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("guests.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "guest_session_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("guest_sessions.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    _create_base_model_indexes("connected_devices")
    op.create_index(
        "ix_connected_devices_router_id", "connected_devices", ["router_id"]
    )
    op.create_index(
        "ix_connected_devices_organization_id",
        "connected_devices",
        ["organization_id"],
    )
    op.create_index(
        "ix_connected_devices_location_id", "connected_devices", ["location_id"]
    )
    op.create_index(
        "ix_connected_devices_mac_address", "connected_devices", ["mac_address"]
    )
    op.create_index(
        "ix_connected_devices_is_active", "connected_devices", ["is_active"]
    )
    op.create_index("ix_connected_devices_guest_id", "connected_devices", ["guest_id"])
    op.create_index(
        "uq_connected_devices_router_id_mac_address",
        "connected_devices",
        ["router_id", "mac_address"],
        unique=True,
        postgresql_where=sa.text("is_deleted = false"),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_connected_devices_router_id_mac_address", table_name="connected_devices"
    )
    op.drop_index("ix_connected_devices_guest_id", table_name="connected_devices")
    op.drop_index("ix_connected_devices_is_active", table_name="connected_devices")
    op.drop_index("ix_connected_devices_mac_address", table_name="connected_devices")
    op.drop_index("ix_connected_devices_location_id", table_name="connected_devices")
    op.drop_index(
        "ix_connected_devices_organization_id", table_name="connected_devices"
    )
    op.drop_index("ix_connected_devices_router_id", table_name="connected_devices")
    _drop_base_model_indexes("connected_devices")
    op.drop_table("connected_devices")
