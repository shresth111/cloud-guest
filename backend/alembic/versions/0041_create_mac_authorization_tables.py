"""MAC Authorization domain: ``mac_authorization_entries``.

New domain (``app.domains.mac_authorization``), an organization/location-
scoped MAC address whitelist (see ``service.py``'s own module
docstring). One new table, additive only:

* ``mac_authorization_entries`` -- one row per whitelisted MAC address.
  A partial unique index (``uq_mac_authorization_entries_org_id_mac_address``)
  enforces "an organization may not hold two non-deleted entries for the
  same MAC address" at the database level, mirroring migration ``0038``'s
  (``vlans``) identical partial-unique-index precedent.

Deliberately a standalone domain, not an extension of
``app.domains.guest_access.models.DeviceAccessRule`` -- see this
domain's own module docstring and ``docs/mac_authorization/FLOW.md`` for
the full reasoning (an explicit scoping decision, not an oversight).

No RBAC schema change beyond a brand-new, additive
``PermissionModule.MAC_AUTHORIZATION`` seeded module (``rbac/enums.py``/
``rbac/seed.py``) plus additive ``AuditAction`` enum values
(``MAC_AUTHORIZATION_ENTRY_CREATED``/``_UPDATED``/``_DELETED``) -- no
migration needed for any of those (``permission_groups``/``permissions``/
``permission_scopes``/``role_permissions`` rows are all seeded
idempotently at application/CLI startup by ``seed_rbac``, never by a
migration, per this codebase's own established convention -- see e.g.
migration ``0040``'s identical note).

Revision ID: 0041_create_mac_authorization_tables
Revises: 0040_create_port_forwarding_tables
Create Date: 2026-07-21
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0041_create_mac_authorization_tables"
down_revision = "0040_create_port_forwarding_tables"
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
        "mac_authorization_entries",
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
            nullable=True,
        ),
        sa.Column("mac_address", sa.String(17), nullable=False),
        sa.Column(
            "authorization_type",
            sa.String(20),
            nullable=False,
            server_default="permanent",
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    _create_base_model_indexes("mac_authorization_entries")
    op.create_index(
        "ix_mac_authorization_entries_organization_id",
        "mac_authorization_entries",
        ["organization_id"],
    )
    op.create_index(
        "ix_mac_authorization_entries_location_id",
        "mac_authorization_entries",
        ["location_id"],
    )
    op.create_index(
        "ix_mac_authorization_entries_mac_address",
        "mac_authorization_entries",
        ["mac_address"],
    )
    op.create_index(
        "ix_mac_authorization_entries_is_enabled",
        "mac_authorization_entries",
        ["is_enabled"],
    )
    op.create_index(
        "uq_mac_authorization_entries_org_id_mac_address",
        "mac_authorization_entries",
        ["organization_id", "mac_address"],
        unique=True,
        postgresql_where=sa.text("is_deleted = false"),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_mac_authorization_entries_org_id_mac_address",
        table_name="mac_authorization_entries",
    )
    op.drop_index(
        "ix_mac_authorization_entries_is_enabled",
        table_name="mac_authorization_entries",
    )
    op.drop_index(
        "ix_mac_authorization_entries_mac_address",
        table_name="mac_authorization_entries",
    )
    op.drop_index(
        "ix_mac_authorization_entries_location_id",
        table_name="mac_authorization_entries",
    )
    op.drop_index(
        "ix_mac_authorization_entries_organization_id",
        table_name="mac_authorization_entries",
    )
    _drop_base_model_indexes("mac_authorization_entries")
    op.drop_table("mac_authorization_entries")
