"""Monitored Hardware domain: ``monitored_hardware``.

New domain (``app.domains.monitored_hardware``) -- a real, persisted
registry of a venue's own network infrastructure (Access Points,
Printers, Routers, Cameras, Other), replacing a frontend feature that was
previously entirely browser-localStorage-only with no backend underneath
at all (see ``app.domains.monitored_hardware``'s own module docstring for
the full "why this exists" write-up). One new table, additive only.

Distinct from ``network_devices`` (a NAC identity/compliance registry --
unrelated purpose) and from ``connected_devices`` (live guest/LAN
presence telemetry, which this domain reads from at request time but
never writes to).

New RBAC module -- ``PermissionModule.MONITORED_HARDWARE`` (scope
``LOCATION``, actions CREATE/READ/DELETE) and two additive
``AuditAction`` enum values need no migration (seeded idempotently by
``seed_rbac``/written directly by the service, never by a migration, per
this codebase's own established convention -- see
``alembic/versions/0054_create_network_device_tables.py`` for the
identical precedent).

Revision ID: 0076_create_monitored_hardware_table
Revises: 0075_add_isp_health_check_composite_index
Create Date: 2026-08-04
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0076_create_monitored_hardware_table"
down_revision = "0075_add_isp_health_check_composite_index"
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
        "monitored_hardware",
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
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("mac_address", sa.String(17), nullable=False),
        sa.Column("device_type", sa.String(50), nullable=False),
        sa.Column("floor", sa.String(50), nullable=True),
    )
    _create_base_model_indexes("monitored_hardware")
    op.create_index(
        "ix_monitored_hardware_organization_id",
        "monitored_hardware",
        ["organization_id"],
    )
    op.create_index(
        "ix_monitored_hardware_location_id", "monitored_hardware", ["location_id"]
    )
    op.create_index(
        "ix_monitored_hardware_router_id", "monitored_hardware", ["router_id"]
    )
    op.create_index(
        "ix_monitored_hardware_mac_address", "monitored_hardware", ["mac_address"]
    )


def downgrade() -> None:
    op.drop_index(
        "ix_monitored_hardware_mac_address", table_name="monitored_hardware"
    )
    op.drop_index("ix_monitored_hardware_router_id", table_name="monitored_hardware")
    op.drop_index(
        "ix_monitored_hardware_location_id", table_name="monitored_hardware"
    )
    op.drop_index(
        "ix_monitored_hardware_organization_id", table_name="monitored_hardware"
    )
    _drop_base_model_indexes("monitored_hardware")
    op.drop_table("monitored_hardware")
