"""Hotspot Settings domain: ``hotspot_profiles``.

New domain (``app.domains.hotspot``), a per-router hotspot user-profile
inventory (see ``service.py``'s own module docstring). One new table,
additive only:

* ``hotspot_profiles`` -- one row per hotspot user-profile a router
  serves (session/idle timeout, upload/download rate limits, a
  walled-garden host list). No database-level uniqueness constraint on
  ``name`` -- mirrors ``dhcp_pools``'s own identical posture.

A pure rules/inventory domain -- no live device push, no history table:
a row's own state *is* its current state, and real RouterOS
``/ip hotspot`` provisioning is composed via the already-built Network
Configuration Management domain (``app.domains.network_config``), not
this domain.

No RBAC schema change beyond upgrading the already pre-seeded
``PermissionModule.HOTSPOT``'s display name (``"Hotspot"`` ->
``"Hotspot Settings"``) plus additive ``AuditAction`` enum values
(``HOTSPOT_PROFILE_CREATED``/``HOTSPOT_PROFILE_UPDATED``/
``HOTSPOT_PROFILE_DELETED``) -- no migration needed for any of those
(``permission_groups``/``permissions``/``permission_scopes``/
``role_permissions`` rows are all seeded idempotently at
application/CLI startup by ``seed_rbac``, never by a migration, per this
codebase's own established convention -- see e.g. migration ``0039``'s
identical note).

Revision ID: 0044_create_hotspot_tables
Revises: 0043_create_device_sync_tables
Create Date: 2026-07-21
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0044_create_hotspot_tables"
down_revision = "0043_create_device_sync_tables"
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
        "hotspot_profiles",
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
        sa.Column("session_timeout_minutes", sa.Integer(), nullable=True),
        sa.Column("idle_timeout_minutes", sa.Integer(), nullable=True),
        sa.Column("upload_limit_kbps", sa.Integer(), nullable=True),
        sa.Column("download_limit_kbps", sa.Integer(), nullable=True),
        sa.Column(
            "walled_garden_hosts",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    _create_base_model_indexes("hotspot_profiles")
    op.create_index("ix_hotspot_profiles_router_id", "hotspot_profiles", ["router_id"])
    op.create_index(
        "ix_hotspot_profiles_organization_id", "hotspot_profiles", ["organization_id"]
    )
    op.create_index(
        "ix_hotspot_profiles_location_id", "hotspot_profiles", ["location_id"]
    )
    op.create_index(
        "ix_hotspot_profiles_is_enabled", "hotspot_profiles", ["is_enabled"]
    )


def downgrade() -> None:
    op.drop_index("ix_hotspot_profiles_is_enabled", table_name="hotspot_profiles")
    op.drop_index("ix_hotspot_profiles_location_id", table_name="hotspot_profiles")
    op.drop_index("ix_hotspot_profiles_organization_id", table_name="hotspot_profiles")
    op.drop_index("ix_hotspot_profiles_router_id", table_name="hotspot_profiles")
    _drop_base_model_indexes("hotspot_profiles")
    op.drop_table("hotspot_profiles")
