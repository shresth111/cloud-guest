"""Device Synchronization domain: ``device_sync_runs``.

New domain (``app.domains.device_sync``), an honest orchestrator over
every real per-router sync mechanism this codebase already has (see
``service.py``'s own module docstring). One new table, additive only:

* ``device_sync_runs`` -- one immutable row per orchestrated "sync this
  router" attempt, with a JSONB ``component_results`` column capturing
  each component's own outcome. No ``update``/soft-delete anywhere in
  this domain -- "Sync History" is simply querying this table, mirroring
  ``app.domains.provisioning_engine.models.ProvisionJob``'s own "new
  row, not mutate" convention.

No RBAC schema change beyond a brand-new, additive
``PermissionModule.DEVICE_SYNC`` seeded module (``rbac/enums.py``/
``rbac/seed.py``) plus one additive ``AuditAction`` enum value
(``DEVICE_SYNC_RUN_COMPLETED``) -- no migration needed for any of those
(``permission_groups``/``permissions``/``permission_scopes``/
``role_permissions`` rows are all seeded idempotently at application/CLI
startup by ``seed_rbac``, never by a migration, per this codebase's own
established convention -- see e.g. migration ``0042``'s identical note).

This migration also has no bearing on ``app.domains.queue_management``'s
own tables -- the new ``reapply_assignments_for_router`` method added to
that domain's service reuses its existing schema unchanged.

Revision ID: 0043_create_device_sync_tables
Revises: 0042_create_connected_devices_tables
Create Date: 2026-07-21
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0043_create_device_sync_tables"
down_revision = "0042_create_connected_devices_tables"
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
        "device_sync_runs",
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
        sa.Column("status", sa.String(10), nullable=False, server_default="success"),
        sa.Column(
            "component_results",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
    )
    _create_base_model_indexes("device_sync_runs")
    op.create_index("ix_device_sync_runs_router_id", "device_sync_runs", ["router_id"])
    op.create_index(
        "ix_device_sync_runs_organization_id",
        "device_sync_runs",
        ["organization_id"],
    )
    op.create_index(
        "ix_device_sync_runs_location_id", "device_sync_runs", ["location_id"]
    )
    op.create_index(
        "ix_device_sync_runs_started_at", "device_sync_runs", ["started_at"]
    )
    op.create_index("ix_device_sync_runs_status", "device_sync_runs", ["status"])


def downgrade() -> None:
    op.drop_index("ix_device_sync_runs_status", table_name="device_sync_runs")
    op.drop_index("ix_device_sync_runs_started_at", table_name="device_sync_runs")
    op.drop_index("ix_device_sync_runs_location_id", table_name="device_sync_runs")
    op.drop_index("ix_device_sync_runs_organization_id", table_name="device_sync_runs")
    op.drop_index("ix_device_sync_runs_router_id", table_name="device_sync_runs")
    _drop_base_model_indexes("device_sync_runs")
    op.drop_table("device_sync_runs")
