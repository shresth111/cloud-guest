"""Network Diagnostics domain: ``diagnostic_runs``.

New domain (``app.domains.network_diagnostics``), a real, on-demand
``ping``/``traceroute`` execution history (see ``service.py``'s own
module docstring). One new table, additive only:

* ``diagnostic_runs`` -- one row per executed diagnostic attempt.
  Immutable/append-only -- no ``update``/soft-delete method exists in
  this domain's own repository, mirroring
  ``app.domains.device_sync.models.DeviceSyncRun``'s own identical
  "new row, not mutate" convention.

Unlike the "config resource" domains (DHCP/VLAN/Port Forwarding/
Hotspot/QoS), this is a real-time execution domain -- it owns no config
to render and is therefore never composed into ``app.domains
.network_config``'s own pipeline.

No RBAC schema change beyond a brand-new, additive ``PermissionModule
.NETWORK_DIAGNOSTICS`` seeded module (``rbac/enums.py``/``rbac/seed.py``)
plus one additive ``AuditAction`` enum value
(``NETWORK_DIAGNOSTIC_RUN_COMPLETED``) -- no migration needed for any of
those (``permission_groups``/``permissions``/``permission_scopes``/
``role_permissions`` rows are all seeded idempotently at application/CLI
startup by ``seed_rbac``, never by a migration, per this codebase's own
established convention -- see e.g. migration ``0039``'s identical note).

Revision ID: 0046_create_network_diagnostics_tables
Revises: 0045_create_qos_tables
Create Date: 2026-07-21
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0046_create_network_diagnostics_tables"
down_revision = "0045_create_qos_tables"
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
        "diagnostic_runs",
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
        sa.Column("diagnostic_type", sa.String(20), nullable=False),
        sa.Column("target", sa.String(255), nullable=False),
        sa.Column("status", sa.String(10), nullable=False, server_default="success"),
        sa.Column(
            "result",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("error_message", sa.String(500), nullable=True),
        sa.Column("executed_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    _create_base_model_indexes("diagnostic_runs")
    op.create_index("ix_diagnostic_runs_router_id", "diagnostic_runs", ["router_id"])
    op.create_index(
        "ix_diagnostic_runs_organization_id", "diagnostic_runs", ["organization_id"]
    )
    op.create_index(
        "ix_diagnostic_runs_location_id", "diagnostic_runs", ["location_id"]
    )
    op.create_index(
        "ix_diagnostic_runs_diagnostic_type", "diagnostic_runs", ["diagnostic_type"]
    )
    op.create_index("ix_diagnostic_runs_status", "diagnostic_runs", ["status"])


def downgrade() -> None:
    op.drop_index("ix_diagnostic_runs_status", table_name="diagnostic_runs")
    op.drop_index("ix_diagnostic_runs_diagnostic_type", table_name="diagnostic_runs")
    op.drop_index("ix_diagnostic_runs_location_id", table_name="diagnostic_runs")
    op.drop_index("ix_diagnostic_runs_organization_id", table_name="diagnostic_runs")
    op.drop_index("ix_diagnostic_runs_router_id", table_name="diagnostic_runs")
    _drop_base_model_indexes("diagnostic_runs")
    op.drop_table("diagnostic_runs")
