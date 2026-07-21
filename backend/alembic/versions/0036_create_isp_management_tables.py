"""ISP Management domain: ``isp_links``, ``isp_health_checks``.

New domain (``app.domains.isp``), a per-router WAN/ISP uplink inventory
composing ``app.domains.router`` (see ``service.py``'s own module
docstring). Two new tables, additive only -- no existing table's own
columns are dropped or retyped:

* ``isp_links`` -- one row per WAN uplink a router carries, holding both
  its static admin-assigned priority (``role``/``priority``) and its
  *current* health snapshot (``health_status``/``latency_ms``/
  ``packet_loss_percentage``/``last_checked_at``) directly as columns. A
  partial unique index (``uq_isp_links_router_id_active_uplink``) enforces
  "at most one active uplink per router" at the database level, mirroring
  migration ``0026``'s (``guest_team_members``) identical partial-unique-
  index precedent.
* ``isp_health_checks`` -- an append-only time-series log of every real
  health-check execution against an ``isp_links`` row's own
  ``gateway_ip_address``, mirroring ``monitoring.models.HealthCheck``'s
  identical shape. This is what "History" (the roadmap's own named
  capability) means concretely -- see ``models.py``'s own module
  docstring.

No RBAC schema change beyond a brand-new, additive
``PermissionModule.ISP`` seeded module (``rbac/enums.py``/``rbac/seed.py``)
plus additive ``AuditAction`` enum values (``ISP_LINK_CREATED``/
``ISP_LINK_UPDATED``/``ISP_LINK_DELETED``/``ISP_FAILOVER_TRIGGERED``/
``ISP_FAILBACK_TRIGGERED``) -- no migration needed for any of those
(``permission_groups``/``permissions``/``permission_scopes``/
``role_permissions`` rows are all seeded idempotently at application/CLI
startup by ``seed_rbac``, never by a migration, per this codebase's own
established convention -- see e.g. migration ``0033``'s identical note).

Revision ID: 0036_create_isp_management_tables
Revises: 0035_create_voucher_plan_series_tables
Create Date: 2026-07-21
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0036_create_isp_management_tables"
down_revision = "0035_create_voucher_plan_series_tables"
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
    # -- isp_links ------------------------------------------------------------
    op.create_table(
        "isp_links",
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
        sa.Column("provider_name", sa.String(200), nullable=False),
        sa.Column("link_type", sa.String(20), nullable=False, server_default="other"),
        sa.Column("role", sa.String(10), nullable=False),
        sa.Column(
            "is_active_uplink", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column(
            "auto_failback", sa.Boolean(), nullable=False, server_default=sa.true()
        ),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("interface", sa.String(100), nullable=True),
        sa.Column("gateway_ip_address", sa.String(45), nullable=True),
        sa.Column("dns_primary", sa.String(45), nullable=True),
        sa.Column("dns_secondary", sa.String(45), nullable=True),
        sa.Column("download_bandwidth_mbps", sa.Integer(), nullable=True),
        sa.Column("upload_bandwidth_mbps", sa.Integer(), nullable=True),
        sa.Column(
            "health_status", sa.String(20), nullable=False, server_default="unknown"
        ),
        sa.Column("latency_ms", sa.Float(), nullable=True),
        sa.Column("packet_loss_percentage", sa.Float(), nullable=True),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "consecutive_unhealthy_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )
    _create_base_model_indexes("isp_links")
    op.create_index("ix_isp_links_router_id", "isp_links", ["router_id"])
    op.create_index("ix_isp_links_organization_id", "isp_links", ["organization_id"])
    op.create_index("ix_isp_links_location_id", "isp_links", ["location_id"])
    op.create_index("ix_isp_links_role", "isp_links", ["role"])
    op.create_index("ix_isp_links_health_status", "isp_links", ["health_status"])
    op.create_index("ix_isp_links_is_enabled", "isp_links", ["is_enabled"])
    op.create_index(
        "uq_isp_links_router_id_active_uplink",
        "isp_links",
        ["router_id"],
        unique=True,
        postgresql_where=sa.text("is_active_uplink = true AND is_deleted = false"),
    )

    # -- isp_health_checks ------------------------------------------------------
    op.create_table(
        "isp_health_checks",
        *_base_model_columns(),
        sa.Column(
            "isp_link_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("isp_links.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("latency_ms", sa.Float(), nullable=True),
        sa.Column("packet_loss_percentage", sa.Float(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
    )
    _create_base_model_indexes("isp_health_checks")
    op.create_index(
        "ix_isp_health_checks_isp_link_id", "isp_health_checks", ["isp_link_id"]
    )
    op.create_index(
        "ix_isp_health_checks_checked_at", "isp_health_checks", ["checked_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_isp_health_checks_checked_at", table_name="isp_health_checks")
    op.drop_index("ix_isp_health_checks_isp_link_id", table_name="isp_health_checks")
    _drop_base_model_indexes("isp_health_checks")
    op.drop_table("isp_health_checks")

    op.drop_index("uq_isp_links_router_id_active_uplink", table_name="isp_links")
    op.drop_index("ix_isp_links_is_enabled", table_name="isp_links")
    op.drop_index("ix_isp_links_health_status", table_name="isp_links")
    op.drop_index("ix_isp_links_role", table_name="isp_links")
    op.drop_index("ix_isp_links_location_id", table_name="isp_links")
    op.drop_index("ix_isp_links_organization_id", table_name="isp_links")
    op.drop_index("ix_isp_links_router_id", table_name="isp_links")
    _drop_base_model_indexes("isp_links")
    op.drop_table("isp_links")
