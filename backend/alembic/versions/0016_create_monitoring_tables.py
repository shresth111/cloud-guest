"""Create Monitoring domain tables: health_checks, service_health,
heartbeat_logs, platform_events.

Mirrors ``0015_create_guest_tables``'s conventions: each table gets the
``BaseModel`` column set (id, created_at, updated_at, soft-delete, audit,
version) plus its own base-model indexes, using the same
``_base_model_columns``/``_create_base_model_indexes`` helpers (duplicated
here, not imported -- Alembic migrations are meant to be self-contained
snapshots rather than depending on other migration modules).

This is BE-011 Part 1 (Health Engine + Event Engine)'s migration -- four new
tables:

* ``health_checks`` -- one row per health-check execution for one platform
  component (database/redis/api/auth/storage/celery/websocket/freeradius/
  wireguard). No FKs -- a pure, self-contained time-series row.
* ``service_health`` -- one row *per component* (unique on ``component``),
  the current rolled-up state a dashboard reads without scanning
  ``health_checks`` history.
* ``heartbeat_logs`` -- a generic, cross-domain heartbeat log.
  ``component_id`` is a plain, **unconstrained** UUID column (no FK) since
  it polymorphically refers to a different table depending on
  ``component_type`` -- see ``app.domains.monitoring.models.HeartbeatLog``'s
  module docstring for the full design write-up.
* ``platform_events`` -- a narrowly-scoped new event table (this module's
  own Health Engine's status-transition detections only -- see
  ``app.domains.monitoring.models.PlatformEvent``'s module docstring for why
  this is not a duplicate of ``audit_log_entries``/``router_events``), FK'd
  (all nullable, ``SET NULL``) to ``organizations``/``locations``/``routers``
  for forward-compatible domain-scoped events.

Deliberately does **not** create a ``device_health`` table -- see
``app.domains.monitoring.models``'s module docstring for the full "why no
new table, and not even a new composition method, earns its keep here"
write-up: ``app.domains.router.models.Router.health_status``/
``last_seen_at``/``last_health_check_at`` plus
``app.domains.router_provisioning.models.RouterHealthSnapshot``/
``RouterEvent`` already provide everything a per-router health rollup would
need.

No RBAC FK follow-up migration is needed (unlike Modules 005/006/008's own
follow-ups): none of these tables are referenced by any RBAC scope column.

Revision ID: 0016_create_monitoring_tables
Revises: 0015_create_guest_tables
Create Date: 2026-07-18
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0016_create_monitoring_tables"
down_revision = "0015_create_guest_tables"
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
    # -- health_checks -------------------------------------------------------
    op.create_table(
        "health_checks",
        *_base_model_columns(),
        sa.Column("component", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("response_time_ms", sa.Float(), nullable=True),
        sa.Column("details", postgresql.JSONB(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
    )
    _create_base_model_indexes("health_checks")
    op.create_index("ix_health_checks_component", "health_checks", ["component"])
    op.create_index("ix_health_checks_status", "health_checks", ["status"])
    op.create_index("ix_health_checks_checked_at", "health_checks", ["checked_at"])

    # -- service_health --------------------------------------------------------
    op.create_table(
        "service_health",
        *_base_model_columns(),
        sa.Column("component", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "consecutive_failure_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )
    _create_base_model_indexes("service_health")
    op.create_index(
        "ix_service_health_component", "service_health", ["component"], unique=True
    )
    op.create_index("ix_service_health_status", "service_health", ["status"])

    # -- heartbeat_logs --------------------------------------------------------
    op.create_table(
        "heartbeat_logs",
        *_base_model_columns(),
        sa.Column("component_type", sa.String(20), nullable=False),
        sa.Column("component_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=True),
    )
    _create_base_model_indexes("heartbeat_logs")
    op.create_index(
        "ix_heartbeat_logs_component_type", "heartbeat_logs", ["component_type"]
    )
    op.create_index(
        "ix_heartbeat_logs_component_id", "heartbeat_logs", ["component_id"]
    )
    op.create_index("ix_heartbeat_logs_received_at", "heartbeat_logs", ["received_at"])

    # -- platform_events -------------------------------------------------------
    op.create_table(
        "platform_events",
        *_base_model_columns(),
        sa.Column("category", sa.String(20), nullable=False),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("location_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("router_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("source_domain", sa.String(50), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("metadata", postgresql.JSONB(), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_platform_events_organization_id_organizations",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["location_id"],
            ["locations.id"],
            name="fk_platform_events_location_id_locations",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["router_id"],
            ["routers.id"],
            name="fk_platform_events_router_id_routers",
            ondelete="SET NULL",
        ),
    )
    _create_base_model_indexes("platform_events")
    op.create_index("ix_platform_events_category", "platform_events", ["category"])
    op.create_index("ix_platform_events_event_type", "platform_events", ["event_type"])
    op.create_index("ix_platform_events_severity", "platform_events", ["severity"])
    op.create_index(
        "ix_platform_events_organization_id", "platform_events", ["organization_id"]
    )
    op.create_index(
        "ix_platform_events_location_id", "platform_events", ["location_id"]
    )
    op.create_index("ix_platform_events_router_id", "platform_events", ["router_id"])
    op.create_index(
        "ix_platform_events_occurred_at", "platform_events", ["occurred_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_platform_events_occurred_at", table_name="platform_events")
    op.drop_index("ix_platform_events_router_id", table_name="platform_events")
    op.drop_index("ix_platform_events_location_id", table_name="platform_events")
    op.drop_index("ix_platform_events_organization_id", table_name="platform_events")
    op.drop_index("ix_platform_events_severity", table_name="platform_events")
    op.drop_index("ix_platform_events_event_type", table_name="platform_events")
    op.drop_index("ix_platform_events_category", table_name="platform_events")
    _drop_base_model_indexes("platform_events")
    op.drop_table("platform_events")

    op.drop_index("ix_heartbeat_logs_received_at", table_name="heartbeat_logs")
    op.drop_index("ix_heartbeat_logs_component_id", table_name="heartbeat_logs")
    op.drop_index("ix_heartbeat_logs_component_type", table_name="heartbeat_logs")
    _drop_base_model_indexes("heartbeat_logs")
    op.drop_table("heartbeat_logs")

    op.drop_index("ix_service_health_status", table_name="service_health")
    op.drop_index("ix_service_health_component", table_name="service_health")
    _drop_base_model_indexes("service_health")
    op.drop_table("service_health")

    op.drop_index("ix_health_checks_checked_at", table_name="health_checks")
    op.drop_index("ix_health_checks_status", table_name="health_checks")
    op.drop_index("ix_health_checks_component", table_name="health_checks")
    _drop_base_model_indexes("health_checks")
    op.drop_table("health_checks")
