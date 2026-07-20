"""Create Alert Engine, Notification Engine, Incident Engine, and SLA
Monitoring tables (BE-011 Part 2).

Mirrors ``0016_create_monitoring_tables``'s conventions: each table gets the
``BaseModel`` column set (id, created_at, updated_at, soft-delete, audit,
version) plus its own base-model indexes, using the same
``_base_model_columns``/``_create_base_model_indexes`` helpers (duplicated
here, not imported -- Alembic migrations are meant to be self-contained
snapshots rather than depending on other migration modules).

Nine new tables, created in FK-dependency order:

* ``notification_channels`` -- a configured delivery destination
  (email/sms/whatsapp/slack/teams/discord/webhook). ``config_encrypted`` is
  Fernet-encrypted JSON (``app.domains.router.crypto``), never plaintext.
* ``alert_rules`` -- a watched condition (health-status-change/threshold/
  event-occurred). ``condition_config`` is JSONB, shape depends on
  ``trigger_type`` (see ``app.domains.monitoring.constants.AlertTriggerType``).
* ``alert_rule_notification_channels`` -- join table: which channels a
  triggered rule notifies (real referential integrity, not a JSONB id list).
* ``alerts`` -- one firing/resolved instance of a rule's condition.
  ``severity`` is copied from the rule at trigger time (never referenced
  live). FK's to ``health_checks``/``platform_events`` are nullable,
  ``SET NULL`` (an alert may optionally point at the specific health-check/
  event row that triggered it).
* ``notification_logs`` -- a durable delivery record (sent/failed) for every
  ``NotificationService.dispatch_notification`` attempt.
* ``incidents`` -- a human-managed grouping of related alerts. Fully
  manual, no auto-grouping heuristic (see
  ``app.domains.monitoring.models.IncidentAlert``'s docstring).
* ``incident_alerts`` -- join table: which alerts are grouped into an
  incident.
* ``sla_targets`` -- a committed uptime target, optionally scoped to an
  organization and/or a ``HealthComponent``.
* ``sla_reports`` -- a computed measurement of a target over a period,
  derived from ``health_checks`` history (``achieved_percentage =
  healthy_checks / total_checks * 100`` -- see
  ``app.domains.monitoring.service.SlaService.generate_report`` for the full
  formula write-up).

No RBAC FK follow-up migration is needed -- see
``docs/monitoring/DATABASE.md`` for the RBAC permission-key-reuse decisions
(there is no dedicated "incidents"/"sla" ``PermissionModule``; both reuse
existing seeded modules, a config-only decision with no schema impact).

Revision ID: 0017_create_alert_notification_incident_sla_tables
Revises: 0016_create_monitoring_tables
Create Date: 2026-07-18
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0017_create_alert_notification_incident_sla_tables"
down_revision = "0016_create_monitoring_tables"
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
    # -- notification_channels ------------------------------------------------
    op.create_table(
        "notification_channels",
        *_base_model_columns(),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("channel_type", sa.String(20), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("config_encrypted", sa.Text(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_notification_channels_organization_id_organizations",
            ondelete="SET NULL",
        ),
    )
    _create_base_model_indexes("notification_channels")
    op.create_index(
        "ix_notification_channels_organization_id",
        "notification_channels",
        ["organization_id"],
    )
    op.create_index(
        "ix_notification_channels_channel_type",
        "notification_channels",
        ["channel_type"],
    )
    op.create_index(
        "ix_notification_channels_is_active", "notification_channels", ["is_active"]
    )

    # -- alert_rules ------------------------------------------------------------
    op.create_table(
        "alert_rules",
        *_base_model_columns(),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("trigger_type", sa.String(30), nullable=False),
        sa.Column("target_component", sa.String(50), nullable=True),
        sa.Column(
            "condition_config",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_alert_rules_organization_id_organizations",
            ondelete="SET NULL",
        ),
    )
    _create_base_model_indexes("alert_rules")
    op.create_index(
        "ix_alert_rules_organization_id", "alert_rules", ["organization_id"]
    )
    op.create_index("ix_alert_rules_trigger_type", "alert_rules", ["trigger_type"])
    op.create_index("ix_alert_rules_is_active", "alert_rules", ["is_active"])

    # -- alert_rule_notification_channels ---------------------------------------
    op.create_table(
        "alert_rule_notification_channels",
        *_base_model_columns(),
        sa.Column("alert_rule_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "notification_channel_id", postgresql.UUID(as_uuid=True), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["alert_rule_id"],
            ["alert_rules.id"],
            name="fk_alert_rule_notification_channels_alert_rule_id_alert_rules",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["notification_channel_id"],
            ["notification_channels.id"],
            # Shortened from the naming convention's literal
            # "fk_alert_rule_notification_channels_notification_channel_id_
            # notification_channels" (81 characters), which exceeds
            # Postgres's 63-character identifier limit and fails at
            # DDL-compile time (verified via `alembic upgrade head --sql`)
            # -- fixed in place for the same reason
            # `0015_create_guest_tables.py`'s own identical fix documents:
            # this table has never been created against a real database.
            name="fk_arnc_notification_channel_id_notification_channels",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "alert_rule_id",
            "notification_channel_id",
            name="uq_alert_rule_notification_channels_rule_channel",
        ),
    )
    _create_base_model_indexes("alert_rule_notification_channels")
    op.create_index(
        "ix_alert_rule_notification_channels_alert_rule_id",
        "alert_rule_notification_channels",
        ["alert_rule_id"],
    )
    op.create_index(
        "ix_alert_rule_notification_channels_notification_channel_id",
        "alert_rule_notification_channels",
        ["notification_channel_id"],
    )

    # -- alerts -------------------------------------------------------------
    op.create_table(
        "alerts",
        *_base_model_columns(),
        sa.Column("rule_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("triggered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "acknowledged_by_user_id", postgresql.UUID(as_uuid=True), nullable=True
        ),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("location_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("router_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column(
            "related_health_check_id", postgresql.UUID(as_uuid=True), nullable=True
        ),
        sa.Column("related_event_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.ForeignKeyConstraint(
            ["rule_id"],
            ["alert_rules.id"],
            name="fk_alerts_rule_id_alert_rules",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_alerts_organization_id_organizations",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["location_id"],
            ["locations.id"],
            name="fk_alerts_location_id_locations",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["router_id"],
            ["routers.id"],
            name="fk_alerts_router_id_routers",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["related_health_check_id"],
            ["health_checks.id"],
            name="fk_alerts_related_health_check_id_health_checks",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["related_event_id"],
            ["platform_events.id"],
            name="fk_alerts_related_event_id_platform_events",
            ondelete="SET NULL",
        ),
    )
    _create_base_model_indexes("alerts")
    op.create_index("ix_alerts_rule_id", "alerts", ["rule_id"])
    op.create_index("ix_alerts_status", "alerts", ["status"])
    op.create_index("ix_alerts_organization_id", "alerts", ["organization_id"])
    op.create_index("ix_alerts_location_id", "alerts", ["location_id"])
    op.create_index("ix_alerts_router_id", "alerts", ["router_id"])
    op.create_index("ix_alerts_triggered_at", "alerts", ["triggered_at"])
    op.create_index("ix_alerts_severity", "alerts", ["severity"])

    # -- notification_logs ---------------------------------------------------
    op.create_table(
        "notification_logs",
        *_base_model_columns(),
        sa.Column("channel_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("alert_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("response_summary", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["channel_id"],
            ["notification_channels.id"],
            name="fk_notification_logs_channel_id_notification_channels",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["alert_id"],
            ["alerts.id"],
            name="fk_notification_logs_alert_id_alerts",
            ondelete="SET NULL",
        ),
    )
    _create_base_model_indexes("notification_logs")
    op.create_index(
        "ix_notification_logs_channel_id", "notification_logs", ["channel_id"]
    )
    op.create_index("ix_notification_logs_alert_id", "notification_logs", ["alert_id"])
    op.create_index("ix_notification_logs_status", "notification_logs", ["status"])
    op.create_index("ix_notification_logs_sent_at", "notification_logs", ["sent_at"])

    # -- incidents -------------------------------------------------------------
    op.create_table(
        "incidents",
        *_base_model_columns(),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("assigned_to_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolution_notes", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_incidents_organization_id_organizations",
            ondelete="SET NULL",
        ),
    )
    _create_base_model_indexes("incidents")
    op.create_index("ix_incidents_organization_id", "incidents", ["organization_id"])
    op.create_index("ix_incidents_status", "incidents", ["status"])
    op.create_index("ix_incidents_severity", "incidents", ["severity"])
    op.create_index("ix_incidents_opened_at", "incidents", ["opened_at"])

    # -- incident_alerts ---------------------------------------------------------
    op.create_table(
        "incident_alerts",
        *_base_model_columns(),
        sa.Column("incident_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("alert_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
            name="fk_incident_alerts_incident_id_incidents",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["alert_id"],
            ["alerts.id"],
            name="fk_incident_alerts_alert_id_alerts",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "incident_id", "alert_id", name="uq_incident_alerts_incident_alert"
        ),
    )
    _create_base_model_indexes("incident_alerts")
    op.create_index(
        "ix_incident_alerts_incident_id", "incident_alerts", ["incident_id"]
    )
    op.create_index("ix_incident_alerts_alert_id", "incident_alerts", ["alert_id"])

    # -- sla_targets -----------------------------------------------------------
    op.create_table(
        "sla_targets",
        *_base_model_columns(),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("component", sa.String(20), nullable=True),
        sa.Column("target_percentage", sa.Float(), nullable=False),
        sa.Column("measurement_window_days", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_sla_targets_organization_id_organizations",
            ondelete="SET NULL",
        ),
    )
    _create_base_model_indexes("sla_targets")
    op.create_index(
        "ix_sla_targets_organization_id", "sla_targets", ["organization_id"]
    )
    op.create_index("ix_sla_targets_component", "sla_targets", ["component"])

    # -- sla_reports -----------------------------------------------------------
    op.create_table(
        "sla_reports",
        *_base_model_columns(),
        sa.Column("sla_target_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("period_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("period_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("achieved_percentage", sa.Float(), nullable=False),
        sa.Column("total_checks", sa.Integer(), nullable=False),
        sa.Column("healthy_checks", sa.Integer(), nullable=False),
        sa.Column("average_response_time_ms", sa.Float(), nullable=True),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["sla_target_id"],
            ["sla_targets.id"],
            name="fk_sla_reports_sla_target_id_sla_targets",
            ondelete="CASCADE",
        ),
    )
    _create_base_model_indexes("sla_reports")
    op.create_index("ix_sla_reports_sla_target_id", "sla_reports", ["sla_target_id"])
    op.create_index("ix_sla_reports_period_start", "sla_reports", ["period_start"])
    op.create_index("ix_sla_reports_period_end", "sla_reports", ["period_end"])


def downgrade() -> None:
    op.drop_index("ix_sla_reports_period_end", table_name="sla_reports")
    op.drop_index("ix_sla_reports_period_start", table_name="sla_reports")
    op.drop_index("ix_sla_reports_sla_target_id", table_name="sla_reports")
    _drop_base_model_indexes("sla_reports")
    op.drop_table("sla_reports")

    op.drop_index("ix_sla_targets_component", table_name="sla_targets")
    op.drop_index("ix_sla_targets_organization_id", table_name="sla_targets")
    _drop_base_model_indexes("sla_targets")
    op.drop_table("sla_targets")

    op.drop_index("ix_incident_alerts_alert_id", table_name="incident_alerts")
    op.drop_index("ix_incident_alerts_incident_id", table_name="incident_alerts")
    _drop_base_model_indexes("incident_alerts")
    op.drop_table("incident_alerts")

    op.drop_index("ix_incidents_opened_at", table_name="incidents")
    op.drop_index("ix_incidents_severity", table_name="incidents")
    op.drop_index("ix_incidents_status", table_name="incidents")
    op.drop_index("ix_incidents_organization_id", table_name="incidents")
    _drop_base_model_indexes("incidents")
    op.drop_table("incidents")

    op.drop_index("ix_notification_logs_sent_at", table_name="notification_logs")
    op.drop_index("ix_notification_logs_status", table_name="notification_logs")
    op.drop_index("ix_notification_logs_alert_id", table_name="notification_logs")
    op.drop_index("ix_notification_logs_channel_id", table_name="notification_logs")
    _drop_base_model_indexes("notification_logs")
    op.drop_table("notification_logs")

    op.drop_index("ix_alerts_severity", table_name="alerts")
    op.drop_index("ix_alerts_triggered_at", table_name="alerts")
    op.drop_index("ix_alerts_router_id", table_name="alerts")
    op.drop_index("ix_alerts_location_id", table_name="alerts")
    op.drop_index("ix_alerts_organization_id", table_name="alerts")
    op.drop_index("ix_alerts_status", table_name="alerts")
    op.drop_index("ix_alerts_rule_id", table_name="alerts")
    _drop_base_model_indexes("alerts")
    op.drop_table("alerts")

    op.drop_index(
        "ix_alert_rule_notification_channels_notification_channel_id",
        table_name="alert_rule_notification_channels",
    )
    op.drop_index(
        "ix_alert_rule_notification_channels_alert_rule_id",
        table_name="alert_rule_notification_channels",
    )
    _drop_base_model_indexes("alert_rule_notification_channels")
    op.drop_table("alert_rule_notification_channels")

    op.drop_index("ix_alert_rules_is_active", table_name="alert_rules")
    op.drop_index("ix_alert_rules_trigger_type", table_name="alert_rules")
    op.drop_index("ix_alert_rules_organization_id", table_name="alert_rules")
    _drop_base_model_indexes("alert_rules")
    op.drop_table("alert_rules")

    op.drop_index(
        "ix_notification_channels_is_active", table_name="notification_channels"
    )
    op.drop_index(
        "ix_notification_channels_channel_type", table_name="notification_channels"
    )
    op.drop_index(
        "ix_notification_channels_organization_id",
        table_name="notification_channels",
    )
    _drop_base_model_indexes("notification_channels")
    op.drop_table("notification_channels")
