"""Create Router Provisioning domain tables: config_templates,
config_variables, config_profiles, config_versions,
router_enrollment_requests, provisioning_jobs, router_health_snapshots,
router_events.

Mirrors ``0007_create_router_tables``'s conventions: each table gets the
``BaseModel`` column set (id, created_at, updated_at, soft-delete, audit,
version) plus its own base-model indexes, using the same
``_base_model_columns``/``_create_base_model_indexes`` helpers (duplicated
here, not imported, since Alembic migrations are meant to be self-contained
snapshots rather than depending on other migration modules).

Table creation order follows FK dependency order: ``config_templates``
(references ``organizations``, nullable) before ``config_profiles``
(references both ``routers`` and ``config_templates``) before
``config_versions`` (references ``routers``, ``config_profiles``, and
itself via ``rollback_of_version_id``). ``config_variables``,
``router_enrollment_requests``, ``provisioning_jobs``,
``router_health_snapshots``, and ``router_events`` each only reference
tables that already exist (``organizations``/``locations``/``routers``/
``users``), so their relative order doesn't matter beyond that.

This is Module 009 Part 1's only migration -- no RBAC FK follow-up migration
is needed this time (unlike Modules 005/006/008's own follow-ups): this
module adds entirely new tables that reference ``routers``/
``organizations``/``locations``, it does not retrofit a column onto any
existing RBAC table.

Revision ID: 0009_create_router_provisioning_tables
Revises: 0008_add_router_fk_to_rbac_tables
Create Date: 2026-07-18
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0009_create_router_provisioning_tables"
down_revision = "0008_add_router_fk_to_rbac_tables"
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
    # -- config_templates ------------------------------------------------------
    op.create_table(
        "config_templates",
        *_base_model_columns(),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "is_system_template",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column("applicable_router_model", sa.String(100), nullable=True),
        sa.Column("template_content", sa.Text(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_config_templates_organization_id_organizations",
            ondelete="CASCADE",
        ),
    )
    _create_base_model_indexes("config_templates")
    op.create_index(
        "ix_config_templates_organization_id", "config_templates", ["organization_id"]
    )
    op.create_index(
        "ix_config_templates_is_system_template",
        "config_templates",
        ["is_system_template"],
    )
    op.create_index(
        "ix_config_templates_applicable_router_model",
        "config_templates",
        ["applicable_router_model"],
    )
    op.create_index("ix_config_templates_is_active", "config_templates", ["is_active"])
    op.create_index("ix_config_templates_name", "config_templates", ["name"])

    # -- config_variables --------------------------------------------------------
    op.create_table(
        "config_variables",
        *_base_model_columns(),
        sa.Column(
            "scope_type",
            sa.String(20),
            nullable=False,
            server_default="organization",
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("location_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("router_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("key", sa.String(150), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("is_secret", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_config_variables_organization_id_organizations",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["location_id"],
            ["locations.id"],
            name="fk_config_variables_location_id_locations",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["router_id"],
            ["routers.id"],
            name="fk_config_variables_router_id_routers",
            ondelete="CASCADE",
        ),
    )
    _create_base_model_indexes("config_variables")
    op.create_index(
        "ix_config_variables_scope_type", "config_variables", ["scope_type"]
    )
    op.create_index(
        "ix_config_variables_organization_id", "config_variables", ["organization_id"]
    )
    op.create_index(
        "ix_config_variables_location_id", "config_variables", ["location_id"]
    )
    op.create_index("ix_config_variables_router_id", "config_variables", ["router_id"])
    op.create_index("ix_config_variables_key", "config_variables", ["key"])

    # -- config_profiles -----------------------------------------------------------
    op.create_table(
        "config_profiles",
        *_base_model_columns(),
        sa.Column("router_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("template_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("assigned_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["router_id"],
            ["routers.id"],
            name="fk_config_profiles_router_id_routers",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["template_id"],
            ["config_templates.id"],
            name="fk_config_profiles_template_id_config_templates",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("router_id", name="uq_config_profiles_router_id"),
    )
    _create_base_model_indexes("config_profiles")
    op.create_index("ix_config_profiles_router_id", "config_profiles", ["router_id"])
    op.create_index(
        "ix_config_profiles_template_id", "config_profiles", ["template_id"]
    )

    # -- config_versions -----------------------------------------------------------
    op.create_table(
        "config_versions",
        *_base_model_columns(),
        sa.Column("router_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("profile_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("version_number", sa.Integer(), nullable=False),
        sa.Column("rendered_content", sa.Text(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="draft"),
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "rollback_of_version_id", postgresql.UUID(as_uuid=True), nullable=True
        ),
        sa.Column("is_backup", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.ForeignKeyConstraint(
            ["router_id"],
            ["routers.id"],
            name="fk_config_versions_router_id_routers",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["profile_id"],
            ["config_profiles.id"],
            name="fk_config_versions_profile_id_config_profiles",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["rollback_of_version_id"],
            ["config_versions.id"],
            name="fk_config_versions_rollback_of_version_id_config_versions",
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint(
            "router_id",
            "version_number",
            name="uq_config_versions_router_id_version_number",
        ),
    )
    _create_base_model_indexes("config_versions")
    op.create_index("ix_config_versions_router_id", "config_versions", ["router_id"])
    op.create_index("ix_config_versions_status", "config_versions", ["status"])
    op.create_index(
        "ix_config_versions_rollback_of_version_id",
        "config_versions",
        ["rollback_of_version_id"],
    )
    op.create_index("ix_config_versions_is_backup", "config_versions", ["is_backup"])

    # -- router_enrollment_requests ------------------------------------------------
    op.create_table(
        "router_enrollment_requests",
        *_base_model_columns(),
        sa.Column("serial_number", sa.String(100), nullable=False),
        sa.Column("mac_address", sa.String(17), nullable=False),
        sa.Column("model", sa.String(100), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("reviewed_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rejection_reason", sa.Text(), nullable=True),
        sa.Column("approved_router_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["approved_router_id"],
            ["routers.id"],
            name="fk_router_enrollment_requests_approved_router_id_routers",
            ondelete="SET NULL",
        ),
    )
    _create_base_model_indexes("router_enrollment_requests")
    op.create_index(
        "ix_router_enrollment_requests_serial_number",
        "router_enrollment_requests",
        ["serial_number"],
    )
    op.create_index(
        "ix_router_enrollment_requests_mac_address",
        "router_enrollment_requests",
        ["mac_address"],
    )
    op.create_index(
        "ix_router_enrollment_requests_status",
        "router_enrollment_requests",
        ["status"],
    )

    # -- provisioning_jobs -----------------------------------------------------------
    op.create_table(
        "provisioning_jobs",
        *_base_model_columns(),
        sa.Column("router_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("job_type", sa.String(30), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="queued"),
        sa.Column(
            "payload",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("scheduled_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("requested_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["router_id"],
            ["routers.id"],
            name="fk_provisioning_jobs_router_id_routers",
            ondelete="CASCADE",
        ),
    )
    _create_base_model_indexes("provisioning_jobs")
    op.create_index(
        "ix_provisioning_jobs_router_id", "provisioning_jobs", ["router_id"]
    )
    op.create_index("ix_provisioning_jobs_job_type", "provisioning_jobs", ["job_type"])
    op.create_index("ix_provisioning_jobs_status", "provisioning_jobs", ["status"])
    op.create_index(
        "ix_provisioning_jobs_scheduled_at", "provisioning_jobs", ["scheduled_at"]
    )

    # -- router_health_snapshots -----------------------------------------------------
    op.create_table(
        "router_health_snapshots",
        *_base_model_columns(),
        sa.Column("router_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("health_status", sa.String(20), nullable=True),
        sa.Column("cpu_usage_percent", sa.Float(), nullable=True),
        sa.Column("memory_usage_percent", sa.Float(), nullable=True),
        sa.Column("uptime_seconds", sa.Integer(), nullable=True),
        sa.Column("connected_clients_count", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(
            ["router_id"],
            ["routers.id"],
            name="fk_router_health_snapshots_router_id_routers",
            ondelete="CASCADE",
        ),
    )
    _create_base_model_indexes("router_health_snapshots")
    op.create_index(
        "ix_router_health_snapshots_router_id",
        "router_health_snapshots",
        ["router_id"],
    )
    op.create_index(
        "ix_router_health_snapshots_recorded_at",
        "router_health_snapshots",
        ["recorded_at"],
    )

    # -- router_events -----------------------------------------------------------
    op.create_table(
        "router_events",
        *_base_model_columns(),
        sa.Column("router_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event_type", sa.String(30), nullable=False),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "metadata",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.ForeignKeyConstraint(
            ["router_id"],
            ["routers.id"],
            name="fk_router_events_router_id_routers",
            ondelete="CASCADE",
        ),
    )
    _create_base_model_indexes("router_events")
    op.create_index("ix_router_events_router_id", "router_events", ["router_id"])
    op.create_index("ix_router_events_event_type", "router_events", ["event_type"])
    op.create_index("ix_router_events_occurred_at", "router_events", ["occurred_at"])


def downgrade() -> None:
    op.drop_index("ix_router_events_occurred_at", table_name="router_events")
    op.drop_index("ix_router_events_event_type", table_name="router_events")
    op.drop_index("ix_router_events_router_id", table_name="router_events")
    _drop_base_model_indexes("router_events")
    op.drop_table("router_events")

    op.drop_index(
        "ix_router_health_snapshots_recorded_at",
        table_name="router_health_snapshots",
    )
    op.drop_index(
        "ix_router_health_snapshots_router_id", table_name="router_health_snapshots"
    )
    _drop_base_model_indexes("router_health_snapshots")
    op.drop_table("router_health_snapshots")

    op.drop_index("ix_provisioning_jobs_scheduled_at", table_name="provisioning_jobs")
    op.drop_index("ix_provisioning_jobs_status", table_name="provisioning_jobs")
    op.drop_index("ix_provisioning_jobs_job_type", table_name="provisioning_jobs")
    op.drop_index("ix_provisioning_jobs_router_id", table_name="provisioning_jobs")
    _drop_base_model_indexes("provisioning_jobs")
    op.drop_table("provisioning_jobs")

    op.drop_index(
        "ix_router_enrollment_requests_status",
        table_name="router_enrollment_requests",
    )
    op.drop_index(
        "ix_router_enrollment_requests_mac_address",
        table_name="router_enrollment_requests",
    )
    op.drop_index(
        "ix_router_enrollment_requests_serial_number",
        table_name="router_enrollment_requests",
    )
    _drop_base_model_indexes("router_enrollment_requests")
    op.drop_table("router_enrollment_requests")

    op.drop_index("ix_config_versions_is_backup", table_name="config_versions")
    op.drop_index(
        "ix_config_versions_rollback_of_version_id", table_name="config_versions"
    )
    op.drop_index("ix_config_versions_status", table_name="config_versions")
    op.drop_index("ix_config_versions_router_id", table_name="config_versions")
    _drop_base_model_indexes("config_versions")
    op.drop_table("config_versions")

    op.drop_index("ix_config_profiles_template_id", table_name="config_profiles")
    op.drop_index("ix_config_profiles_router_id", table_name="config_profiles")
    _drop_base_model_indexes("config_profiles")
    op.drop_table("config_profiles")

    op.drop_index("ix_config_variables_key", table_name="config_variables")
    op.drop_index("ix_config_variables_router_id", table_name="config_variables")
    op.drop_index("ix_config_variables_location_id", table_name="config_variables")
    op.drop_index("ix_config_variables_organization_id", table_name="config_variables")
    op.drop_index("ix_config_variables_scope_type", table_name="config_variables")
    _drop_base_model_indexes("config_variables")
    op.drop_table("config_variables")

    op.drop_index("ix_config_templates_name", table_name="config_templates")
    op.drop_index("ix_config_templates_is_active", table_name="config_templates")
    op.drop_index(
        "ix_config_templates_applicable_router_model", table_name="config_templates"
    )
    op.drop_index(
        "ix_config_templates_is_system_template", table_name="config_templates"
    )
    op.drop_index("ix_config_templates_organization_id", table_name="config_templates")
    _drop_base_model_indexes("config_templates")
    op.drop_table("config_templates")
