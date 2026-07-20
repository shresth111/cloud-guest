"""Provisioning Engine: ``provision_templates``, ``provision_jobs``,
``provision_steps``, ``provision_logs``.

New domain (``app.domains.provisioning_engine``), the end-to-end automation
orchestrator composing ``app.domains.router``/``router_provisioning``/
``policy``/``guest`` (see ``service.py``'s own module docstring). Four new
tables -- deliberately not the full list of names the module brief used
(``ProvisionHistory``/``ProvisionTimeline``/``ProvisionQueue``/
``ProvisionRetry``/``ProvisionRollback`` are read-models or a new-row
composition pattern over these four, not separate storage -- see
``models.py``'s own module docstring for the full write-up):

* ``provision_templates`` -- a reusable, named provisioning "package" for a
  site type (Hotel/Apartment/Corporate/...), composing an existing
  ``router_provisioning.config_templates`` row and an optional
  ``policy.policies`` row. Created first: ``provision_jobs`` FKs to it.
* ``provision_jobs`` -- the top-level orchestration run for one router.
  Self-referencing ``retry_of_job_id``/``rollback_of_job_id`` (a retry/
  rollback is a **new** row, never a mutation of the original -- mirrors
  ``config_versions``'/``policy_versions``' own "new row, not mutate"
  convention) and two FKs into ``router_provisioning.config_versions``
  (``applied_config_version_id``/``rollback_target_version_id``).
* ``provision_steps`` -- one row per stage in a job's ordered sequence
  (Discover/Validate/Generate Config/Push Config/Verify Config/Health
  Check/Register Monitoring). FKs to ``provision_jobs``.
* ``provision_logs`` -- an append-only per-job (optionally per-step) log
  line, separate from RBAC's ``audit_log_entries`` for the same high-
  volume/non-human-attributable reason ``router_provisioning.router_events``
  already documents.

No circular/deferred foreign keys are needed here (unlike migration
``0029``'s ``policies``/``policy_versions`` mutual reference) --
``provision_jobs``' self-referencing columns and its FKs into
already-existing ``config_versions``/``provision_templates`` are all
one-directional, so every FK is declared inline at table-creation time.

No RBAC schema change -- this feature's only edit to ``app.domains.rbac`` is
additive ``PermissionModule.PROVISIONING_ENGINE``/``AuditAction`` enum
values (``enums.py``) plus their corresponding seed data (``seed.py``), no
migration needed (``permission_groups``/``permissions``/
``permission_scopes``/``role_permissions`` rows are all seeded idempotently
at application/CLI startup by ``seed_rbac``, never by a migration, per this
codebase's own established convention -- see e.g. migration ``0029``'s
identical note).

Revision ID: 0032_create_provisioning_engine_tables
Revises: 0031_add_vendor_to_router_and_template
Create Date: 2026-07-20
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0032_create_provisioning_engine_tables"
down_revision = "0031_add_vendor_to_router_and_template"
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
    # -- provision_templates ----------------------------------------------------
    op.create_table(
        "provision_templates",
        *_base_model_columns(),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("site_type", sa.String(20), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "config_template_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("config_templates.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "default_policy_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("policies.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "settings",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    _create_base_model_indexes("provision_templates")
    op.create_index(
        "ix_provision_templates_organization_id",
        "provision_templates",
        ["organization_id"],
    )
    op.create_index(
        "ix_provision_templates_site_type", "provision_templates", ["site_type"]
    )
    op.create_index(
        "ix_provision_templates_is_active", "provision_templates", ["is_active"]
    )

    # -- provision_jobs -----------------------------------------------------------
    op.create_table(
        "provision_jobs",
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
            sa.ForeignKey("routers.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "provision_template_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("provision_templates.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("current_step", sa.String(30), nullable=True),
        sa.Column("progress_percent", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "policy_snapshot",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("requested_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("retry_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("max_retries", sa.Integer(), nullable=False, server_default="3"),
        sa.Column(
            "retry_of_job_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("provision_jobs.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "is_rollback", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column(
            "rollback_of_job_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("provision_jobs.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "applied_config_version_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("config_versions.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "rollback_target_version_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("config_versions.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    _create_base_model_indexes("provision_jobs")
    op.create_index(
        "ix_provision_jobs_organization_id", "provision_jobs", ["organization_id"]
    )
    op.create_index("ix_provision_jobs_location_id", "provision_jobs", ["location_id"])
    op.create_index("ix_provision_jobs_router_id", "provision_jobs", ["router_id"])
    op.create_index("ix_provision_jobs_status", "provision_jobs", ["status"])
    op.create_index(
        "ix_provision_jobs_retry_of_job_id", "provision_jobs", ["retry_of_job_id"]
    )
    op.create_index(
        "ix_provision_jobs_rollback_of_job_id",
        "provision_jobs",
        ["rollback_of_job_id"],
    )

    # -- provision_steps ----------------------------------------------------------
    op.create_table(
        "provision_steps",
        *_base_model_columns(),
        sa.Column(
            "job_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("provision_jobs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("step_type", sa.String(30), nullable=False),
        sa.Column("sequence_number", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "output",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("error_message", sa.Text(), nullable=True),
    )
    _create_base_model_indexes("provision_steps")
    op.create_index("ix_provision_steps_job_id", "provision_steps", ["job_id"])
    op.create_index("ix_provision_steps_step_type", "provision_steps", ["step_type"])
    op.create_index("ix_provision_steps_status", "provision_steps", ["status"])

    # -- provision_logs -----------------------------------------------------------
    op.create_table(
        "provision_logs",
        *_base_model_columns(),
        sa.Column(
            "job_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("provision_jobs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "step_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("provision_steps.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("level", sa.String(10), nullable=False, server_default="info"),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("logged_at", sa.DateTime(timezone=True), nullable=False),
    )
    _create_base_model_indexes("provision_logs")
    op.create_index("ix_provision_logs_job_id", "provision_logs", ["job_id"])
    op.create_index("ix_provision_logs_step_id", "provision_logs", ["step_id"])
    op.create_index("ix_provision_logs_logged_at", "provision_logs", ["logged_at"])


def downgrade() -> None:
    op.drop_index("ix_provision_logs_logged_at", table_name="provision_logs")
    op.drop_index("ix_provision_logs_step_id", table_name="provision_logs")
    op.drop_index("ix_provision_logs_job_id", table_name="provision_logs")
    _drop_base_model_indexes("provision_logs")
    op.drop_table("provision_logs")

    op.drop_index("ix_provision_steps_status", table_name="provision_steps")
    op.drop_index("ix_provision_steps_step_type", table_name="provision_steps")
    op.drop_index("ix_provision_steps_job_id", table_name="provision_steps")
    _drop_base_model_indexes("provision_steps")
    op.drop_table("provision_steps")

    op.drop_index("ix_provision_jobs_rollback_of_job_id", table_name="provision_jobs")
    op.drop_index("ix_provision_jobs_retry_of_job_id", table_name="provision_jobs")
    op.drop_index("ix_provision_jobs_status", table_name="provision_jobs")
    op.drop_index("ix_provision_jobs_router_id", table_name="provision_jobs")
    op.drop_index("ix_provision_jobs_location_id", table_name="provision_jobs")
    op.drop_index("ix_provision_jobs_organization_id", table_name="provision_jobs")
    _drop_base_model_indexes("provision_jobs")
    op.drop_table("provision_jobs")

    op.drop_index("ix_provision_templates_is_active", table_name="provision_templates")
    op.drop_index("ix_provision_templates_site_type", table_name="provision_templates")
    op.drop_index(
        "ix_provision_templates_organization_id", table_name="provision_templates"
    )
    _drop_base_model_indexes("provision_templates")
    op.drop_table("provision_templates")
