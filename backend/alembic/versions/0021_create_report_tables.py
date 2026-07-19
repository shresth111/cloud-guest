"""Create Report Engine tables (BE-012 Part 5: Report Engine + Export
Engine).

Mirrors ``0018_create_analytics_tables``'s conventions: the ``BaseModel``
column set (id, created_at, updated_at, soft-delete, audit, version) plus
its own base-model indexes, using the same ``_base_model_columns``/
``_create_base_model_indexes`` helpers (duplicated here, not imported --
Alembic migrations are meant to be self-contained snapshots rather than
depending on other migration modules).

Two new tables:

* ``report_templates`` -- a reusable, persisted report definition
  (``report_type``/``config``). ``organization_id`` is nullable, ``SET
  NULL`` FK (``NULL`` means a platform-wide system template) -- mirrors
  ``analytics_snapshots``' own optional-scope convention.
* ``scheduled_reports`` -- a recurring render of one ``report_templates``
  row, emailed on ``frequency``'s cadence. ``template_id``/``organization_id``
  are both required, ``CASCADE`` FKs (a schedule has no reason to survive
  its parent template or organization being deleted). See
  ``app.domains.analytics.models.ScheduledReport``'s own docstring for the
  full column reference and why ``organization_id`` here is *not* nullable
  the way ``report_templates.organization_id`` is.

No RBAC FK follow-up migration is needed -- this domain reuses RBAC's
already-seeded ``reports.*`` permission keys (already present since Part 1,
see ``0018_create_analytics_tables``'s own note on this), and no new
``app.domains.rbac.enums.PermissionModule``/``AuditAction`` member is added
(this domain's own local ``audit_log_entries.action`` string-constant
convention, see ``app.domains.analytics.constants``'s Part 5 section).

Revision ID: 0021_create_report_tables
Revises: 0020_add_accept_language_to_guest_sessions
Create Date: 2026-07-19
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0021_create_report_tables"
down_revision = "0020_add_accept_language_to_guest_sessions"
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
    # -- report_templates -----------------------------------------------------
    op.create_table(
        "report_templates",
        *_base_model_columns(),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.String(2000), nullable=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("report_type", sa.String(30), nullable=False),
        sa.Column(
            "config",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "is_active", sa.Boolean(), nullable=False, server_default=sa.true()
        ),
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_report_templates_organization_id_organizations",
            ondelete="SET NULL",
        ),
    )
    _create_base_model_indexes("report_templates")
    op.create_index(
        "ix_report_templates_organization_id",
        "report_templates",
        ["organization_id"],
    )
    op.create_index(
        "ix_report_templates_report_type", "report_templates", ["report_type"]
    )
    op.create_index(
        "ix_report_templates_is_active", "report_templates", ["is_active"]
    )

    # -- scheduled_reports ----------------------------------------------------
    op.create_table(
        "scheduled_reports",
        *_base_model_columns(),
        sa.Column("template_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("frequency", sa.String(20), nullable=False),
        sa.Column(
            "recipient_emails",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("export_format", sa.String(10), nullable=False),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_run_status", sa.String(10), nullable=True),
        sa.Column(
            "is_active", sa.Boolean(), nullable=False, server_default=sa.true()
        ),
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["template_id"],
            ["report_templates.id"],
            name="fk_scheduled_reports_template_id_report_templates",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_scheduled_reports_organization_id_organizations",
            ondelete="CASCADE",
        ),
    )
    _create_base_model_indexes("scheduled_reports")
    op.create_index(
        "ix_scheduled_reports_template_id", "scheduled_reports", ["template_id"]
    )
    op.create_index(
        "ix_scheduled_reports_organization_id",
        "scheduled_reports",
        ["organization_id"],
    )
    # Primary query pattern for report_tasks.run_scheduled_reports's "which
    # schedules are due" sweep -- see app.domains.analytics.models
    # .ScheduledReport's own indexing-rationale docstring.
    op.create_index(
        "ix_scheduled_reports_is_active_next_run_at",
        "scheduled_reports",
        ["is_active", "next_run_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_scheduled_reports_is_active_next_run_at",
        table_name="scheduled_reports",
    )
    op.drop_index(
        "ix_scheduled_reports_organization_id", table_name="scheduled_reports"
    )
    op.drop_index("ix_scheduled_reports_template_id", table_name="scheduled_reports")
    _drop_base_model_indexes("scheduled_reports")
    op.drop_table("scheduled_reports")

    op.drop_index("ix_report_templates_is_active", table_name="report_templates")
    op.drop_index("ix_report_templates_report_type", table_name="report_templates")
    op.drop_index(
        "ix_report_templates_organization_id", table_name="report_templates"
    )
    _drop_base_model_indexes("report_templates")
    op.drop_table("report_templates")
