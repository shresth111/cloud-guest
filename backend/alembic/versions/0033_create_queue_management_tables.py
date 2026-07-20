"""Queue Management Engine: ``queue_profiles``, ``queue_schedules``,
``queue_templates``, ``queue_assignments``.

New domain (``app.domains.queue_management``), the vendor-agnostic
bandwidth/QoS orchestrator composing ``app.domains.router``/``policy`` (see
``service.py``'s own module docstring). Four new tables -- deliberately not
the full list of names the module brief used (``QueueHistory``/
``QueueAudit`` are a read-model and a reuse of RBAC's existing
``audit_log_entries`` table, not separate storage -- see ``models.py``'s
own module docstring for the full write-up):

* ``queue_profiles`` -- a reusable, named bandwidth/QoS rate definition.
  Created first: ``queue_templates``/``queue_assignments`` both FK to it.
* ``queue_schedules`` -- a reusable, named time-window definition (Office
  Hours/Night Mode/Weekend/Holiday/Custom). Created second, independent of
  ``queue_profiles``: ``queue_templates``/``queue_assignments`` both FK to
  it too.
* ``queue_templates`` -- a reusable, named site-persona bundle composing an
  existing ``queue_profiles``/``queue_schedules`` row.
* ``queue_assignments`` -- attaches a profile to a polymorphic target
  (organization/location/router/guest team/guest/voucher/device/session --
  see ``constants.QueueTargetType``). Self-referencing
  ``superseded_by_assignment_id`` (a "Move Queue" operation creates a
  **new** row, never mutates the old one -- mirrors ``config_versions``'/
  ``provision_jobs``' own "new row, not mutate" convention).

No circular/deferred foreign keys are needed -- every FK here (including
the self-referencing column) is one-directional and declared inline at
table-creation time, mirroring migration ``0032``'s identical note.

No RBAC schema change beyond extending an *existing* seeded module's own
action tuple -- this feature's only edit to ``app.domains.rbac`` is
extending ``MODULE_ACTIONS[PermissionModule.BANDWIDTH]`` (already seeded,
ahead of any real domain, specifically for this concern) plus additive
``AuditAction`` enum values (``enums.py``/``seed.py``), no migration needed
(``permission_groups``/``permissions``/``permission_scopes``/
``role_permissions`` rows are all seeded idempotently at application/CLI
startup by ``seed_rbac``, never by a migration, per this codebase's own
established convention -- see e.g. migration ``0029``'s identical note).

Revision ID: 0033_create_queue_management_tables
Revises: 0032_create_provisioning_engine_tables
Create Date: 2026-07-20
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0033_create_queue_management_tables"
down_revision = "0032_create_provisioning_engine_tables"
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
    # -- queue_profiles -----------------------------------------------------------
    op.create_table(
        "queue_profiles",
        *_base_model_columns(),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("download_rate_kbps", sa.Integer(), nullable=False),
        sa.Column("upload_rate_kbps", sa.Integer(), nullable=False),
        sa.Column("burst_download_kbps", sa.Integer(), nullable=True),
        sa.Column("burst_upload_kbps", sa.Integer(), nullable=True),
        sa.Column("burst_threshold_kbps", sa.Integer(), nullable=True),
        sa.Column("burst_time_seconds", sa.Integer(), nullable=True),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="8"),
        sa.Column("queue_type", sa.String(20), nullable=False, server_default="simple"),
        sa.Column(
            "is_system_profile",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    _create_base_model_indexes("queue_profiles")
    op.create_index(
        "ix_queue_profiles_organization_id", "queue_profiles", ["organization_id"]
    )
    op.create_index(
        "ix_queue_profiles_is_system_profile", "queue_profiles", ["is_system_profile"]
    )
    op.create_index("ix_queue_profiles_is_active", "queue_profiles", ["is_active"])
    op.create_index("ix_queue_profiles_name", "queue_profiles", ["name"])

    # -- queue_schedules ------------------------------------------------------------
    op.create_table(
        "queue_schedules",
        *_base_model_columns(),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("schedule_type", sa.String(20), nullable=False),
        sa.Column(
            "days_of_week",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("start_time", sa.String(5), nullable=True),
        sa.Column("end_time", sa.String(5), nullable=True),
        sa.Column(
            "specific_dates",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("timezone", sa.String(50), nullable=False, server_default="UTC"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    _create_base_model_indexes("queue_schedules")
    op.create_index(
        "ix_queue_schedules_organization_id", "queue_schedules", ["organization_id"]
    )
    op.create_index(
        "ix_queue_schedules_schedule_type", "queue_schedules", ["schedule_type"]
    )
    op.create_index("ix_queue_schedules_is_active", "queue_schedules", ["is_active"])

    # -- queue_templates --------------------------------------------------------------
    op.create_table(
        "queue_templates",
        *_base_model_columns(),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("persona", sa.String(20), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "queue_profile_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("queue_profiles.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "default_queue_schedule_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("queue_schedules.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    _create_base_model_indexes("queue_templates")
    op.create_index(
        "ix_queue_templates_organization_id", "queue_templates", ["organization_id"]
    )
    op.create_index("ix_queue_templates_persona", "queue_templates", ["persona"])
    op.create_index("ix_queue_templates_is_active", "queue_templates", ["is_active"])

    # -- queue_assignments ----------------------------------------------------
    op.create_table(
        "queue_assignments",
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
            nullable=True,
        ),
        sa.Column(
            "router_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("routers.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("target_type", sa.String(20), nullable=False),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("device_target", sa.String(64), nullable=True),
        sa.Column("device_queue_id", sa.String(32), nullable=True),
        sa.Column(
            "queue_profile_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("queue_profiles.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "queue_schedule_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("queue_schedules.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("priority_override", sa.Integer(), nullable=True),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column(
            "superseded_by_assignment_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("queue_assignments.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    _create_base_model_indexes("queue_assignments")
    op.create_index(
        "ix_queue_assignments_organization_id",
        "queue_assignments",
        ["organization_id"],
    )
    op.create_index(
        "ix_queue_assignments_location_id", "queue_assignments", ["location_id"]
    )
    op.create_index(
        "ix_queue_assignments_router_id", "queue_assignments", ["router_id"]
    )
    op.create_index(
        "ix_queue_assignments_target_type", "queue_assignments", ["target_type"]
    )
    op.create_index(
        "ix_queue_assignments_target_id", "queue_assignments", ["target_id"]
    )
    op.create_index("ix_queue_assignments_status", "queue_assignments", ["status"])
    op.create_index(
        "ix_queue_assignments_superseded_by_assignment_id",
        "queue_assignments",
        ["superseded_by_assignment_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_queue_assignments_superseded_by_assignment_id",
        table_name="queue_assignments",
    )
    op.drop_index("ix_queue_assignments_status", table_name="queue_assignments")
    op.drop_index("ix_queue_assignments_target_id", table_name="queue_assignments")
    op.drop_index("ix_queue_assignments_target_type", table_name="queue_assignments")
    op.drop_index("ix_queue_assignments_router_id", table_name="queue_assignments")
    op.drop_index("ix_queue_assignments_location_id", table_name="queue_assignments")
    op.drop_index(
        "ix_queue_assignments_organization_id", table_name="queue_assignments"
    )
    _drop_base_model_indexes("queue_assignments")
    op.drop_table("queue_assignments")

    op.drop_index("ix_queue_templates_is_active", table_name="queue_templates")
    op.drop_index("ix_queue_templates_persona", table_name="queue_templates")
    op.drop_index("ix_queue_templates_organization_id", table_name="queue_templates")
    _drop_base_model_indexes("queue_templates")
    op.drop_table("queue_templates")

    op.drop_index("ix_queue_schedules_is_active", table_name="queue_schedules")
    op.drop_index("ix_queue_schedules_schedule_type", table_name="queue_schedules")
    op.drop_index("ix_queue_schedules_organization_id", table_name="queue_schedules")
    _drop_base_model_indexes("queue_schedules")
    op.drop_table("queue_schedules")

    op.drop_index("ix_queue_profiles_name", table_name="queue_profiles")
    op.drop_index("ix_queue_profiles_is_active", table_name="queue_profiles")
    op.drop_index("ix_queue_profiles_is_system_profile", table_name="queue_profiles")
    op.drop_index("ix_queue_profiles_organization_id", table_name="queue_profiles")
    _drop_base_model_indexes("queue_profiles")
    op.drop_table("queue_profiles")
