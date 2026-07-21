"""Notification domain: ``notification_templates``/``notification_deliveries``.

New domain (``app.domains.notification``) -- a generic, recipient-addressed
outbox for real email/SMS delivery (auth verification/reset, voucher batch
export, billing renewal/expiry reminders, analytics scheduled reports).
See ``service.py``'s own module docstring for the full outbox/dispatch
design, and its module docstring for why this is deliberately distinct
from ``app.domains.monitoring``'s existing ``notification_channels``/
``notification_logs`` tables (an ops-configured alert-routing channel, not
a recipient-addressed outbox).

Two new tables, additive only:

* ``notification_templates`` -- one row per ``(organization_id, event_type,
  channel)``; ``organization_id IS NULL`` means a platform-wide default,
  mirroring ``config_templates``'s identical nullable-FK convention.
* ``notification_deliveries`` -- the outbox row itself: ``PENDING`` ->
  ``SENT``/``RETRYING``/``FAILED``.

RBAC change: ``PermissionModule.NOTIFICATIONS`` (already seeded, scope
``LOCATION``) gains a ``CREATE`` action -- additive only, no migration
needed (``permission_groups``/``permissions``/``permission_scopes``/
``role_permissions`` rows are all seeded idempotently at application/CLI
startup by ``seed_rbac``, never by a migration, per this codebase's own
established convention -- see e.g. migration ``0048``'s identical note).

Revision ID: 0049_create_notification_tables
Revises: 0048_create_campaigns_tables
Create Date: 2026-07-21
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0049_create_notification_tables"
down_revision = "0048_create_campaigns_tables"
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
        "notification_templates",
        *_base_model_columns(),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("event_type", sa.String(50), nullable=False),
        sa.Column("channel", sa.String(20), nullable=False),
        sa.Column("subject_template", sa.Text(), nullable=True),
        sa.Column("body_template", sa.Text(), nullable=False),
        sa.Column(
            "is_active", sa.Boolean(), nullable=False, server_default=sa.true()
        ),
    )
    _create_base_model_indexes("notification_templates")
    op.create_index(
        "ix_notification_templates_organization_id",
        "notification_templates",
        ["organization_id"],
    )
    op.create_index(
        "ix_notification_templates_event_type",
        "notification_templates",
        ["event_type"],
    )
    op.create_index(
        "ix_notification_templates_channel", "notification_templates", ["channel"]
    )
    op.create_index(
        "ix_notification_templates_is_active",
        "notification_templates",
        ["is_active"],
    )

    op.create_table(
        "notification_deliveries",
        *_base_model_columns(),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "template_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("notification_templates.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("event_type", sa.String(50), nullable=False),
        sa.Column("channel", sa.String(20), nullable=False),
        sa.Column("recipient", sa.String(255), nullable=False),
        sa.Column("subject", sa.Text(), nullable=True),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column(
            "attempt_count", sa.Integer(), nullable=False, server_default="0"
        ),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("attachment_storage_key", sa.String(500), nullable=True),
        sa.Column("attachment_filename", sa.String(255), nullable=True),
        sa.Column("context", postgresql.JSONB(), nullable=True),
    )
    _create_base_model_indexes("notification_deliveries")
    op.create_index(
        "ix_notification_deliveries_organization_id",
        "notification_deliveries",
        ["organization_id"],
    )
    op.create_index(
        "ix_notification_deliveries_status", "notification_deliveries", ["status"]
    )
    op.create_index(
        "ix_notification_deliveries_event_type",
        "notification_deliveries",
        ["event_type"],
    )
    op.create_index(
        "ix_notification_deliveries_next_attempt_at",
        "notification_deliveries",
        ["next_attempt_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_notification_deliveries_next_attempt_at",
        table_name="notification_deliveries",
    )
    op.drop_index(
        "ix_notification_deliveries_event_type", table_name="notification_deliveries"
    )
    op.drop_index(
        "ix_notification_deliveries_status", table_name="notification_deliveries"
    )
    op.drop_index(
        "ix_notification_deliveries_organization_id",
        table_name="notification_deliveries",
    )
    _drop_base_model_indexes("notification_deliveries")
    op.drop_table("notification_deliveries")

    op.drop_index(
        "ix_notification_templates_is_active", table_name="notification_templates"
    )
    op.drop_index(
        "ix_notification_templates_channel", table_name="notification_templates"
    )
    op.drop_index(
        "ix_notification_templates_event_type", table_name="notification_templates"
    )
    op.drop_index(
        "ix_notification_templates_organization_id",
        table_name="notification_templates",
    )
    _drop_base_model_indexes("notification_templates")
    op.drop_table("notification_templates")
