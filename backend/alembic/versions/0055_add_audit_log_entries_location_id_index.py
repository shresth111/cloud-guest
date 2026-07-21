"""Add a missing index on ``audit_log_entries.location_id``.

Enterprise SaaS Phase E: ``AuditLogEntry.location_id`` has existed since
this table's own creation (a nullable FK, per that model's own
docstring -- "Column names are kept generic... so other domains could
plausibly log into this same table later") but was never indexed like
its sibling ``organization_id``/``actor_user_id``/``action``/
``entity_type``/``entity_id`` columns. ``AuditService.search`` gains a
``location_id`` filter in this same phase, so this index is added ahead
of that filter seeing real query traffic.

Revision ID: 0055_add_audit_log_entries_location_id_index
Revises: 0054_create_network_device_tables
Create Date: 2026-07-21
"""

from alembic import op

# revision identifiers, used by Alembic.
revision = "0055_add_audit_log_entries_location_id_index"
down_revision = "0054_create_network_device_tables"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_audit_log_entries_location_id",
        "audit_log_entries",
        ["location_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_audit_log_entries_location_id", table_name="audit_log_entries"
    )
