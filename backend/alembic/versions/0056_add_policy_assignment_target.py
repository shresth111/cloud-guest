"""Enterprise SaaS Phase F: add a WHO-targeting axis to ``policy_assignments``.

Adds ``target_type`` (default ``'none'``, matching
``constants.PolicyAssignmentTargetType.NONE``) and nullable ``target_id``
to ``policy_assignments`` -- a second, orthogonal axis alongside the
existing ``scope_type``/``scope_id`` WHERE axis. Every existing row gets
``target_type='none'``/``target_id=NULL`` via the column's server
default, which is semantically identical to "applies to everyone within
the WHERE scope" -- this migration changes no existing row's resolved
behavior.

Revision ID: 0056_add_policy_assignment_target
Revises: 0055_add_audit_log_entries_location_id_index
Create Date: 2026-07-22
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0056_add_policy_assignment_target"
down_revision = "0055_add_audit_log_entries_location_id_index"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "policy_assignments",
        sa.Column(
            "target_type",
            sa.String(20),
            nullable=False,
            server_default="none",
        ),
    )
    op.add_column(
        "policy_assignments",
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_index(
        "ix_policy_assignments_target_type", "policy_assignments", ["target_type"]
    )
    op.create_index(
        "ix_policy_assignments_target_id", "policy_assignments", ["target_id"]
    )


def downgrade() -> None:
    op.drop_index(
        "ix_policy_assignments_target_id", table_name="policy_assignments"
    )
    op.drop_index(
        "ix_policy_assignments_target_type", table_name="policy_assignments"
    )
    op.drop_column("policy_assignments", "target_id")
    op.drop_column("policy_assignments", "target_type")
