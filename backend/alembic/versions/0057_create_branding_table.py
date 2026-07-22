"""Create brandings table for per-organization visual branding.

Stores company name, logo/favicon URLs, color scheme (primary/secondary/
accent), and theme (light/dark) in a dedicated table with a unique FK to
organizations. Every organization gets at most one branding row.

When no branding row exists, the API returns a platform default — the
frontend never receives null branding data.

Revision ID: 0057_create_branding_table
Revises: 0056_add_policy_assignment_target
Create Date: 2026-07-22
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0057_create_branding_table"
down_revision = "0056_add_policy_assignment_target"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "brandings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("company_name", sa.String(255), nullable=True),
        sa.Column("logo_url", sa.String(1024), nullable=True),
        sa.Column("favicon_url", sa.String(1024), nullable=True),
        sa.Column("primary_color", sa.String(50), nullable=True),
        sa.Column("secondary_color", sa.String(50), nullable=True),
        sa.Column("accent_color", sa.String(50), nullable=True),
        sa.Column("theme", sa.String(20), nullable=True, server_default="light"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "is_deleted",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("updated_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default=sa.text("1")),
    )
    op.create_index(
        "ix_brandings_organization_id",
        "brandings",
        ["organization_id"],
        unique=True,
    )
    op.create_index(
        "ix_brandings_is_deleted", "brandings", ["is_deleted"]
    )
    op.create_index(
        "ix_brandings_deleted_at", "brandings", ["deleted_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_brandings_deleted_at", table_name="brandings")
    op.drop_index("ix_brandings_is_deleted", table_name="brandings")
    op.drop_index("ix_brandings_organization_id", table_name="brandings")
    op.drop_table("brandings")
