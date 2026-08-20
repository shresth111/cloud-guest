"""Wave 1 Step 11: ``managed_router_resources``.

Tracks per-resource managed state for planner apply/rollback (P13/P21).

Revision ID: 0094_create_managed_router_resources_table
Revises: 0093_configuration_plans_and_verification_runs
Create Date: 2026-08-20
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0094_create_managed_router_resources_table"
down_revision = "0093_configuration_plans_and_verification_runs"
branch_labels = None
depends_on = None


def _base_model_columns() -> list[sa.Column]:
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
        "managed_router_resources",
        *_base_model_columns(),
        sa.Column(
            "router_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("routers.id", ondelete="CASCADE"),
            nullable=False,
        ),
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
            "plan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("configuration_plans.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("resource_kind", sa.String(length=40), nullable=False),
        sa.Column("routeros_path", sa.String(length=120), nullable=False),
        sa.Column("comment_tag", sa.String(length=150), nullable=False),
        sa.Column("desired_state_hash", sa.String(length=64), nullable=True),
        sa.Column("op", sa.String(length=10), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=True),
    )
    _create_base_model_indexes("managed_router_resources")
    op.create_index(
        "ix_managed_router_resources_router_id",
        "managed_router_resources",
        ["router_id"],
    )
    op.create_index(
        "ix_managed_router_resources_organization_id",
        "managed_router_resources",
        ["organization_id"],
    )
    op.create_index(
        "ix_managed_router_resources_comment_tag",
        "managed_router_resources",
        ["comment_tag"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_managed_router_resources_comment_tag",
        table_name="managed_router_resources",
    )
    op.drop_index(
        "ix_managed_router_resources_organization_id",
        table_name="managed_router_resources",
    )
    op.drop_index(
        "ix_managed_router_resources_router_id",
        table_name="managed_router_resources",
    )
    _drop_base_model_indexes("managed_router_resources")
    op.drop_table("managed_router_resources")
