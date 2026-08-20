"""Wave 1 Step 6: ``configuration_plans`` + ``verification_runs``.

Two new tables in one revision (cross-FK: verification_runs.plan_id →
configuration_plans). Additive only — no changes to live venue tables.

Revision ID: 0093_configuration_plans_and_verification_runs
Revises: 0092_isp_links_physical_routing_split
Create Date: 2026-08-20
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0093_configuration_plans_and_verification_runs"
down_revision = "0092_isp_links_physical_routing_split"
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
        "configuration_plans",
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
            "snapshot_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("router_snapshots.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.String(length=20),
            nullable=False,
            server_default="draft",
        ),
        sa.Column("engine_version", sa.String(length=20), nullable=False),
        sa.Column(
            "requested_config",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "actions",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "conflicts",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "approved_by_user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "rendered_version_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("config_versions.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "pre_apply_backup_version_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("config_versions.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
    )
    _create_base_model_indexes("configuration_plans")
    op.create_index(
        "ix_configuration_plans_router_id", "configuration_plans", ["router_id"]
    )
    op.create_index(
        "ix_configuration_plans_organization_id",
        "configuration_plans",
        ["organization_id"],
    )
    op.create_index(
        "ix_configuration_plans_snapshot_id", "configuration_plans", ["snapshot_id"]
    )

    op.create_table(
        "verification_runs",
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
        sa.Column("scope", sa.String(length=20), nullable=False),
        sa.Column(
            "run_group_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "plan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("configuration_plans.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "isp_link_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("isp_links.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("overall", sa.String(length=20), nullable=False),
        sa.Column(
            "checks",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    _create_base_model_indexes("verification_runs")
    op.create_index(
        "ix_verification_runs_router_id", "verification_runs", ["router_id"]
    )
    op.create_index(
        "ix_verification_runs_organization_id",
        "verification_runs",
        ["organization_id"],
    )
    op.create_index(
        "ix_verification_runs_run_group_id", "verification_runs", ["run_group_id"]
    )
    op.create_index(
        "ix_verification_runs_isp_link_id", "verification_runs", ["isp_link_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_verification_runs_isp_link_id", table_name="verification_runs")
    op.drop_index("ix_verification_runs_run_group_id", table_name="verification_runs")
    op.drop_index(
        "ix_verification_runs_organization_id", table_name="verification_runs"
    )
    op.drop_index("ix_verification_runs_router_id", table_name="verification_runs")
    _drop_base_model_indexes("verification_runs")
    op.drop_table("verification_runs")

    op.drop_index(
        "ix_configuration_plans_snapshot_id", table_name="configuration_plans"
    )
    op.drop_index(
        "ix_configuration_plans_organization_id", table_name="configuration_plans"
    )
    op.drop_index("ix_configuration_plans_router_id", table_name="configuration_plans")
    _drop_base_model_indexes("configuration_plans")
    op.drop_table("configuration_plans")
