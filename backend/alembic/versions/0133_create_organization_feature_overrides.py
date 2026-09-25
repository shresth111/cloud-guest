"""Per-organization feature overrides (Guest Marketing add-on lock/unlock).

``organization_feature_overrides`` lets the Master console lock or unlock a
paid add-on for one organization without cloning a plan. Effective
entitlement = the live override row when one exists, the plan's value
otherwise (merged in ``LicenseService.get_entitlement_snapshot``).

Additive only: one new table, no backfill. No plan is changed, so every
organization starts with ``guest_marketing`` locked.

Numbered 0133 because open PRs #307/#308 already claim 0131/0132. If they
merge first, re-point ``down_revision`` at their head before merging this.

Revision ID: 0133_create_organization_feature_overrides
Revises: 0130_add_device_push_columns_to_firewall_rules
Create Date: 2026-09-25
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0133_create_organization_feature_overrides"
down_revision = "0130_add_device_push_columns_to_firewall_rules"
branch_labels = None
depends_on = None


# House convention: base-model helpers are duplicated into each migration so
# it stays a frozen snapshot (see 0122's note).
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


TABLE = "organization_feature_overrides"


def upgrade() -> None:
    op.create_table(
        TABLE,
        *_base_model_columns(),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("feature_key", sa.String(length=64), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), nullable=False),
        sa.Column("reason", sa.String(length=500), nullable=True),
        sa.Column("set_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_index(
        "uq_org_feature_overrides_org_key_live",
        "organization_feature_overrides",
        ["organization_id", "feature_key"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )
    op.create_index(
        "ix_org_feature_overrides_organization_id",
        "organization_feature_overrides",
        ["organization_id"],
    )
    _create_base_model_indexes(TABLE)


def downgrade() -> None:
    _drop_base_model_indexes(TABLE)
    op.drop_index(
        "ix_org_feature_overrides_organization_id",
        table_name="organization_feature_overrides",
    )
    op.drop_index(
        "uq_org_feature_overrides_org_key_live",
        table_name="organization_feature_overrides",
    )
    op.drop_table("organization_feature_overrides")
