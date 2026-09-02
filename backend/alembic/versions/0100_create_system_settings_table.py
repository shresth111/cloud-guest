"""Platform-wide settings store: ``system_settings``.

One new table, additive only. Nothing existing changes -- no column is
added to any other table and no data is backfilled. This is the table the
RBAC ``system_settings.*`` GLOBAL permission
(``app.domains.rbac.seed``) was reserved for but never had behind it.

## Shape

A generic key/value store: a unique ``key`` (drawn from the closed
``app.domains.system_settings.constants.SystemSettingKey`` set) and a JSONB
``value``. Zero-or-one row per key; a key never written simply doesn't
exist and reads as its schema default. See
``app.domains.system_settings.models``'s module docstring for why this is a
k/v table and not a single wide singleton row.

``uq_system_settings_key`` (unique on ``key``) is what makes the upsert
safe: a second writer for the same key collides here rather than inserting
a duplicate row the read map would then pick between arbitrarily.

Revision ID: 0100_create_system_settings_table
Revises: 0099_add_banner_coupon_fields_to_campaign_assets
Create Date: 2026-08-30
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0100_create_system_settings_table"
down_revision = "0099_add_banner_coupon_fields_to_campaign_assets"
branch_labels = None
depends_on = None

TABLE = "system_settings"


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
        TABLE,
        *_base_model_columns(),
        sa.Column("key", sa.String(length=100), nullable=False),
        sa.Column("value", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.UniqueConstraint("key", name="uq_system_settings_key"),
    )
    _create_base_model_indexes(TABLE)
    op.create_index("ix_system_settings_key", TABLE, ["key"])


def downgrade() -> None:
    op.drop_index("ix_system_settings_key", table_name=TABLE)
    _drop_base_model_indexes(TABLE)
    op.drop_table(TABLE)
