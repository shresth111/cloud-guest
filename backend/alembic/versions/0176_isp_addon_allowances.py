"""ISP ADDENDUM_04 §2: per-ISP add-on allowance (Master-set).

Additive: creates ``isp_addon_allowances`` only. No existing table is altered
and no row is written; with no rows every ISP gets the policy default
(``ISP_PARTNER_ADDON_DEFAULT_ALLOWANCE=none``). ``downgrade`` drops the table.

Revision ID: 0176_isp_addon_allowances
Revises: 0175_isp_subscriber_invoices
Create Date: 2026-10-23
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0176_isp_addon_allowances"
down_revision = "0175_isp_subscriber_invoices"
branch_labels = None
depends_on = None

_TABLE = "isp_addon_allowances"
_BASE_INDEXED = ("created_at", "deleted_at", "is_deleted", "created_by", "updated_by")


def _uuid(name: str, *args: object, **kw: object) -> sa.Column:
    return sa.Column(name, postgresql.UUID(as_uuid=True), *args, **kw)


def upgrade() -> None:
    op.create_table(
        _TABLE,
        _uuid("id", primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "is_deleted", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
        _uuid("created_by", nullable=True),
        _uuid("updated_by", nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        _uuid(
            "isp_organization_id",
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("feature_key", sa.String(64), nullable=False),
        sa.Column(
            "enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
        sa.Column("max_customers", sa.Integer(), nullable=True),
        sa.CheckConstraint(
            "max_customers IS NULL OR max_customers >= 0",
            name="ck_isp_addon_allowances_max_customers",
        ),
    )
    for column in _BASE_INDEXED:
        op.create_index(f"ix_{_TABLE}_{column}", _TABLE, [column])
    op.create_index(
        "uq_isp_addon_allowances_isp_key",
        _TABLE,
        ["isp_organization_id", "feature_key"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )


def downgrade() -> None:
    op.drop_table(_TABLE)
