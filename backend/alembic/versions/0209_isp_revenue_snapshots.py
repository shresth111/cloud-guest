"""SMALL-4: daily revenue snapshots (MRR history + DSO).

Additive: one new ISP-owned table. ``downgrade`` drops exactly it.

Revision ID: 0209_isp_revenue_snapshots
Revises: 0208_isp_winback_actions
Create Date: 2026-11-01
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0209_isp_revenue_snapshots"
down_revision = "0208_isp_winback_actions"
branch_labels = None
depends_on = None

T = "isp_revenue_snapshots"


def _uuid(name: str, *args: object, **kw: object) -> sa.Column:
    return sa.Column(name, postgresql.UUID(as_uuid=True), *args, **kw)


def upgrade() -> None:
    op.create_table(
        T,
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
        sa.Column("snapshot_date", sa.Date(), nullable=False),
        sa.Column("mrr_paise", sa.BigInteger(), nullable=False),
        sa.Column("arpu_paise", sa.BigInteger(), nullable=True),
        sa.Column("active", sa.Integer(), nullable=False),
        sa.Column("pending", sa.Integer(), nullable=False),
        sa.Column("expired", sa.Integer(), nullable=False),
        sa.Column("churned", sa.Integer(), nullable=False),
        sa.Column("unpriced", sa.Integer(), nullable=False),
        sa.Column("billed_month_paise", sa.BigInteger(), nullable=False),
        sa.Column("collected_month_paise", sa.BigInteger(), nullable=False),
        sa.Column("dues_paise", sa.BigInteger(), nullable=False),
        sa.Column("sales_90d_paise", sa.BigInteger(), nullable=False),
        sa.Column("dso_days", sa.Numeric(8, 1), nullable=True),
    )
    for col in ("created_at", "deleted_at", "is_deleted", "created_by", "updated_by"):
        op.create_index(f"ix_{T}_{col}", T, [col])
    op.create_index(
        "uq_isp_revenue_snapshots_isp_date",
        T,
        ["isp_organization_id", "snapshot_date"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_table(T)
