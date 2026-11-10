"""PROV-FIX item 10: the zone a coupon batch was created in.

Additive: one new ISP-owned side table, ``isp_coupon_batch_zones`` (one row
per batch, only for batches created while franchisee logins are on). The
``isp_coupon_batches`` table is not changed; a batch without a row keeps
today's visibility. ``downgrade`` drops exactly this table.

Revision ID: 0226_isp_coupon_batch_zone
Revises: 0225_isp_workflow
Create Date: 2026-11-10
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0226_isp_coupon_batch_zone"
down_revision = "0225_isp_workflow"
branch_labels = None
depends_on = None

_T = "isp_coupon_batch_zones"
_BASE_INDEXED = ("created_at", "deleted_at", "is_deleted", "created_by", "updated_by")


def _uuid(name: str, *args: object, **kw: object) -> sa.Column:
    return sa.Column(name, postgresql.UUID(as_uuid=True), *args, **kw)


def upgrade() -> None:
    op.create_table(
        _T,
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
            "coupon_batch_id",
            sa.ForeignKey("isp_coupon_batches.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        _uuid("isp_organization_id", sa.ForeignKey("organizations.id"), nullable=False),
        _uuid("zone_id", sa.ForeignKey("isp_zones.id"), nullable=False),
    )
    for col in _BASE_INDEXED:
        op.create_index(f"ix_{_T}_{col}", _T, [col])
    op.create_index(
        "ix_isp_coupon_batch_zones_isp_zone", _T, ["isp_organization_id", "zone_id"]
    )


def downgrade() -> None:
    op.drop_table(_T)
