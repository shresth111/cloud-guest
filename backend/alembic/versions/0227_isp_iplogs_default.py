"""DEFAULT-LOGS: the ISP's IP-logs choice per partner router.

Additive: one new ISP-owned side table, ``isp_router_iplogs_defaults`` (one
row per router, written only by the partner console while
``ISP_IPLOGS_SELFSERVE_ENABLED`` is on). No existing table is changed.
``downgrade`` drops exactly this table.

Revision ID: 0227_isp_iplogs_default
Revises: 0226_isp_coupon_batch_zone
Create Date: 2026-11-11
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0227_isp_iplogs_default"
down_revision = "0226_isp_coupon_batch_zone"
branch_labels = None
depends_on = None

_T = "isp_router_iplogs_defaults"
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
            "router_id",
            sa.ForeignKey("routers.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        _uuid("isp_organization_id", sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("wanted", sa.Boolean(), nullable=False),
        sa.Column("source", sa.String(16), nullable=False),
    )
    for col in _BASE_INDEXED:
        op.create_index(f"ix_{_T}_{col}", _T, [col])


def downgrade() -> None:
    op.drop_table(_T)
