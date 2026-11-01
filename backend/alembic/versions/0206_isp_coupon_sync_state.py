"""BE-HARDEN: per-ISP watermark for the incremental coupon subscriber sync.

Additive: one new ISP-owned table. ``downgrade`` drops exactly it.

Revision ID: 0206_isp_coupon_sync_state
Revises: 0205_isp_pppoe_session_reuse
Create Date: 2026-11-01
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0206_isp_coupon_sync_state"
down_revision = "0205_isp_pppoe_session_reuse"
branch_labels = None
depends_on = None


def _uuid(name: str, *args: object, **kw: object) -> sa.Column:
    return sa.Column(name, postgresql.UUID(as_uuid=True), *args, **kw)


def _base() -> list[sa.Column]:
    return [
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
    ]


def _org(name: str) -> sa.Column:
    return _uuid(
        name, sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )


_BASE_INDEXED = ("created_at", "deleted_at", "is_deleted", "created_by", "updated_by")


def _base_indexes(table: str) -> None:
    for col in _BASE_INDEXED:
        op.create_index(f"ix_{table}_{col}", table, [col])


def upgrade() -> None:
    op.create_table(
        "isp_coupon_sync_state",
        *_base(),
        _org("isp_organization_id"),
        sa.Column("watermark_at", sa.DateTime(timezone=True), nullable=True),
        _uuid("watermark_voucher_id", nullable=True),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_applied", sa.Integer(), nullable=False, server_default="0"),
    )
    _base_indexes("isp_coupon_sync_state")
    op.create_index(
        "uq_isp_coupon_sync_state_isp",
        "isp_coupon_sync_state",
        ["isp_organization_id"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_table("isp_coupon_sync_state")
