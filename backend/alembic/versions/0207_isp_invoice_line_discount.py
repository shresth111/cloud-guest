"""DISCOUNT-WIRE: a JAZE-5 discount code applied to a subscriber invoice line.

Two nullable-safe columns on the ISP-owned ``isp_invoice_lines``:
``discount_paise`` (pre-tax amount taken off the line; ``taxable_paise`` is
already net of it; default 0 = no discount, so every existing row reads as
before) and ``discount_label`` ("Discount SAVE10 (10% off)"). No backfill.

Revision ID: 0207_isp_invoice_line_discount
Revises: 0206_isp_coupon_sync_state
Create Date: 2026-11-01
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0207_isp_invoice_line_discount"
down_revision = "0206_isp_coupon_sync_state"
branch_labels = None
depends_on = None

_T = "isp_invoice_lines"


def upgrade() -> None:
    op.add_column(
        _T,
        sa.Column(
            "discount_paise", sa.BigInteger(), nullable=False, server_default="0"
        ),
    )
    op.add_column(_T, sa.Column("discount_label", sa.String(120), nullable=True))


def downgrade() -> None:
    op.drop_column(_T, "discount_label")
    op.drop_column(_T, "discount_paise")
