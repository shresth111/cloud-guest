"""REFERRAL-1: referral settings and referrals.

Additive: two new ISP-owned tables. ``downgrade`` drops exactly these.

Revision ID: 0204_isp_referrals
Revises: 0203_isp_queued_renewals
Create Date: 2026-11-01
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0204_isp_referrals"
down_revision = "0203_isp_queued_renewals"
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


def _sub(name: str) -> sa.Column:
    return _uuid(
        name, sa.ForeignKey("isp_subscribers.id", ondelete="CASCADE"), nullable=False
    )


def upgrade() -> None:
    op.create_table(
        "isp_referral_settings",
        *_base(),
        _org("isp_organization_id"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("reward_paise", sa.BigInteger(), nullable=False),
        sa.Column("max_rewards_per_year", sa.Integer(), nullable=False),
        sa.Column("window_days", sa.Integer(), nullable=False),
        sa.Column("min_first_invoice_paise", sa.BigInteger(), nullable=False),
    )
    _base_indexes("isp_referral_settings")
    op.create_index(
        "uq_isp_referral_settings_isp",
        "isp_referral_settings",
        ["isp_organization_id"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )

    t = "isp_referrals"
    op.create_table(
        t,
        *_base(),
        _org("isp_organization_id"),
        _sub("referrer_subscriber_id"),
        _sub("referred_subscriber_id"),
        _org("referrer_customer_id"),
        _org("referred_customer_id"),
        sa.Column("status", sa.String(10), nullable=False),
        sa.Column("reward_paise", sa.BigInteger(), nullable=True),
        _uuid("qualifying_invoice_id", sa.ForeignKey("isp_invoices.id"), nullable=True),
        sa.Column("earned_at", sa.DateTime(timezone=True), nullable=True),
        _uuid("applied_invoice_id", sa.ForeignKey("isp_invoices.id"), nullable=True),
        _uuid("credit_note_id", sa.ForeignKey("isp_invoices.id"), nullable=True),
        sa.Column("applied_paise", sa.BigInteger(), nullable=True),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reason", sa.String(255), nullable=True),
        sa.Column("note", sa.String(500), nullable=True),
        sa.Column(
            "history",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )
    _base_indexes(t)
    op.create_index(
        "uq_isp_referrals_referred",
        t,
        ["referred_subscriber_id"],
        unique=True,
        postgresql_where=sa.text(
            "status IN ('pending', 'earned', 'applied') AND deleted_at IS NULL"
        ),
    )
    op.create_index("ix_isp_referrals_isp_status", t, ["isp_organization_id", "status"])
    op.create_index("ix_isp_referrals_referrer", t, ["referrer_subscriber_id"])


def downgrade() -> None:
    op.drop_table("isp_referrals")
    op.drop_table("isp_referral_settings")
