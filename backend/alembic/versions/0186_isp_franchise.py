"""FRANCHISE-2: zone share plans, renewal auto-debits, recurring zone
charges, settlements.

Additive: four new ISP-owned tables. JAZE-4's zone tables are not altered.
``downgrade`` drops exactly these four.

Revision ID: 0186_isp_franchise
Revises: 0185_isp_comms_hub
Create Date: 2026-11-01
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0186_isp_franchise"
down_revision = "0185_isp_comms_hub"
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


def _isp() -> sa.Column:
    return _uuid(
        "isp_organization_id",
        sa.ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )


_BASE_INDEXED = ("created_at", "deleted_at", "is_deleted", "created_by", "updated_by")


def _base_indexes(table: str) -> None:
    for col in _BASE_INDEXED:
        op.create_index(f"ix_{table}_{col}", table, [col])


def upgrade() -> None:
    op.create_table(
        "isp_zone_share_plans",
        *_base(),
        _isp(),
        _uuid(
            "zone_id", sa.ForeignKey("isp_zones.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("mode", sa.String(10), nullable=False),
        sa.Column(
            "wholesale_paise", sa.BigInteger(), nullable=False, server_default="0"
        ),
        sa.Column("auto_debit", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("below_min_since", sa.DateTime(timezone=True), nullable=True),
        sa.Column("alerted_at", sa.DateTime(timezone=True), nullable=True),
    )
    _base_indexes("isp_zone_share_plans")
    op.create_index(
        "uq_isp_zone_share_plans_zone",
        "isp_zone_share_plans",
        ["zone_id"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )

    op.create_table(
        "isp_zone_autodebits",
        *_base(),
        _isp(),
        _uuid("zone_id", sa.ForeignKey("isp_zones.id"), nullable=False),
        _uuid("document_id", sa.ForeignKey("isp_invoices.id"), nullable=False),
        _uuid("invoice_id", sa.ForeignKey("isp_invoices.id"), nullable=False),
        sa.Column("kind", sa.String(10), nullable=False),
        sa.Column("amount_paise", sa.BigInteger(), nullable=False),
        _uuid(
            "ledger_entry_id",
            sa.ForeignKey("isp_zone_ledger_entries.id"),
            nullable=True,
        ),
        sa.Column("mode", sa.String(10), nullable=False),
    )
    _base_indexes("isp_zone_autodebits")
    op.create_index(
        "uq_isp_zone_autodebits_doc",
        "isp_zone_autodebits",
        ["document_id", "kind"],
        unique=True,
    )
    op.create_index(
        "ix_isp_zone_autodebits_zone", "isp_zone_autodebits", ["zone_id", "created_at"]
    )

    op.create_table(
        "isp_zone_charges",
        *_base(),
        _isp(),
        _uuid(
            "zone_id", sa.ForeignKey("isp_zones.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("amount_paise", sa.BigInteger(), nullable=False),
        sa.Column("day_of_month", sa.Integer(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("starts_on", sa.Date(), nullable=False),
        sa.Column("last_period", sa.String(7), nullable=True),
    )
    _base_indexes("isp_zone_charges")
    op.create_index("ix_isp_zone_charges_zone", "isp_zone_charges", ["zone_id"])

    op.create_table(
        "isp_zone_settlements",
        *_base(),
        _isp(),
        _uuid("zone_id", sa.ForeignKey("isp_zones.id"), nullable=False),
        sa.Column("number", sa.String(24), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("fy", sa.String(5), nullable=False),
        sa.Column("period_from", sa.Date(), nullable=False),
        sa.Column("period_to", sa.Date(), nullable=False),
        sa.Column("opening_paise", sa.BigInteger(), nullable=False),
        sa.Column("debits_paise", sa.BigInteger(), nullable=False),
        sa.Column("credits_paise", sa.BigInteger(), nullable=False),
        sa.Column("closing_paise", sa.BigInteger(), nullable=False),
        sa.Column("billed_paise", sa.BigInteger(), nullable=False),
        sa.Column("taxable_paise", sa.BigInteger(), nullable=False),
        sa.Column("cgst_paise", sa.BigInteger(), nullable=False),
        sa.Column("sgst_paise", sa.BigInteger(), nullable=False),
        sa.Column("igst_paise", sa.BigInteger(), nullable=False),
        sa.Column(
            "lines",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "snapshot",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )
    _base_indexes("isp_zone_settlements")
    op.create_index(
        "uq_isp_zone_settlements_number",
        "isp_zone_settlements",
        ["isp_organization_id", "number"],
        unique=True,
    )
    op.create_index(
        "ix_isp_zone_settlements_zone", "isp_zone_settlements", ["zone_id", "period_to"]
    )


def downgrade() -> None:
    for table in (
        "isp_zone_settlements",
        "isp_zone_charges",
        "isp_zone_autodebits",
        "isp_zone_share_plans",
    ):
        op.drop_table(table)
