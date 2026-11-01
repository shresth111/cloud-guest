"""COLLECTIONS-1: promise-to-pay, collection timeline, cash handovers.

Additive: four new ISP-owned tables. ``isp_invoices`` / ``isp_payments`` are
not altered. ``downgrade`` drops exactly these four.

Revision ID: 0201_isp_collections
Revises: 0200_isp_zone_invoices
Create Date: 2026-11-01
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0201_isp_collections"
down_revision = "0200_isp_zone_invoices"
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


def _subscriber() -> sa.Column:
    return _uuid(
        "subscriber_id",
        sa.ForeignKey("isp_subscribers.id", ondelete="CASCADE"),
        nullable=True,
    )


_BASE_INDEXED = ("created_at", "deleted_at", "is_deleted", "created_by", "updated_by")


def _base_indexes(table: str) -> None:
    for col in _BASE_INDEXED:
        op.create_index(f"ix_{table}_{col}", table, [col])


def upgrade() -> None:
    op.create_table(
        "isp_collection_promises",
        *_base(),
        _org("isp_organization_id"),
        _org("customer_organization_id"),
        _subscriber(),
        sa.Column("promised_on", sa.Date(), nullable=False),
        sa.Column("amount_paise", sa.BigInteger(), nullable=True),
        sa.Column("target_paise", sa.BigInteger(), nullable=False),
        sa.Column("overdue_at_creation_paise", sa.BigInteger(), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("status", sa.String(12), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_reason", sa.String(255), nullable=True),
        _uuid("followup_task_id", nullable=True),
    )
    _base_indexes("isp_collection_promises")
    op.create_index(
        "ix_isp_collection_promises_isp_status",
        "isp_collection_promises",
        ["isp_organization_id", "status", "promised_on"],
    )
    op.create_index(
        "ix_isp_collection_promises_party",
        "isp_collection_promises",
        ["customer_organization_id", "subscriber_id"],
    )

    op.create_table(
        "isp_collection_events",
        *_base(),
        _org("isp_organization_id"),
        _org("customer_organization_id"),
        _subscriber(),
        sa.Column("kind", sa.String(24), nullable=False),
        sa.Column("outcome", sa.String(16), nullable=True),
        sa.Column("body", sa.Text(), nullable=True),
        _uuid(
            "promise_id",
            sa.ForeignKey("isp_collection_promises.id", ondelete="SET NULL"),
            nullable=True,
        ),
        _uuid("payment_id", sa.ForeignKey("isp_payments.id"), nullable=True),
        sa.Column(
            "detail",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
    )
    _base_indexes("isp_collection_events")
    op.create_index(
        "ix_isp_collection_events_party",
        "isp_collection_events",
        ["customer_organization_id", "subscriber_id", "occurred_at"],
    )
    op.create_index(
        "ix_isp_collection_events_isp",
        "isp_collection_events",
        ["isp_organization_id", "occurred_at"],
    )

    op.create_table(
        "isp_cash_handovers",
        *_base(),
        _org("isp_organization_id"),
        _uuid("collector_user_id", sa.ForeignKey("users.id"), nullable=False),
        sa.Column("business_date", sa.Date(), nullable=False),
        sa.Column("expected_paise", sa.BigInteger(), nullable=False),
        sa.Column("declared_paise", sa.BigInteger(), nullable=False),
        sa.Column("received_paise", sa.BigInteger(), nullable=True),
        sa.Column("status", sa.String(10), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=False),
        _uuid("decided_by", sa.ForeignKey("users.id"), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decision_note", sa.Text(), nullable=True),
    )
    _base_indexes("isp_cash_handovers")
    op.create_index(
        "ix_isp_cash_handovers_isp",
        "isp_cash_handovers",
        ["isp_organization_id", "status", "business_date"],
    )
    op.create_index(
        "ix_isp_cash_handovers_collector",
        "isp_cash_handovers",
        ["collector_user_id", "business_date"],
    )

    op.create_table(
        "isp_cash_handover_items",
        *_base(),
        _uuid(
            "handover_id",
            sa.ForeignKey("isp_cash_handovers.id", ondelete="CASCADE"),
            nullable=False,
        ),
        _uuid("payment_id", sa.ForeignKey("isp_payments.id"), nullable=False),
        sa.Column("amount_paise", sa.BigInteger(), nullable=False),
    )
    _base_indexes("isp_cash_handover_items")
    op.create_index(
        "uq_isp_cash_handover_items_payment",
        "isp_cash_handover_items",
        ["payment_id"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )
    op.create_index(
        "ix_isp_cash_handover_items_handover",
        "isp_cash_handover_items",
        ["handover_id"],
    )


def downgrade() -> None:
    for table in (
        "isp_cash_handover_items",
        "isp_cash_handovers",
        "isp_collection_events",
        "isp_collection_promises",
    ):
        op.drop_table(table)
