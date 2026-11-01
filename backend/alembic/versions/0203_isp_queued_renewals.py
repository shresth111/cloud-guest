"""QUEUED-RENEWAL: renewals whose plan starts when the current one ends.

Additive: one new ISP-owned table. ``downgrade`` drops exactly it.

Revision ID: 0203_isp_queued_renewals
Revises: 0202_isp_incidents
Create Date: 2026-11-01
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0203_isp_queued_renewals"
down_revision = "0202_isp_incidents"
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
    t = "isp_queued_renewals"
    op.create_table(
        t,
        *_base(),
        _org("isp_organization_id"),
        _org("customer_organization_id"),
        _uuid(
            "subscriber_id",
            sa.ForeignKey("isp_subscribers.id", ondelete="CASCADE"),
            nullable=False,
        ),
        _uuid("package_id", sa.ForeignKey("isp_packages.id"), nullable=False),
        _uuid("speed_group_id", sa.ForeignKey("isp_speed_groups.id"), nullable=False),
        _uuid("previous_package_id", sa.ForeignKey("isp_packages.id"), nullable=True),
        sa.Column("cycles", sa.Integer(), nullable=False),
        _uuid("invoice_id", sa.ForeignKey("isp_invoices.id"), nullable=True),
        _uuid("renewal_event_id", nullable=True),
        sa.Column("starts_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ends_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(10), nullable=False),
        sa.Column("idempotency_key", sa.String(64), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancelled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancel_reason", sa.String(255), nullable=True),
        sa.Column(
            "outcome",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )
    _base_indexes(t)
    op.create_index(
        "uq_isp_queued_renewals_key",
        t,
        ["isp_organization_id", "idempotency_key"],
        unique=True,
    )
    op.create_index(
        "uq_isp_queued_renewals_pending",
        t,
        ["subscriber_id"],
        unique=True,
        postgresql_where=sa.text("status = 'pending' AND deleted_at IS NULL"),
    )
    op.create_index("ix_isp_queued_renewals_due", t, ["status", "starts_at"])


def downgrade() -> None:
    op.drop_table("isp_queued_renewals")
