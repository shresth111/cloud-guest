"""SMALL-3: win-back actions (CHURN-RISK save rate).

Additive: one new ISP-owned table. ``downgrade`` drops exactly it.

Revision ID: 0196_isp_winback_actions
Revises: 0195_isp_invoice_line_discount
Create Date: 2026-11-01
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0196_isp_winback_actions"
down_revision = "0195_isp_invoice_line_discount"
branch_labels = None
depends_on = None

T = "isp_winback_actions"


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
        _uuid(
            "customer_organization_id",
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        _uuid(
            "subscriber_id",
            sa.ForeignKey("isp_subscribers.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("action", sa.String(20), nullable=False),
        sa.Column(
            "reasons",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        _uuid("ref_id", nullable=True),
        sa.Column("idempotency_key", sa.String(64), nullable=True),
        sa.Column("acted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_days", sa.Integer(), nullable=False),
        sa.Column("window_ends_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("saved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("saved_via", sa.String(10), nullable=True),
        _uuid("saved_ref_id", nullable=True),
    )
    for col in ("created_at", "deleted_at", "is_deleted", "created_by", "updated_by"):
        op.create_index(f"ix_{T}_{col}", T, [col])
    op.create_index(
        "ix_isp_winback_actions_isp_acted", T, ["isp_organization_id", "acted_at"]
    )
    op.create_index("ix_isp_winback_actions_subscriber", T, ["subscriber_id"])
    op.create_index(
        "uq_isp_winback_actions_key",
        T,
        ["isp_organization_id", "idempotency_key"],
        unique=True,
        postgresql_where=sa.text("idempotency_key IS NOT NULL"),
    )
    op.create_index(
        "ix_isp_winback_actions_open",
        T,
        ["isp_organization_id", "window_ends_at"],
        postgresql_where=sa.text("saved_at IS NULL"),
    )


def downgrade() -> None:
    op.drop_table(T)
