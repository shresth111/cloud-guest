"""ISP ADDENDUM_04 F1-F3 per-ISP settings.

Additive, ISP-owned tables only:

- ``isp_addon_allowances`` (created by 0176): + ``price_per_customer_paise``
  (nullable; a record, nothing bills from it).
- new ``isp_parity_settings``: per-ISP ``pii_unmask_enabled`` (Master) and
  ``byo_customer_override_enabled`` (ISP owner/admin).
- new ``isp_customer_messaging``: per-customer ``own_sender`` override.

No pre-ISP table is touched. ``downgrade`` drops exactly these.

Revision ID: 0177_isp_parity_settings
Revises: 0176_isp_addon_allowances
Create Date: 2026-10-23
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0177_isp_parity_settings"
down_revision = "0176_isp_addon_allowances"
branch_labels = None
depends_on = None

_BASE_INDEXED = ("created_at", "deleted_at", "is_deleted", "created_by", "updated_by")


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


def _flag(name: str) -> sa.Column:
    return sa.Column(
        name, sa.Boolean(), nullable=False, server_default=sa.text("false")
    )


def upgrade() -> None:
    op.add_column(
        "isp_addon_allowances",
        sa.Column("price_per_customer_paise", sa.Integer(), nullable=True),
    )
    op.create_table(
        "isp_parity_settings",
        *_base(),
        _uuid(
            "isp_organization_id",
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        _flag("pii_unmask_enabled"),
        _flag("byo_customer_override_enabled"),
    )
    op.create_table(
        "isp_customer_messaging",
        *_base(),
        _uuid(
            "customer_organization_id",
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        _flag("own_sender"),
    )
    for table in ("isp_parity_settings", "isp_customer_messaging"):
        for column in _BASE_INDEXED:
            op.create_index(f"ix_{table}_{column}", table, [column])
    op.create_index(
        "uq_isp_parity_settings_isp",
        "isp_parity_settings",
        ["isp_organization_id"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )
    op.create_index(
        "uq_isp_customer_messaging_customer",
        "isp_customer_messaging",
        ["customer_organization_id"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )


def downgrade() -> None:
    op.drop_table("isp_customer_messaging")
    op.drop_table("isp_parity_settings")
    op.drop_column("isp_addon_allowances", "price_per_customer_paise")
