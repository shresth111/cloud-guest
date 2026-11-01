"""ISP ADDENDUM_05 J1/J2/J11 (JAZE-1): subscriber profile + timeline.

Additive, ISP-owned tables only:

- ``isp_subscriber_profiles``: 1:1 with ``isp_subscribers`` (onboarding
  fields, override price, after-due action, block/freeze/grace state).
- ``isp_subscriber_events``: append-only subscriber timeline.

No pre-existing table is touched. ``downgrade`` drops exactly these.

Revision ID: 0179_isp_subscriber_360
Revises: 0178_merge_integ_parity_settings
Create Date: 2026-11-01
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0179_isp_subscriber_360"
down_revision = "0178_merge_integ_parity_settings"
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


def _fk(name: str, target: str) -> sa.Column:
    return _uuid(name, sa.ForeignKey(target, ondelete="CASCADE"), nullable=False)


def _ts(name: str) -> sa.Column:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=True)


def _s(name: str, n: int) -> sa.Column:
    return sa.Column(name, sa.String(n), nullable=True)


def upgrade() -> None:
    op.create_table(
        "isp_subscriber_profiles",
        *_base(),
        _fk("isp_organization_id", "organizations.id"),
        _fk("subscriber_id", "isp_subscribers.id"),
        _s("alt_email", 255),
        _s("gender", 12),
        _s("billing_city", 100),
        _s("billing_pincode", 10),
        sa.Column(
            "install_same_as_billing",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column("install_address", sa.Text(), nullable=True),
        _s("install_area", 120),
        _s("install_building", 120),
        _s("install_city", 100),
        _s("install_pincode", 10),
        sa.Column("latitude", sa.Numeric(9, 6), nullable=True),
        sa.Column("longitude", sa.Numeric(9, 6), nullable=True),
        _ts("installed_at"),
        sa.Column("user_type", sa.String(12), nullable=False, server_default="home"),
        _s("connection_type", 12),
        _s("ont_serial", 64),
        _s("stb_serial", 64),
        sa.Column("override_price_paise", sa.BigInteger(), nullable=True),
        sa.Column("billing_anchor_day", sa.SmallInteger(), nullable=True),
        sa.Column(
            "after_due_action", sa.String(16), nullable=False, server_default="suspend"
        ),
        sa.Column(
            "exclude_reminders",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        _ts("activation_at"),
        sa.Column("comments", sa.Text(), nullable=True),
        _s("block_kind", 10),
        _s("blocked_reason", 255),
        _ts("blocked_at"),
        _s("status_before_hold", 10),
        _ts("frozen_at"),
        sa.Column("frozen_remaining_seconds", sa.BigInteger(), nullable=True),
        _ts("grace_until"),
    )
    op.create_table(
        "isp_subscriber_events",
        *_base(),
        _fk("isp_organization_id", "organizations.id"),
        _fk("subscriber_id", "isp_subscribers.id"),
        sa.Column("kind", sa.String(24), nullable=False),
        _s("summary", 255),
        sa.Column(
            "detail",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        _uuid("actor_user_id", nullable=True),
    )
    for table in ("isp_subscriber_profiles", "isp_subscriber_events"):
        for column in _BASE_INDEXED:
            op.create_index(f"ix_{table}_{column}", table, [column])
    op.create_index(
        "uq_isp_subscriber_profiles_subscriber",
        "isp_subscriber_profiles",
        ["subscriber_id"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )
    op.create_index(
        "ix_isp_subscriber_profiles_isp",
        "isp_subscriber_profiles",
        ["isp_organization_id"],
    )
    op.create_index(
        "ix_isp_subscriber_events_sub_created",
        "isp_subscriber_events",
        ["subscriber_id", "created_at"],
    )
    op.create_index(
        "ix_isp_subscriber_events_isp_kind",
        "isp_subscriber_events",
        ["isp_organization_id", "kind"],
    )


def downgrade() -> None:
    op.drop_table("isp_subscriber_events")
    op.drop_table("isp_subscriber_profiles")
