"""ISP JAZE-2 (ADDENDUM_05 J3/J8): package policy, subscriber usage, MAC/IP
bindings, enforcement events.

New ISP-owned tables only; no existing table is altered. ``downgrade`` drops
exactly these.

Before merging into integ/isp-test, re-point ``down_revision`` onto the
current integ head (lane rule, LANE_NOTES).

Revision ID: 0179_isp_jaze2_enforcement
Revises: 0178_merge_integ_parity_settings
Create Date: 2026-11-01
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0179_isp_jaze2_enforcement"
down_revision = "0178_merge_integ_parity_settings"
branch_labels = None
depends_on = None

_BASE_INDEXED = ("created_at", "deleted_at", "is_deleted", "created_by", "updated_by")
_TABLES = (
    "isp_package_policies",
    "isp_subscriber_usage",
    "isp_subscriber_mac_bindings",
    "isp_subscriber_ip_bindings",
    "isp_enforcement_events",
)


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


def _sub() -> sa.Column:
    return _uuid(
        "subscriber_id",
        sa.ForeignKey("isp_subscribers.id", ondelete="CASCADE"),
        nullable=False,
    )


def _flag(name: str) -> sa.Column:
    return sa.Column(
        name, sa.Boolean(), nullable=False, server_default=sa.text("false")
    )


_LIVE = sa.text("deleted_at IS NULL")


def upgrade() -> None:
    op.create_table(
        "isp_package_policies",
        *_base(),
        _isp(),
        _uuid(
            "package_id",
            sa.ForeignKey("isp_packages.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("fup_limit_mb", sa.BigInteger(), nullable=True),
        sa.Column("fup_reset", sa.String(8), nullable=False, server_default="cycle"),
        _uuid(
            "fup_fallback_speed_group_id",
            sa.ForeignKey("isp_speed_groups.id"),
            nullable=True,
        ),
        _flag("fup_exclude_upload"),
        _flag("fup_carry_forward"),
        _uuid(
            "boost_speed_group_id", sa.ForeignKey("isp_speed_groups.id"), nullable=True
        ),
        sa.Column("boost_start_minute", sa.SmallInteger(), nullable=True),
        sa.Column("boost_end_minute", sa.SmallInteger(), nullable=True),
        _flag("boost_state_active"),
        sa.Column(
            "validity_starts",
            sa.String(12),
            nullable=False,
            server_default="activation",
        ),
        sa.Column("queue_priority", sa.SmallInteger(), nullable=True),
        sa.Column(
            "mac_bind_count", sa.SmallInteger(), nullable=False, server_default="0"
        ),
        _flag("mac_restriction"),
        _flag("ip_restriction"),
        sa.Column("max_simultaneous", sa.SmallInteger(), nullable=True),
        sa.Column("idle_timeout_s", sa.Integer(), nullable=True),
        sa.Column("hard_timeout_s", sa.Integer(), nullable=True),
    )
    op.create_index(
        "uq_isp_package_policies_package",
        "isp_package_policies",
        ["package_id"],
        unique=True,
        postgresql_where=_LIVE,
    )
    op.create_index(
        "ix_isp_package_policies_isp", "isp_package_policies", ["isp_organization_id"]
    )

    op.create_table(
        "isp_subscriber_usage",
        *_base(),
        _isp(),
        _sub(),
        sa.Column("period_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("period_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "used_down_bytes", sa.BigInteger(), nullable=False, server_default="0"
        ),
        sa.Column("used_up_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("carry_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        _flag("throttled"),
        sa.Column("throttled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("topup_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("last_computed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "uq_isp_subscriber_usage_subscriber",
        "isp_subscriber_usage",
        ["subscriber_id"],
        unique=True,
        postgresql_where=_LIVE,
    )

    op.create_table(
        "isp_subscriber_mac_bindings",
        *_base(),
        _isp(),
        _sub(),
        sa.Column("mac", sa.String(17), nullable=False),
        sa.Column("source", sa.String(8), nullable=False),
    )
    op.create_index(
        "uq_isp_subscriber_mac_bindings_sub_mac",
        "isp_subscriber_mac_bindings",
        ["subscriber_id", "mac"],
        unique=True,
        postgresql_where=_LIVE,
    )

    op.create_table(
        "isp_subscriber_ip_bindings",
        *_base(),
        _isp(),
        _uuid(
            "customer_organization_id",
            sa.ForeignKey("organizations.id"),
            nullable=False,
        ),
        _sub(),
        _uuid("location_id", sa.ForeignKey("locations.id"), nullable=False),
        _uuid("router_id", sa.ForeignKey("routers.id"), nullable=True),
        _uuid("dhcp_pool_id", sa.ForeignKey("dhcp_pools.id"), nullable=True),
        sa.Column("ip", sa.String(45), nullable=False),
        sa.Column("mac", sa.String(17), nullable=True),
        _flag("static_queue"),
        _uuid("queue_assignment_id", nullable=True),
        sa.Column("queue_status", sa.String(8), nullable=False, server_default="none"),
        sa.Column("queue_error", sa.String(255), nullable=True),
    )
    op.create_index(
        "uq_isp_subscriber_ip_bindings_location_ip",
        "isp_subscriber_ip_bindings",
        ["location_id", "ip"],
        unique=True,
        postgresql_where=_LIVE,
    )
    op.create_index(
        "ix_isp_subscriber_ip_bindings_subscriber",
        "isp_subscriber_ip_bindings",
        ["subscriber_id"],
    )

    op.create_table(
        "isp_enforcement_events",
        *_base(),
        _isp(),
        _sub(),
        sa.Column("kind", sa.String(24), nullable=False),
        _uuid("session_id", nullable=True),
        sa.Column("detail", sa.String(255), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_isp_enforcement_events_sub_time",
        "isp_enforcement_events",
        ["subscriber_id", "occurred_at"],
    )

    for table in _TABLES:
        for column in _BASE_INDEXED:
            op.create_index(f"ix_{table}_{column}", table, [column])


def downgrade() -> None:
    for table in reversed(_TABLES):
        op.drop_table(table)
