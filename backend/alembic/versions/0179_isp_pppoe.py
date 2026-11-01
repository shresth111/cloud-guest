"""ISP Phase 2b PPPoE (JAZE-6): credentials + RADIUS accounting sessions.

Additive, ISP-owned tables only:

- ``isp_pppoe_credentials``: one PPPoE login per ``isp_subscribers`` row
  (Fernet-encrypted password; FreeRADIUS verifies CHAP/MS-CHAPv2 itself).
- ``isp_pppoe_sessions``: one row per (NAS, Acct-Session-Id).

No pre-ISP table is touched. ``downgrade`` drops exactly these.

integ/isp-test: re-point ``down_revision`` onto the current integ head before
merging (lane rule), so the chain keeps one head.

Revision ID: 0179_isp_pppoe
Revises: 0178_merge_integ_parity_settings
Create Date: 2026-11-01
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0179_isp_pppoe"
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


def _base_indexes(table: str) -> None:
    for col in _BASE_INDEXED:
        op.create_index(f"ix_{table}_{col}", table, [col])


def upgrade() -> None:
    op.create_table(
        "isp_pppoe_credentials",
        *_base(),
        _uuid("isp_organization_id", sa.ForeignKey("organizations.id"), nullable=False),
        _uuid(
            "customer_organization_id", sa.ForeignKey("organizations.id"), nullable=False
        ),
        _uuid("subscriber_id", sa.ForeignKey("isp_subscribers.id"), nullable=False),
        sa.Column("username", sa.String(64), nullable=False),
        sa.Column("username_lower", sa.String(64), nullable=False),
        sa.Column("password_encrypted", sa.String(512), nullable=False),
        sa.Column("status", sa.String(10), nullable=False, server_default="active"),
        sa.Column("static_ip", sa.String(45), nullable=True),
        sa.Column("ip_pool_name", sa.String(64), nullable=True),
        sa.Column("last_auth_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_auth_result", sa.String(32), nullable=True),
        sa.Column("last_calling_station_id", sa.String(64), nullable=True),
        sa.Column("password_set_at", sa.DateTime(timezone=True), nullable=True),
    )
    _base_indexes("isp_pppoe_credentials")
    op.create_index(
        "uq_isp_pppoe_credentials_subscriber",
        "isp_pppoe_credentials",
        ["subscriber_id"],
        unique=True,
        postgresql_where=sa.text("is_deleted = false"),
    )
    op.create_index(
        "uq_isp_pppoe_credentials_isp_username",
        "isp_pppoe_credentials",
        ["isp_organization_id", "username_lower"],
        unique=True,
        postgresql_where=sa.text("is_deleted = false"),
    )
    op.create_index(
        "ix_isp_pppoe_credentials_customer_username",
        "isp_pppoe_credentials",
        ["customer_organization_id", "username_lower"],
    )

    op.create_table(
        "isp_pppoe_sessions",
        *_base(),
        _uuid("isp_organization_id", sa.ForeignKey("organizations.id"), nullable=False),
        _uuid(
            "customer_organization_id", sa.ForeignKey("organizations.id"), nullable=False
        ),
        _uuid("location_id", sa.ForeignKey("locations.id"), nullable=True),
        _uuid("router_id", sa.ForeignKey("routers.id"), nullable=True),
        _uuid("nas_client_id", sa.ForeignKey("radius_nas_clients.id"), nullable=False),
        _uuid("subscriber_id", sa.ForeignKey("isp_subscribers.id"), nullable=True),
        _uuid("credential_id", sa.ForeignKey("isp_pppoe_credentials.id"), nullable=True),
        sa.Column("username", sa.String(64), nullable=False),
        sa.Column("acct_session_id", sa.String(128), nullable=False),
        sa.Column("calling_station_id", sa.String(64), nullable=True),
        sa.Column("framed_ip_address", sa.String(45), nullable=True),
        sa.Column("framed_ipv6_prefix", sa.String(64), nullable=True),
        sa.Column("delegated_ipv6_prefix", sa.String(64), nullable=True),
        sa.Column("nas_port_id", sa.String(64), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_update_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("stopped_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(10), nullable=False),
        sa.Column("bytes_uploaded", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("bytes_downloaded", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("terminate_cause", sa.String(64), nullable=True),
    )
    _base_indexes("isp_pppoe_sessions")
    op.create_index(
        "uq_isp_pppoe_sessions_nas_acct",
        "isp_pppoe_sessions",
        ["nas_client_id", "acct_session_id"],
        unique=True,
    )
    op.create_index(
        "ix_isp_pppoe_sessions_isp_started",
        "isp_pppoe_sessions",
        ["isp_organization_id", "started_at"],
    )
    op.create_index(
        "ix_isp_pppoe_sessions_subscriber", "isp_pppoe_sessions", ["subscriber_id", "status"]
    )
    op.create_index(
        "ix_isp_pppoe_sessions_framed_ip",
        "isp_pppoe_sessions",
        ["framed_ip_address", "started_at"],
    )
    op.create_index(
        "ix_isp_pppoe_sessions_customer_status",
        "isp_pppoe_sessions",
        ["customer_organization_id", "status"],
    )


def downgrade() -> None:
    op.drop_table("isp_pppoe_sessions")
    op.drop_table("isp_pppoe_credentials")
