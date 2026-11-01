"""COMMS-2: delivery receipts, Meta webhook config, per-event templates.

Additive: three new ISP-owned tables. ``isp_message_log`` (JAZE-4) is not
altered. ``downgrade`` drops exactly these three.

Revision ID: 0184_isp_comms_hub
Revises: 0183_isp_zone_branding
Create Date: 2026-11-01
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0184_isp_comms_hub"
down_revision = "0183_isp_zone_branding"
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
        "isp_message_receipts",
        *_base(),
        _isp(),
        _uuid(
            "message_log_id",
            sa.ForeignKey("isp_message_log.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("provider_message_id", sa.String(128), nullable=False),
        sa.Column("status", sa.String(12), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("error_code", sa.String(32), nullable=True),
        sa.Column("error_title", sa.String(300), nullable=True),
    )
    _base_indexes("isp_message_receipts")
    op.create_index(
        "uq_isp_message_receipts_msg_status",
        "isp_message_receipts",
        ["isp_organization_id", "provider_message_id", "status"],
        unique=True,
    )
    op.create_index(
        "ix_isp_message_receipts_log", "isp_message_receipts", ["message_log_id"]
    )

    op.create_table(
        "isp_comms_webhooks",
        *_base(),
        _isp(),
        sa.Column("path_token", sa.String(64), nullable=False),
        sa.Column("verify_token", sa.String(64), nullable=False),
        sa.Column("app_secret_encrypted", sa.Text(), nullable=True),
        sa.Column("last_received_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rejected_count", sa.Integer(), nullable=False, server_default="0"),
    )
    _base_indexes("isp_comms_webhooks")
    op.create_index(
        "uq_isp_comms_webhooks_isp",
        "isp_comms_webhooks",
        ["isp_organization_id"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )
    op.create_index(
        "uq_isp_comms_webhooks_token", "isp_comms_webhooks", ["path_token"], unique=True
    )

    op.create_table(
        "isp_message_templates",
        *_base(),
        _isp(),
        sa.Column("event", sa.String(24), nullable=False),
        sa.Column("channel", sa.String(10), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("email_subject", sa.String(200), nullable=True),
        sa.Column("email_body", sa.Text(), nullable=True),
        sa.Column("wa_template_name", sa.String(512), nullable=True),
        sa.Column("wa_language", sa.String(15), nullable=True),
        sa.Column("wa_approval_status", sa.String(24), nullable=True),
        sa.Column("wa_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("wa_body_params", sa.Integer(), nullable=True),
        sa.Column(
            "detail",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )
    _base_indexes("isp_message_templates")
    op.create_index(
        "uq_isp_message_templates_event",
        "isp_message_templates",
        ["isp_organization_id", "event", "channel"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )


def downgrade() -> None:
    for table in (
        "isp_message_templates",
        "isp_comms_webhooks",
        "isp_message_receipts",
    ):
        op.drop_table(table)
