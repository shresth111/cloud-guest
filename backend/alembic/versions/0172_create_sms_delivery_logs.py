"""SMS delivery log: one row per real SMS send attempt.

Additive only. One new table, nothing existing is altered.

``sms_delivery_logs`` records, per attempt: who (org/location), why
(purpose), through what (provider, wyfy-or-own account), to whom (masked
number only), the provider's message id and outcome (sent/failed), and --
only when the provider's own delivery report arrives -- delivered/undelivered.

Revision ID: 0172_create_sms_delivery_logs
Revises: 0171_create_monitored_device_health
Create Date: 2026-10-26
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0172_create_sms_delivery_logs"
down_revision = "0171_create_monitored_device_health"
branch_labels = None
depends_on = None

_TABLE = "sms_delivery_logs"


def _ts(name: str, nullable: bool = True, **kw: object) -> sa.Column:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable, **kw)


def upgrade() -> None:
    op.create_table(
        _TABLE,
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        _ts("created_at", nullable=False, server_default=sa.func.now()),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey(
                "organizations.id",
                ondelete="CASCADE",
                name="fk_sms_delivery_logs_organization_id_organizations",
            ),
            nullable=True,
        ),
        sa.Column(
            "location_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey(
                "locations.id",
                ondelete="SET NULL",
                name="fk_sms_delivery_logs_location_id_locations",
            ),
            nullable=True,
        ),
        sa.Column("purpose", sa.String(32), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column(
            "provider_source", sa.String(8), nullable=False, server_default="wyfy"
        ),
        sa.Column("recipient_masked", sa.String(32), nullable=True),
        sa.Column("reference_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("provider_message_id", sa.String(100), nullable=True),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("error_code", sa.String(64), nullable=True),
        sa.Column("error_message", sa.String(300), nullable=True),
        _ts("status_updated_at", nullable=False, server_default=sa.func.now()),
        _ts("dlr_received_at"),
        sa.Column("dlr_source", sa.String(8), nullable=True),
        sa.Column("dlr_raw", sa.String(120), nullable=True),
        sa.Column(
            "dlr_poll_count", sa.SmallInteger(), nullable=False, server_default="0"
        ),
        _ts("last_dlr_poll_at"),
        sa.PrimaryKeyConstraint("id", name="pk_sms_delivery_logs"),
    )
    op.create_index(
        "ix_sms_delivery_logs_org_created", _TABLE, ["organization_id", "created_at"]
    )
    op.create_index("ix_sms_delivery_logs_created_at", _TABLE, ["created_at"])
    op.create_index(
        "ix_sms_delivery_logs_provider_msg", _TABLE, ["provider", "provider_message_id"]
    )
    op.create_index(
        "ix_sms_delivery_logs_awaiting_dlr",
        _TABLE,
        ["created_at"],
        postgresql_where=sa.text("status = 'sent'"),
    )


def downgrade() -> None:
    op.drop_index("ix_sms_delivery_logs_awaiting_dlr", table_name=_TABLE)
    op.drop_index("ix_sms_delivery_logs_provider_msg", table_name=_TABLE)
    op.drop_index("ix_sms_delivery_logs_created_at", table_name=_TABLE)
    op.drop_index("ix_sms_delivery_logs_org_created", table_name=_TABLE)
    op.drop_table(_TABLE)
