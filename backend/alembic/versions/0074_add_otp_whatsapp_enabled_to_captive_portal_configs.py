"""Add otp_whatsapp_enabled to captive_portal_configs -- backs the new
WhatsApp OTP delivery channel (app.domains.otp.constants.OtpChannel.WHATSAPP)
as a genuine third per-location toggle, additive alongside the existing
otp_sms_enabled/otp_email_enabled columns.

Revision ID: 0074_add_otp_whatsapp_enabled_to_captive_portal_configs
Revises: 0073_add_isp_link_traffic_monitoring
Create Date: 2026-08-01
"""

import sqlalchemy as sa

from alembic import op

revision = "0074_add_otp_whatsapp_enabled_to_captive_portal_configs"
down_revision = "0073_add_isp_link_traffic_monitoring"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "captive_portal_configs",
        sa.Column(
            "otp_whatsapp_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    op.drop_column("captive_portal_configs", "otp_whatsapp_enabled")
