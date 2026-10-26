"""Index the location-wise SMS OTP usage report.

The report reads only real SMS rows from ``otp_requests`` and groups them by
location and local calendar day.  This partial index keeps the common
organization-scoped report bounded to SMS rows without adding a new event or
delivery-status table.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0172_add_otp_sms_usage_index"
down_revision = "0171_create_monitored_device_health"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_otp_requests_sms_usage",
        "otp_requests",
        ["organization_id", "location_id", "created_at"],
        postgresql_where=sa.text("channel = 'sms' AND is_deleted = false"),
    )


def downgrade() -> None:
    op.drop_index("ix_otp_requests_sms_usage", table_name="otp_requests")
