"""Device-push tracking on ``firewall_rules``. Additive-only, three columns,
one table.

Until now the firewall domain wrote a row and returned 201; its only device
path was ``network_config``'s SFTP + ``/import`` over port 22, which the
fleet filters. ``FirewallService.push_rules_to_router`` now puts a router's
rules on the device over the RouterOS API (8728), inside the platform's
sentinel band, and these columns are its record -- the same
``device_push_status``/``device_push_error``/``device_pushed_at`` trio
``content_filter_rules`` gained in 0106, so the two read alike.

**NOT NULL with a server_default of ``pending``.** Every existing row has
demonstrably never been on a device, so ``pending`` is the truth for all of
them and the backfill is exactly the default.

**Reversibility.** ``downgrade`` drops all three; without them the domain
simply has no push record, which is the pre-migration state.

Revision ID: 0130_add_device_push_columns_to_firewall_rules
Revises: 0129_add_notification_channel_routing_and_log_kind
Create Date: 2026-09-23
"""

import sqlalchemy as sa

from alembic import op

revision = "0130_add_device_push_columns_to_firewall_rules"
down_revision = "0129_add_notification_channel_routing_and_log_kind"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "firewall_rules",
        sa.Column(
            "device_push_status",
            sa.String(length=20),
            nullable=False,
            server_default="pending",
        ),
    )
    op.add_column(
        "firewall_rules",
        sa.Column("device_push_error", sa.Text(), nullable=True),
    )
    op.add_column(
        "firewall_rules",
        sa.Column("device_pushed_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("firewall_rules", "device_pushed_at")
    op.drop_column("firewall_rules", "device_push_error")
    op.drop_column("firewall_rules", "device_push_status")
