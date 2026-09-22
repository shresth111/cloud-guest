"""``notification_channels``/``notification_logs`` -- routing for producers
that are not an alert, and a delivery record that says which it was.

## What this adds, and why each piece

### ``notification_channels.event_categories``

The Notification Engine routes alerts by association table:
``alert_rule_notification_channels`` says which channels a triggered
``AlertRule`` notifies, and that mechanism is untouched here.

What it has never had is a way to route anything that is *not* an alert.
Every such producer has instead grown its own environment variable holding
its own webhook URL -- ``Settings.platform_alert_slack_webhook_url`` for
the platform team's copy of a controller outage, with more of the same
shape arriving for customer onboarding. That is a credential per producer,
changed by editing an env file and redeploying, invisible to the console,
and with no delivery record: when one stops working, nothing anywhere says
so.

This column is the routing key those producers publish to instead. A
channel listing a category receives that category's events in addition to
any alert rules linked to it. Empty -- the default, and the value every
existing row gets -- means "alerts only", which is exactly the behaviour
every channel has today, so no row changes meaning and no delivery starts
or stops because of this migration.

``NOT NULL DEFAULT '[]'::jsonb`` rather than nullable: an absent list and
an empty list would mean the same thing, and a nullable column would make
every reader handle both spellings of it forever.

### ``notification_logs.kind``

``notification_logs`` is about to receive rows that were not produced by
an alert at all -- an operator pressing "Send test" on a channel, which is
the action that proves a credential before anyone relies on it. Those rows
must be distinguishable from real deliveries, for a reason that is not
cosmetic: the console shows "last delivery" per channel, and a channel
whose only successful delivery was a test has never carried an alert. A
green tick sourced from a test row tells an operator the channel is proven
in production when all that is proven is that the URL accepted a POST.

``alert_id IS NULL`` cannot carry that distinction. It is already nullable
-- ``alerts.id`` is referenced ``ondelete="SET NULL"`` -- so a genuine
alert delivery whose alert has since been deleted already reads NULL, and
is today indistinguishable from what a test row would look like.

``DEFAULT 'alert'`` backfills every existing row to the only thing it can
have been.

### ``ix_notification_logs_channel_id_sent_at``

"The latest delivery on each of these channels" is the query the console's
channel list runs for every row on the page. ``ix_notification_logs_
channel_id`` and ``ix_notification_logs_sent_at`` exist separately, which
leaves the planner sorting a channel's whole history to take one row from
it. The composite, descending on ``sent_at``, answers it from the index.

Built ``CONCURRENTLY`` (and therefore inside ``autocommit_block``, the
shape ``0075_add_isp_health_check_composite_index`` and ``0128`` already
use here): ``notification_logs`` is append-only on a live database and a
plain ``CREATE INDEX`` would hold a lock against the alert-evaluation
sweep that writes it.

## Why the two ``ALTER TABLE``s are safe to run against production live

Both add a column with a constant, non-volatile default. On PostgreSQL 11+
that is a metadata-only change: no table rewrite, no per-row update, and
the ``ACCESS EXCLUSIVE`` lock is held for the duration of a catalogue
write rather than of a scan. Production is 17.11. ``notification_channels``
holds tens of rows and ``notification_logs`` thousands, so even a rewrite
would have been unremarkable -- but the property is worth stating, because
it is the reason these two can share a migration with a ``CONCURRENTLY``
index build without the lock they take mattering.

Revision ID: 0129_add_notification_channel_routing_and_log_kind
Revises: 0128_add_analytics_snapshot_natural_key_unique_index
Create Date: 2026-09-22
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0129_add_notification_channel_routing_and_log_kind"
down_revision = "0128_add_analytics_snapshot_natural_key_unique_index"
branch_labels = None
depends_on = None

LOG_CHANNEL_SENT_AT_INDEX = "ix_notification_logs_channel_id_sent_at"


def upgrade() -> None:
    op.add_column(
        "notification_channels",
        sa.Column(
            "event_categories",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )
    op.add_column(
        "notification_logs",
        sa.Column(
            "kind",
            sa.String(length=20),
            nullable=False,
            server_default="alert",
        ),
    )

    with op.get_context().autocommit_block():
        # IF NOT EXISTS so a re-run after a failed CONCURRENTLY build --
        # which leaves an *invalid* index behind holding the name, rather
        # than nothing -- does not fail on the name instead of on the real
        # problem. See 0128's own write-up of this failure mode.
        op.execute(
            f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {LOG_CHANNEL_SENT_AT_INDEX} "
            "ON notification_logs (channel_id, sent_at DESC)"
        )


def downgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {LOG_CHANNEL_SENT_AT_INDEX}")
    op.drop_column("notification_logs", "kind")
    op.drop_column("notification_channels", "event_categories")
