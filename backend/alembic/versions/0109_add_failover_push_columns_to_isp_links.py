"""Device-push tracking for WAN failover on ``isp_links``. Additive-only,
three columns, one table.

Until now ``IspService.trigger_failover`` flipped two ``is_active_uplink``
booleans, wrote an audit row and returned 200. ``isp/device_adapters.py``
had no write method of any kind -- ``ping``,
``get_active_default_gateway``, ``get_pppoe_interface_status``,
``get_interface_traffic_counters`` and ``run_speed_test`` are all reads.
So during an outage a customer clicked "Trigger failover", got
``toast.success("Failover triggered")``, the venue stayed offline, and the
"Active uplink" tile started naming the backup. The one screen anyone
looks at while they are already down became actively wrong, which is worse
than having no button.

These three columns are the record of the real device push that now
happens, mirroring ``vlans``' (0102), ``dhcp_pools``' (0103) and
``content_filter_rules``' (0106) ``device_push_status``/
``device_push_error``/``device_pushed_at`` trio field-for-field, so all
four read the same way in a database session.

**Named ``failover_push_*``, not ``device_push_*``.** The other three
tables have exactly one kind of device object per row, so an unqualified
name is unambiguous there. An ``isp_links`` row already participates in
device state through several other paths -- the WAN section of the
rendered setup script writes its address, route, NAT and mangle rules --
and none of those are what these columns track. The qualified name says
which push this is the record of.

**On the promoted link, not on the router.** A failover moves traffic onto
one specific link, and that link is what succeeded or failed. A
per-router column would have to answer "which push?" for a router whose
last failover succeeded and whose last failback did not, and either answer
it gives is wrong about one of them.

**NOT NULL with a server_default.** "As before" is a real value here, not
an absence: every existing row has demonstrably never had a failover
pushed to a device, because no code path could push one. ``pending`` says
exactly that, and the backfill is exactly the default. A nullable column
would add a fourth state ("unknown") that nothing in the domain means.

``failover_push_error`` is ``Text`` and holds the raw ``str(exc)``, shown
to the customer verbatim -- a RouterOS refusal is more useful unedited
than summarized.

**Reversibility.** ``downgrade`` drops all three. Lossless for behaviour:
without them the domain has no push record, which is the pre-migration
state. It discards the history of which failovers reached a device, which
is the correct direction to lose data in -- the alternative (a status
column whose writer is gone, rows still asserting ``active``) leaves
claims about device state that nothing can correct.

**Head note.** ``alembic heads`` on this branch reports exactly one head,
``0108_add_block_enforcement_columns_to_guest_access_rules``, and this chains
off it. Checked deliberately: two engineers each added a ``0106`` on
2026-09-02 and it broke every deploy, so the number was taken from the
live ``heads`` output rather than from the highest filename.

Revision ID: 0109_add_failover_push_columns_to_isp_links
Revises: 0108_add_block_enforcement_columns_to_guest_access_rules
Create Date: 2026-09-03
"""

import sqlalchemy as sa

from alembic import op

revision = "0109_add_failover_push_columns_to_isp_links"
down_revision = "0108_add_block_enforcement_columns_to_guest_access_rules"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "isp_links",
        sa.Column(
            "failover_push_status",
            sa.String(length=20),
            nullable=False,
            server_default="pending",
        ),
    )
    op.add_column(
        "isp_links",
        sa.Column("failover_push_error", sa.Text(), nullable=True),
    )
    op.add_column(
        "isp_links",
        sa.Column("failover_pushed_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("isp_links", "failover_pushed_at")
    op.drop_column("isp_links", "failover_push_error")
    op.drop_column("isp_links", "failover_push_status")
