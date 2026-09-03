"""Device-push tracking on ``content_filter_rules``. Additive-only, three
columns, one table.

Until now the Content Filtering domain -- what a customer sees as "Website
Blocking" -- wrote a row and returned 201 without ever contacting the
router. Its own ``service.py`` docstring said so and called it deliberate,
deferring real provisioning to ``network_config``'s script pipeline. The
consequence was not a missing feature but a lying one: a customer blocked
facebook.com, the dashboard showed it blocked, and a guest device on that
router reached it unchanged. There was nothing to record because nothing
was attempted.

These three columns are the record of a real push, mirroring
``vlans``' and ``dhcp_pools``' own ``device_push_status``/
``device_push_error``/``device_pushed_at`` trio field-for-field (0102 and
0103) so all three domains read the same way in a database session.

**Per-rule, not per-router, and these columns are why.** One row is one
blocked site, and the push that realizes it is scoped to that row alone --
so a rule the router rejects records its own failure and leaves every
other rule on that router pushed and enforcing. A per-router status would
have to collapse "these fourteen are on the device, this fifteenth was
refused" into a single value, and whichever value it picked would be
wrong about fourteen rows or about one. See ``service.py``'s own module
docstring for the full write-up.

**Why this is not ``ConfigVersion``'s job.** ``network_config`` already
tracks whether a *rendered script* was shipped to a router. That is a
different fact, on a different transport (SFTP + ``/import`` over SSH,
port 22, filtered on this fleet), and a ``ConfigVersion`` marked APPLIED
is not evidence a device received anything -- several code paths mark
versions applied without device I/O. This column set is about one row and
one direct RouterOS-API call on 8728, and is deliberately independent of
both ``is_enabled`` (intent) and the config version's status.

**NOT NULL with a server_default.** The value meaning "as before" here
*is* a particular value, not an absence: every existing rule row has
demonstrably never been pushed, so ``pending`` states the truth for all of
them and the backfill is exactly the default. A nullable column would
introduce a fourth state ("unknown") that nothing in the domain means or
handles.

``device_push_error`` is ``Text`` and holds the raw ``str(exc)``. It is
shown to the customer verbatim: a RouterOS error ("already have such
item", "no such item", a policy denial) is more useful unedited than
summarized, and summarizing device errors is how the previous silence
started.

**Reversibility.** ``downgrade`` drops all three. Lossless for behaviour --
without them the domain simply has no push record, which is the
pre-migration state. It discards the history of which rules reached a
device, which is the correct direction to lose data in for a rollback: the
alternative (keeping a status column whose writer is gone) would leave rows
asserting ``active`` with nothing able to correct them.

**Head note.** This chains off 0105, the device-push lineage
(0102 vlans -> 0103 dhcp_pools -> 0104 -> 0105). ``alembic heads`` reports
a second, pre-existing head on this branch --
``0103_add_discount_amount_to_invoices``, which forked from 0102
independently -- that this migration deliberately does not merge. Merging
two unrelated lineages is a decision about the invoices work, not about
this one, and doing it here would bury it in an unrelated change.

Revision ID: 0106_add_device_push_columns_to_content_filter_rules
Revises: 0105_add_mikrotik_interface_name_to_vlans
Create Date: 2026-09-03
"""

import sqlalchemy as sa

from alembic import op

revision = "0106_add_device_push_columns_to_content_filter_rules"
down_revision = "0105_add_mikrotik_interface_name_to_vlans"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "content_filter_rules",
        sa.Column(
            "device_push_status",
            sa.String(length=20),
            nullable=False,
            server_default="pending",
        ),
    )
    op.add_column(
        "content_filter_rules",
        sa.Column("device_push_error", sa.Text(), nullable=True),
    )
    op.add_column(
        "content_filter_rules",
        sa.Column("device_pushed_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("content_filter_rules", "device_pushed_at")
    op.drop_column("content_filter_rules", "device_push_error")
    op.drop_column("content_filter_rules", "device_push_status")
