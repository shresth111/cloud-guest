"""Block-enforcement tracking on ``guest_access_rules``. Additive-only,
four columns, one table.

Until now, blocking a guest was a database insert and nothing else.
``GuestAccessService.create_guest_rule`` wrote a row, wrote an audit
entry, and returned 201 -- while the customer dashboard's Blocked Guests
form told the customer, verbatim, *"Takes effect immediately, ending any
session these users currently have."* No session was looked up, no router
was contacted, nothing was ended. The blocked guest stayed online and the
product asserted the opposite. There was nothing to record because nothing
was attempted.

These four columns are the record of a real attempt, mirroring ``vlans``',
``dhcp_pools``' and ``content_filter_rules``' own
``device_push_status``/``device_push_error``/``device_pushed_at`` trio
(0102, 0103, 0106) so every domain that reaches a device reads the same
way in a database session. ``sessions_ended`` is the one addition the
trio does not have, because this domain's push has a *quantity*: how many
live sessions were confirmed gone from their router's own active table.
Confirmed, not attempted -- see ``enforcement.BlocklistEnforcer``.

**Nullable, with no server_default, and that is deliberate -- unlike
0106.** There, the value meaning "as before" was a real value: every
existing content-filter rule had demonstrably never been pushed, so
``pending`` was true of all of them. Here it is not. These rules are of
four types and only ``blocklist`` has anything to enforce; a whitelist row
backfilled to ``pending`` would be asserting that a push is owed for it,
forever, and nothing would ever clear it. A NULL says exactly what is
true of every pre-existing row: this platform has no record of what, if
anything, was done about this rule's live sessions -- which is the honest
answer, because it did nothing and did not know it. New rows always carry
one of ``constants.BlockEnforcementStatus``'s four real values.

**Why not backfill blocklist rows to ``failed``.** It would be the truth
about the sessions those blocks did not end, and it would also be
retroactively alarming about guests who have long since gone offline.
NULL distinguishes "written before this code existed" from "this code ran
and could not reach the router", and only the second is something an
operator should act on.

``enforcement_error`` is ``Text`` and holds the raw ``str(exc)``, shown
verbatim for the same reason 0106 gives: a RouterOS or connection error is
more useful unedited than summarized, and summarizing device errors is how
the original silence started.

**Reversibility.** ``downgrade`` drops all four. Lossless for behaviour --
without them the domain simply has no enforcement record, which is the
pre-migration state. It discards the history of which blocks reached a
router, which is the correct direction to lose data in for a rollback: the
alternative (keeping a status column whose writer is gone) would leave
rows asserting ``enforced`` with nothing able to correct them.

**Head note.** ``alembic heads`` reported exactly one head when this was
written -- ``0106_add_device_push_columns_to_content_filter_rules`` -- and
this chains off it. That single head is itself recent: the
``0103_add_discount_amount_to_invoices`` fork off 0102 was merged in
``fix/alembic-two-heads`` after two engineers each added a ``0106`` on the
same day and broke every deploy. Checking ``alembic heads`` before adding
a revision is not a formality on this repository.

Revision ID: 0108_add_block_enforcement_columns_to_guest_access_rules
Revises: 0107_add_device_push_columns_to_port_forwarding_rules
Create Date: 2026-09-03
"""

import sqlalchemy as sa

from alembic import op

revision = "0108_add_block_enforcement_columns_to_guest_access_rules"
down_revision = "0107_add_device_push_columns_to_port_forwarding_rules"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "guest_access_rules",
        sa.Column("enforcement_status", sa.String(length=20), nullable=True),
    )
    op.add_column(
        "guest_access_rules",
        sa.Column("enforcement_error", sa.Text(), nullable=True),
    )
    op.add_column(
        "guest_access_rules",
        sa.Column("enforced_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "guest_access_rules",
        sa.Column("sessions_ended", sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("guest_access_rules", "sessions_ended")
    op.drop_column("guest_access_rules", "enforced_at")
    op.drop_column("guest_access_rules", "enforcement_error")
    op.drop_column("guest_access_rules", "enforcement_status")
