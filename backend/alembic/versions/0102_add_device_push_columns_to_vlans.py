"""Device-push tracking on ``vlans``. Additive-only, three columns, one table.

Until now the VLAN domain wrote a row and returned 201 without ever
contacting the router: no adapter, no push, no job, no subscriber to its
own ``VlanCreated`` event. The operator saw "VLAN created" and the device
was untouched. There was nothing to record because nothing was attempted.

These three columns are the record of a real push, mirroring
``qos_traffic_rules``' own ``device_push_status``/``device_push_error``/
``device_pushed_at`` trio field-for-field so the two domains read the same
way in a database session.

**Why this is not ``ConfigVersion``'s job.** ``network_config`` already
tracks whether a *rendered script* was shipped to a router. That is a
different fact, on a different transport (SFTP + ``/import`` over SSH), and
a ``ConfigVersion`` marked APPLIED is not evidence a device received
anything -- several code paths mark versions applied without device I/O.
This column set is about one row and one direct RouterOS-API call, and is
deliberately independent of both ``is_enabled`` (intent) and the config
version's status.

**NOT NULL with a server_default, unlike 0101's deliberate nullable.** The
value meaning "as before" here *is* a particular value, not an absence:
every existing VLAN row has demonstrably never been pushed, so ``pending``
states the truth for all of them and the backfill is exactly the default.
A nullable column would introduce a fourth state ("unknown") that nothing
in the domain means or handles.

``device_push_error`` is ``Text`` and holds the raw ``str(exc)``. It is
shown to the operator verbatim: a RouterOS error ("already have such item",
"no such item", a policy denial) is more useful unedited than summarized,
and summarizing device errors is how the previous silence started.

**Reversibility.** ``downgrade`` drops all three. Lossless for behaviour --
without them the domain simply has no push record, which is the
pre-migration state. It discards the history of which VLANs reached a
device, which is the correct direction to lose data in for a rollback: the
alternative (keeping a status column whose writer is gone) would leave rows
asserting ``active`` with nothing able to correct them.

Revision ID: 0102_add_device_push_columns_to_vlans
Revises: 0101_add_post_login_html_to_captive_portal_configs
Create Date: 2026-09-02
"""

import sqlalchemy as sa

from alembic import op

revision = "0102_add_device_push_columns_to_vlans"
down_revision = "0101_add_post_login_html_to_captive_portal_configs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "vlans",
        sa.Column(
            "device_push_status",
            sa.String(length=20),
            nullable=False,
            server_default="pending",
        ),
    )
    op.add_column("vlans", sa.Column("device_push_error", sa.Text(), nullable=True))
    op.add_column(
        "vlans",
        sa.Column("device_pushed_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("vlans", "device_pushed_at")
    op.drop_column("vlans", "device_push_error")
    op.drop_column("vlans", "device_push_status")
