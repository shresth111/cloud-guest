"""Device-push tracking on ``port_forwarding_rules``. Additive-only, three
columns.

Creating a port-forwarding rule wrote a row and returned 201. Nothing else
happened. ``app.domains.port_forwarding``'s own package docstring said so
plainly -- "A pure inventory/rules domain -- no ``device_adapters.py``, no
live device push" -- and deferred real provisioning to the "not-yet-built
Network Configuration Management domain's own provisioning-integration
layer".

The writer was never the missing piece. ``wyfy_device_gateway
.mikrotik_adapter.configure_port_forward`` already issued the real
``/ip firewall nat add chain=dstnat ... action=dst-nat`` operation over
librouteros on port 8728, and had zero callers anywhere in ``app/``. This
is the third table in the same shape, after ``vlans`` (0102) and
``dhcp_pools`` (0103).

The consequence here is the one a customer notices fastest and blames the
platform for. A VLAN that never reached a router is an absent network; a
DHCP pool that never reached one hands out no addresses. A port-forwarding
rule that never reached one is a published service -- a camera, a PMS
terminal, an office NAS -- that the dashboard lists as forwarded and that
answers nothing from outside, with no failure anywhere to point at.

These three columns mirror ``vlans``' and ``dhcp_pools``' own
``device_push_status``/``device_push_error``/``device_pushed_at`` trio
field-for-field (and ``qos_traffic_rules``' before them) so every domain
that reaches a device reads the same way in a database session.

**NOT NULL with a server_default, matching 0102/0103's reasoning.** The
value meaning "as before" is a particular value, not an absence: every
existing rule row has demonstrably never been pushed, because no code path
could push one. ``pending`` states the truth for all of them and the
backfill is exactly the default. A nullable column would introduce a fourth
"unknown" state nothing in the domain means or handles.

``device_push_error`` is ``Text`` and holds the raw ``str(exc)``, shown to
the operator verbatim -- a RouterOS error ("already have such item", "no
such item", a policy denial) is more useful unedited than summarized.

**Reversibility.** ``downgrade`` drops all three. Lossless for behaviour:
without them the domain simply has no push record, which is the
pre-migration state. It discards the history of which rules reached a
device, the correct direction to lose data in for a rollback -- the
alternative, keeping a status column whose writer is gone, would leave rows
asserting ``active`` with nothing able to correct them. What it does *not*
undo is the device side: rules already pushed keep forwarding, and after a
downgrade nothing in this database knows they are there. That is inherent
to rolling back a schema behind a live-device feature, not something this
migration can honestly fix, and it is why the rollback direction is to
forget rather than to assert.

Revision ID: 0106_add_device_push_columns_to_port_forwarding_rules
Revises: 0105_add_mikrotik_interface_name_to_vlans
Create Date: 2026-09-03
"""

import sqlalchemy as sa

from alembic import op

revision = "0106_add_device_push_columns_to_port_forwarding_rules"
down_revision = "0105_add_mikrotik_interface_name_to_vlans"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "port_forwarding_rules",
        sa.Column(
            "device_push_status",
            sa.String(length=20),
            nullable=False,
            server_default="pending",
        ),
    )
    op.add_column(
        "port_forwarding_rules",
        sa.Column("device_push_error", sa.Text(), nullable=True),
    )
    op.add_column(
        "port_forwarding_rules",
        sa.Column("device_pushed_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("port_forwarding_rules", "device_pushed_at")
    op.drop_column("port_forwarding_rules", "device_push_error")
    op.drop_column("port_forwarding_rules", "device_push_status")
