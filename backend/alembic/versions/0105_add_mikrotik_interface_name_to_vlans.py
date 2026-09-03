"""``mikrotik_interface_name`` on ``vlans``. Additive-only, one column.

## What this column is

The name the VLAN's interface actually carries on the router, written by
the push that created it. In trunk mode that is the deterministic
``vlan<id>`` the adapter derives from ``vlan_id``; in access mode there is
no ``/interface vlan`` entry at all -- the VLAN is realized as a physical
port -- so the column holds that port's name instead. Storing ``vlan<id>``
for an access row would record an interface that does not exist on the
device.

**Stored rather than recomputed, and that is the point.** Every reader can
already derive ``vlan<id>`` from ``vlan_id``, and several do. What none of
them can derive is what the *device* was told, which is the only useful
version of this fact: a row whose ``port_mode`` was flipped after its last
push, or whose ``vlan_id`` was edited, has an interface on the router that
no longer matches anything computable from the row. NULL until the first
successful push, truthfully -- before one, this platform has no claim
about what any router carries.

## Why there is no ``trunk_interface`` and no ``access_port`` column

The product spec names both. They are not added, because ``interface`` +
``port_mode`` already carry exactly that fact and carry it better:

* ``port_mode="trunk"`` -> ``interface`` *is* the trunk parent.
* ``port_mode="access"`` -> ``interface`` *is* the dedicated access port.

Splitting them into two columns adds no information and subtracts a
guarantee. A row could then hold values in both (which of the two is the
VLAN actually on?) or in neither, and every reader -- renderer, adapter,
teardown -- would still have to branch on ``port_mode`` first to know
which column to trust, so the branch is not removed, only duplicated. The
two-column shape also makes "the operator switched this VLAN from access
to trunk" ambiguous where one column makes it a single edit. Adding a
column because a spec lists a name, when an existing column already holds
the fact under a different name, is how a schema acquires two sources of
truth that disagree.

## Why there is no ``error_message`` column

``device_push_error`` is it -- same content (the device's own words,
verbatim), same audience (the customer, shown on the VLAN row), already
written and committed by ``VlanService.push_vlan_to_device`` before it
re-raises. A second column named after the spec's wording would be a
second place to look for one fact, and only one of the two would ever be
maintained.

## Why ``PROVISIONING`` needs no schema change

``device_push_status`` is already ``String(20)``; ``"provisioning"`` is
twelve characters and the column has no CHECK constraint or enum type
behind it (see 0102, which chose a plain string for exactly this
reason). The new state is a ``VlanDevicePushStatus`` member and nothing
else.

## Reversibility

``downgrade`` drops the column. Lossless for behaviour -- the push path
simply stops recording the device-side name, which is the pre-migration
state -- and it discards only this platform's record of what it named
things, never anything on a device. Rows written as ``"provisioning"``
survive a downgrade unchanged and read as an unknown status to older
code, which treats them as not-``ACTIVE``: the safe direction, since a
push that was in flight is exactly a push nobody has confirmed.

Revision ID: 0105_add_mikrotik_interface_name_to_vlans
Revises: 0104_add_nat_enabled_to_vlans
Create Date: 2026-09-03
"""

import sqlalchemy as sa

from alembic import op

revision = "0105_add_mikrotik_interface_name_to_vlans"
down_revision = "0104_add_nat_enabled_to_vlans"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "vlans",
        sa.Column("mikrotik_interface_name", sa.String(length=100), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("vlans", "mikrotik_interface_name")
