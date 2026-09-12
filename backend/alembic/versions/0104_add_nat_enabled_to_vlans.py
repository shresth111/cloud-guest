"""NAT / Internet Access on ``vlans``. Additive-only, one column.

A VLAN this platform pushes to a router gets an interface, an address, and
(via 0103's pool push) a DHCP server. That is a complete, working *local*
network and nothing more. Its guests associate, get a lease, get a gateway
-- and reach nothing, because the router has no source-NAT rule
translating that subnet onto its uplink. There is no error anywhere: the
push succeeds, the VLAN is "active", and the internet is simply absent.

``nat_enabled`` is the customer-facing toggle for the missing piece. When
true, ``VlanService.push_vlan_to_device`` realizes

    /ip firewall nat add chain=srcnat src-address=<the VLAN's own cidr> \
        out-interface=<the router's own WAN> action=masquerade \
        comment="WyfyGuest VLAN <tag>"

and when false it removes that same rule. Neither the subnet, the
interface, nor the tag is a stored or hardcoded value: the subnet is this
row's ``cidr``, the tag is its ``vlan_id``, and the WAN is derived from the
router's own live default route
(``mikrotik_adapter.resolve_wan_interface``) because nothing in this
database knows which port a given site's uplink is plugged into.

**Boolean rather than a nullable one, and a column rather than a
``settings`` key.** This is a routing decision with a real device object
behind it, exactly like ``enable_hotspot`` beside it, and it is read on
every push -- not a bag-of-options preference. It mirrors
``enable_hotspot``'s own column definition field-for-field for that
reason.

**NOT NULL with a server_default of false, matching 0102/0103's
reasoning.** The value meaning "as before" is a particular value, not an
absence: no code path could create a masquerade rule before this
migration, so every existing VLAN row demonstrably has no NAT on its
device. ``false`` states that truth for all of them and the backfill is
exactly the default.

The default is also the *safe* direction rather than merely the
convenient one. Defaulting to true would, on the next push of any existing
VLAN, silently route a network someone deliberately built as isolated --
a back-office or PoS segment -- onto the public internet. An operator
turning NAT on is a decision; this migration inferring it for them is not.

**Reversibility.** ``downgrade`` drops the column. Lossless for
behaviour: without it the push path has no NAT step, which is the
pre-migration state. It does discard which VLANs were meant to have
internet access, and -- worth stating plainly -- dropping the column does
**not** remove any masquerade rule already on a device. A rollback leaves
those rules in place and running; they are removed by deleting the VLAN
(the teardown path removes NAT unconditionally) or by hand. The
alternative, having ``downgrade`` reach out to routers, is not something a
schema migration may do.

Revision ID: 0104_add_nat_enabled_to_vlans
Revises: 0103_add_device_push_columns_to_dhcp_pools
Create Date: 2026-09-02
"""

import sqlalchemy as sa

from alembic import op

revision = "0104_add_nat_enabled_to_vlans"
down_revision = "0103_add_device_push_columns_to_dhcp_pools"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "vlans",
        sa.Column(
            "nat_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    op.drop_column("vlans", "nat_enabled")
