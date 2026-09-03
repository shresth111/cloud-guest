"""Write operations ported from ``network_config/renderers.py``'s real
RouterOS command shapes (``/interface vlan add``, ``/ip address add``,
``/ip pool add``, ``/ip dhcp-server add``, ``/ip dhcp-server network
add``), issued directly over the structured API instead of as script
text."""

from __future__ import annotations

import pytest

from tests.fake_write_transport import FakeRouterOSApi
from wyfy_device_gateway.contract import (
    ContentFilterRuleConfig,
    DhcpPoolConfig,
    NatRuleConfig,
    PortForwardConfig,
    QosPacketMarkConfig,
    RadiusClientConfig,
    RogueDhcpAlertConfig,
    VlanConfig,
    VlanHotspotConfig,
)
from wyfy_device_gateway.mikrotik_adapter import (
    MikroTikAdapter,
    _same_routeros_duration,
    _same_routeros_path,
    MikroTikDeviceError,
    MikroTikWanInterfaceError,
)


@pytest.mark.asyncio
async def test_configure_vlan_adds_interface_and_address(patch_connect, mikrotik_creds):
    api = FakeRouterOSApi()
    patch_connect(api)

    vlan = VlanConfig(vlan_id=42, name="Guest WiFi", interface="ether2", ip_cidr="10.42.0.1/24")
    await MikroTikAdapter().configure_vlan(mikrotik_creds, vlan=vlan)

    assert api.add_calls == [
        (
            ("interface", "vlan"),
            {"name": "vlan42", "vlan-id": "42", "interface": "ether2", "comment": "Guest WiFi"},
        ),
        (("ip", "address"), {"address": "10.42.0.1/24", "interface": "vlan42"}),
    ]


@pytest.mark.asyncio
async def test_configure_vlan_without_cidr_skips_address(patch_connect, mikrotik_creds):
    api = FakeRouterOSApi()
    patch_connect(api)

    vlan = VlanConfig(vlan_id=7, name="No IP VLAN", interface="ether3", ip_cidr=None)
    await MikroTikAdapter().configure_vlan(mikrotik_creds, vlan=vlan)

    assert len(api.add_calls) == 1
    assert api.add_calls[0][0] == ("interface", "vlan")


@pytest.mark.asyncio
async def test_configure_dhcp_pool_derives_smallest_enclosing_network(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi()
    patch_connect(api)

    pool = DhcpPoolConfig(
        interface="ether2",
        range_start="192.168.50.100",
        range_end="192.168.50.200",
        gateway="192.168.50.1",
        dns_servers=["1.1.1.1", "8.8.8.8"],
        lease_time_seconds=3600,
    )
    await MikroTikAdapter().configure_dhcp_pool(mikrotik_creds, pool=pool)

    segments = [call[0] for call in api.add_calls]
    assert segments == [
        ("ip", "pool"),
        ("ip", "dhcp-server"),
        ("ip", "dhcp-server", "network"),
    ]

    pool_call = api.add_calls[0][1]
    assert pool_call["ranges"] == "192.168.50.100-192.168.50.200"

    server_call = api.add_calls[1][1]
    assert server_call["interface"] == "ether2"
    assert server_call["lease-time"] == "3600s"
    assert server_call["address-pool"] == pool_call["name"]

    network_call = api.add_calls[2][1]
    # The smallest real CIDR block that contains both .100 and .200 is a /24.
    assert network_call["address"] == "192.168.50.0/24"
    assert network_call["gateway"] == "192.168.50.1"
    assert network_call["dns-server"] == "1.1.1.1,8.8.8.8"


# ---------------------------------------------------------------------------
# port_mode, and re-pushing
#
# `Vlan.port_mode` decides what gets built, not how it looks: an "access" row
# realized as a trunk puts the physical port on the wrong network. And a
# re-push is ordinary -- someone edits a name and saves again -- so a second
# identical push must not surface as a device error, or people learn to
# ignore push failures.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_access_mode_frees_the_port_and_addresses_it_directly(
    patch_connect, mikrotik_creds
):
    """render_vlan's "access" branch: pull the physical port out of the
    shared bridge and give it the subnet untagged. No /interface vlan entry
    is created at all."""
    api = FakeRouterOSApi(
        menus={
            ("interface", "bridge", "port"): [
                {".id": "*1", "interface": "ether3", "bridge": "bridge-lan"},
                {".id": "*2", "interface": "ether4", "bridge": "bridge-lan"},
            ]
        }
    )
    patch_connect(api)

    vlan = VlanConfig(
        vlan_id=30,
        name="Back office",
        interface="ether3",
        ip_cidr="192.168.30.1/24",
        port_mode="access",
    )
    await MikroTikAdapter().configure_vlan(mikrotik_creds, vlan=vlan)

    assert api.remove_calls == [(("interface", "bridge", "port"), ("*1",))]
    # ether4 is someone else's port and must be left alone.
    assert [r["interface"] for r in api._menus[("interface", "bridge", "port")]] == [
        "ether4"
    ]
    # The address lands on the physical port, not on a vlan sub-interface.
    assert api.add_calls == [
        (("ip", "address"), {"address": "192.168.30.1/24", "interface": "ether3"})
    ]
    assert not any(seg == ("interface", "vlan") for seg, _ in api.add_calls)


@pytest.mark.asyncio
async def test_trunk_mode_is_unchanged_by_the_port_mode_default(
    patch_connect, mikrotik_creds
):
    """port_mode defaults to "trunk", so every existing caller keeps its
    exact previous behaviour."""
    api = FakeRouterOSApi()
    patch_connect(api)

    vlan = VlanConfig(vlan_id=42, name="Guest", interface="ether2", ip_cidr="10.42.0.1/24")
    await MikroTikAdapter().configure_vlan(mikrotik_creds, vlan=vlan)

    assert api.add_calls == [
        (
            ("interface", "vlan"),
            {"name": "vlan42", "vlan-id": "42", "interface": "ether2", "comment": "Guest"},
        ),
        (("ip", "address"), {"address": "10.42.0.1/24", "interface": "vlan42"}),
    ]


@pytest.mark.asyncio
async def test_re_pushing_an_unchanged_vlan_is_a_no_op(patch_connect, mikrotik_creds):
    """RouterOS answers a duplicate add with "already have such item". A
    second push of an unchanged row must add nothing and raise nothing."""
    api = FakeRouterOSApi(
        menus={
            ("interface", "vlan"): [
                {".id": "*1", "name": "vlan42", "vlan-id": "42", "interface": "ether2"}
            ],
            ("ip", "address"): [
                {".id": "*1", "address": "10.42.0.1/24", "interface": "vlan42"}
            ],
        }
    )
    patch_connect(api)

    vlan = VlanConfig(vlan_id=42, name="Guest", interface="ether2", ip_cidr="10.42.0.1/24")
    await MikroTikAdapter().configure_vlan(mikrotik_creds, vlan=vlan)

    assert api.add_calls == []


@pytest.mark.asyncio
async def test_re_pushing_access_mode_does_not_re_add_the_address(
    patch_connect, mikrotik_creds
):
    """Same idempotency guarantee on the access branch. The bridge-port
    removal is naturally idempotent -- the port is simply no longer there."""
    api = FakeRouterOSApi(
        menus={
            ("interface", "bridge", "port"): [],
            ("ip", "address"): [
                {".id": "*1", "address": "192.168.30.1/24", "interface": "ether3"}
            ],
        }
    )
    patch_connect(api)

    vlan = VlanConfig(
        vlan_id=30,
        name="Back office",
        interface="ether3",
        ip_cidr="192.168.30.1/24",
        port_mode="access",
    )
    await MikroTikAdapter().configure_vlan(mikrotik_creds, vlan=vlan)

    assert api.add_calls == []
    assert api.remove_calls == []


@pytest.mark.asyncio
async def test_an_address_on_a_different_interface_does_not_count_as_present(
    patch_connect, mikrotik_creds
):
    """The idempotency check must match on address *and* interface. The same
    subnet already existing somewhere else is not this VLAN's address."""
    api = FakeRouterOSApi(
        menus={
            ("ip", "address"): [
                {".id": "*1", "address": "10.42.0.1/24", "interface": "ether9"}
            ]
        }
    )
    patch_connect(api)

    vlan = VlanConfig(vlan_id=42, name="Guest", interface="ether2", ip_cidr="10.42.0.1/24")
    await MikroTikAdapter().configure_vlan(mikrotik_creds, vlan=vlan)

    assert (
        ("ip", "address"),
        {"address": "10.42.0.1/24", "interface": "vlan42"},
    ) in api.add_calls


# ============================================================================
# DHCP pool idempotency -- all three writes were unconditional ``add`` calls,
# so the second push of an unchanged pool died on RouterOS's "already have
# such item". Re-pushing is an ordinary operation.
# ============================================================================


def _pool() -> DhcpPoolConfig:
    return DhcpPoolConfig(
        interface="vlan300",
        range_start="10.30.30.100",
        range_end="10.30.30.200",
        gateway="10.30.30.1",
        dns_servers=["1.1.1.1", "8.8.8.8"],
        lease_time_seconds=3600,
    )


@pytest.mark.asyncio
async def test_re_pushing_an_unchanged_dhcp_pool_is_a_no_op(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()

    await adapter.configure_dhcp_pool(mikrotik_creds, pool=_pool())
    first_adds = list(api.add_calls)
    assert len(first_adds) == 3  # pool, dhcp-server, dhcp-server network

    await adapter.configure_dhcp_pool(mikrotik_creds, pool=_pool())

    # Nothing added the second time, and nothing raised.
    assert api.add_calls == first_adds
    assert api.update_calls == []


@pytest.mark.asyncio
async def test_widening_the_range_updates_the_pool_rather_than_skipping(
    patch_connect, mikrotik_creds
):
    """The range is the thing an operator actually edits. Skipping because
    a pool of that name exists would report success and leave the old
    range on the device."""
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()

    await adapter.configure_dhcp_pool(mikrotik_creds, pool=_pool())
    widened = DhcpPoolConfig(
        interface="vlan300",
        range_start="10.30.30.100",
        range_end="10.30.30.250",
        gateway="10.30.30.1",
        dns_servers=["1.1.1.1", "8.8.8.8"],
        lease_time_seconds=3600,
    )
    await adapter.configure_dhcp_pool(mikrotik_creds, pool=widened)

    pool_updates = [
        fields for segments, fields in api.update_calls if segments == ("ip", "pool")
    ]
    assert len(pool_updates) == 1
    assert pool_updates[0]["ranges"] == "10.30.30.100-10.30.30.250"


@pytest.mark.asyncio
async def test_changed_dns_updates_the_network_row_for_that_subnet(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()

    await adapter.configure_dhcp_pool(mikrotik_creds, pool=_pool())
    changed = DhcpPoolConfig(
        interface="vlan300",
        range_start="10.30.30.100",
        range_end="10.30.30.200",
        gateway="10.30.30.1",
        dns_servers=["9.9.9.9"],
        lease_time_seconds=3600,
    )
    await adapter.configure_dhcp_pool(mikrotik_creds, pool=changed)

    network_updates = [
        fields
        for segments, fields in api.update_calls
        if segments == ("ip", "dhcp-server", "network")
    ]
    assert len(network_updates) == 1
    assert network_updates[0]["dns-server"] == "9.9.9.9"
    # The subnet itself is the row's identity and must not be re-added.
    assert (
        len([s for s, _ in api.add_calls if s == ("ip", "dhcp-server", "network")]) == 1
    )


@pytest.mark.asyncio
async def test_a_pool_on_a_different_interface_is_a_separate_pool(
    patch_connect, mikrotik_creds
):
    """Identifiers are derived from the interface name, so two interfaces
    must not collide into one pool."""
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()

    await adapter.configure_dhcp_pool(mikrotik_creds, pool=_pool())
    other = DhcpPoolConfig(
        interface="vlan400",
        range_start="10.40.40.100",
        range_end="10.40.40.200",
        gateway="10.40.40.1",
        dns_servers=["1.1.1.1"],
        lease_time_seconds=3600,
    )
    await adapter.configure_dhcp_pool(mikrotik_creds, pool=other)

    pool_adds = [f for s, f in api.add_calls if s == ("ip", "pool")]
    assert [f["name"] for f in pool_adds] == ["vlan300-pool", "vlan400-pool"]


# ============================================================================
# Teardown -- deleting a row never removed anything from the device, and the
# gateway had no method to call even if it had wanted to. A "deleted" VLAN
# or pool went on serving traffic forever.
# ============================================================================


@pytest.mark.asyncio
async def test_delete_vlan_removes_the_address_then_the_interface(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()
    vlan = VlanConfig(
        vlan_id=300, name="Guest", interface="bridge", ip_cidr="10.30.30.1/24"
    )
    await adapter.configure_vlan(mikrotik_creds, vlan=vlan)

    await adapter.delete_vlan(mikrotik_creds, vlan=vlan)

    assert list(api.path("interface", "vlan")) == []
    assert list(api.path("ip", "address")) == []


@pytest.mark.asyncio
async def test_deleting_a_vlan_twice_is_a_no_op(patch_connect, mikrotik_creds):
    """A delete retried after a partial failure has to complete cleanly,
    and deleting a row that was never pushed must do nothing."""
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()
    vlan = VlanConfig(
        vlan_id=300, name="Guest", interface="bridge", ip_cidr="10.30.30.1/24"
    )
    await adapter.configure_vlan(mikrotik_creds, vlan=vlan)
    await adapter.delete_vlan(mikrotik_creds, vlan=vlan)

    await adapter.delete_vlan(mikrotik_creds, vlan=vlan)  # must not raise

    assert list(api.path("interface", "vlan")) == []


@pytest.mark.asyncio
async def test_delete_vlan_leaves_the_same_subnet_on_another_interface_alone(
    patch_connect, mikrotik_creds
):
    """Matches on address *and* interface, the same pair the write adds
    on. The same subnet living elsewhere is not this VLAN's address."""
    api = FakeRouterOSApi(
        menus={
            ("ip", "address"): [
                {".id": "*9", "address": "10.30.30.1/24", "interface": "ether4"}
            ]
        }
    )
    patch_connect(api)
    adapter = MikroTikAdapter()
    vlan = VlanConfig(
        vlan_id=300, name="Guest", interface="bridge", ip_cidr="10.30.30.1/24"
    )
    await adapter.configure_vlan(mikrotik_creds, vlan=vlan)

    await adapter.delete_vlan(mikrotik_creds, vlan=vlan)

    remaining = list(api.path("ip", "address"))
    assert len(remaining) == 1
    assert remaining[0]["interface"] == "ether4"


@pytest.mark.asyncio
async def test_delete_access_vlan_frees_the_address_without_rebridging(
    patch_connect, mikrotik_creds
):
    """The port is deliberately not put back into a bridge: which bridge it
    belonged to was never recorded, and re-adding it to a guessed one would
    silently rejoin a port to the wrong L2 segment."""
    api = FakeRouterOSApi(
        menus={
            ("interface", "bridge", "port"): [
                {".id": "*1", "interface": "ether5", "bridge": "bridge"}
            ]
        }
    )
    patch_connect(api)
    adapter = MikroTikAdapter()
    vlan = VlanConfig(
        vlan_id=400,
        name="Access",
        interface="ether5",
        ip_cidr="10.40.40.1/24",
        port_mode="access",
    )
    await adapter.configure_vlan(mikrotik_creds, vlan=vlan)
    assert list(api.path("interface", "bridge", "port")) == []

    await adapter.delete_vlan(mikrotik_creds, vlan=vlan)

    assert list(api.path("ip", "address")) == []
    assert list(api.path("interface", "bridge", "port")) == []


@pytest.mark.asyncio
async def test_delete_dhcp_pool_removes_all_three_objects(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_dhcp_pool(mikrotik_creds, pool=_pool())

    await adapter.delete_dhcp_pool(mikrotik_creds, pool=_pool())

    assert list(api.path("ip", "pool")) == []
    assert list(api.path("ip", "dhcp-server")) == []
    assert list(api.path("ip", "dhcp-server", "network")) == []


@pytest.mark.asyncio
async def test_dhcp_server_is_removed_before_the_pool_it_references(
    patch_connect, mikrotik_creds
):
    """Not cosmetic: RouterOS refuses to remove an address pool that a
    DHCP server still points at."""
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_dhcp_pool(mikrotik_creds, pool=_pool())

    await adapter.delete_dhcp_pool(mikrotik_creds, pool=_pool())

    order = [segments for segments, _ids in api.remove_calls]
    assert order.index(("ip", "dhcp-server")) < order.index(("ip", "pool"))


@pytest.mark.asyncio
async def test_deleting_a_dhcp_pool_twice_is_a_no_op(patch_connect, mikrotik_creds):
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_dhcp_pool(mikrotik_creds, pool=_pool())
    await adapter.delete_dhcp_pool(mikrotik_creds, pool=_pool())

    await adapter.delete_dhcp_pool(mikrotik_creds, pool=_pool())  # must not raise

    assert list(api.path("ip", "pool")) == []


@pytest.mark.asyncio
async def test_deleting_one_pool_leaves_another_interfaces_pool_alone(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()
    other = DhcpPoolConfig(
        interface="vlan400",
        range_start="10.40.40.100",
        range_end="10.40.40.200",
        gateway="10.40.40.1",
        dns_servers=["1.1.1.1"],
        lease_time_seconds=3600,
    )
    await adapter.configure_dhcp_pool(mikrotik_creds, pool=_pool())
    await adapter.configure_dhcp_pool(mikrotik_creds, pool=other)

    await adapter.delete_dhcp_pool(mikrotik_creds, pool=_pool())

    remaining = [row["name"] for row in api.path("ip", "pool")]
    assert remaining == ["vlan400-pool"]


# ============================================================================
# NAT / internet access -- ``/ip firewall nat`` chain=srcnat action=masquerade.
#
# A VLAN with an address and a DHCP pool is a working *local* network and
# nothing more: its guests get a lease, a gateway, and no route off the
# router. These tests pin the three things that make the rule safe to push
# repeatedly -- the values are derived rather than hardcoded, the rule is
# found again by its comment, and disabling NAT (or deleting the VLAN)
# genuinely takes it back off.
# ============================================================================


def _wan_menus(
    overrides: dict[tuple[str, ...], list[dict[str, object]]] | None = None,
) -> dict[tuple[str, ...], list[dict[str, object]]]:
    """A router shaped like the lab unit: ether1 is the WAN, holding a
    dynamic DHCP address, and is not a bridge port. Nothing in it is named
    "WAN" -- the resolution has to come from the routing table."""
    menus: dict[tuple[str, ...], list[dict[str, object]]] = {
        ("interface",): [
            {".id": "*1", "name": "ether1"},
            {".id": "*2", "name": "ether2"},
            {".id": "*3", "name": "bridge"},
            {".id": "*4", "name": "vlan100"},
        ],
        ("ip", "route"): [
            {
                ".id": "*1",
                "dst-address": "0.0.0.0/0",
                "gateway": "192.168.1.1",
                "dynamic": "true",
                "active": "true",
            }
        ],
        ("ip", "address"): [
            {".id": "*1", "address": "192.168.1.100/24", "interface": "ether1"},
            {".id": "*2", "address": "10.100.0.1/24", "interface": "vlan100"},
        ],
        ("ip", "dhcp-client"): [
            {
                ".id": "*1",
                "interface": "ether1",
                "gateway": "192.168.1.1",
                "status": "bound",
            }
        ],
    }
    menus.update(overrides or {})
    return menus


def _nat_rule(vlan_id: int = 100, src: str = "10.100.0.0/24") -> NatRuleConfig:
    return NatRuleConfig(vlan_id=vlan_id, src_address=src)


@pytest.mark.asyncio
async def test_nat_rule_is_built_from_the_vlan_and_the_routers_real_wan(
    patch_connect, mikrotik_creds
):
    """Every value is derived: the subnet from the VLAN, the interface from
    the router's own default route, the comment from the VLAN's id. The
    literal "WAN" appears nowhere on this router and the rule still lands on
    the right interface."""
    api = FakeRouterOSApi(menus=_wan_menus())
    patch_connect(api)

    await MikroTikAdapter().configure_nat_masquerade(mikrotik_creds, rule=_nat_rule())

    assert api.add_calls == [
        (
            ("ip", "firewall", "nat"),
            {
                "chain": "srcnat",
                "action": "masquerade",
                "src-address": "10.100.0.0/24",
                "out-interface": "ether1",
                "comment": "WyfyGuest VLAN 100",
                "disabled": "no",
            },
        )
    ]


@pytest.mark.asyncio
async def test_the_wan_follows_the_default_route_not_the_interface_ordering(
    patch_connect, mikrotik_creds
):
    """ether1 being the uplink is a convention of one router, not a fact
    about routers. Move the default route to ether5 and the rule has to
    follow it."""
    api = FakeRouterOSApi(
        menus=_wan_menus(
            {
                ("interface",): [
                    {".id": "*1", "name": "ether1"},
                    {".id": "*2", "name": "ether5"},
                    {".id": "*3", "name": "vlan100"},
                ],
                ("ip", "route"): [
                    {
                        ".id": "*1",
                        "dst-address": "0.0.0.0/0",
                        "gateway": "203.0.113.1",
                        "dynamic": "false",
                        "active": "true",
                    }
                ],
                ("ip", "address"): [
                    {".id": "*1", "address": "192.168.1.100/24", "interface": "ether1"},
                    {".id": "*2", "address": "203.0.113.9/24", "interface": "ether5"},
                ],
                ("ip", "dhcp-client"): [],
            }
        )
    )
    patch_connect(api)

    await MikroTikAdapter().configure_nat_masquerade(mikrotik_creds, rule=_nat_rule())

    assert api.add_calls[0][1]["out-interface"] == "ether5"


@pytest.mark.asyncio
async def test_a_route_naming_its_own_interface_is_believed_over_the_subnet_match(
    patch_connect, mikrotik_creds
):
    """RouterOS naming the egress interface outright is a stronger signal
    than deriving it from which address holds the gateway."""
    api = FakeRouterOSApi(
        menus=_wan_menus(
            {
                ("ip", "route"): [
                    {
                        ".id": "*1",
                        "dst-address": "0.0.0.0/0",
                        "gateway": "192.168.1.1",
                        "immediate-gw": "192.168.1.1%ether2",
                        "dynamic": "true",
                        "active": "true",
                    }
                ]
            }
        )
    )
    patch_connect(api)

    await MikroTikAdapter().configure_nat_masquerade(mikrotik_creds, rule=_nat_rule())

    assert api.add_calls[0][1]["out-interface"] == "ether2"


@pytest.mark.asyncio
async def test_no_usable_default_route_raises_rather_than_guessing(
    patch_connect, mikrotik_creds
):
    """A wrong out-interface does not fail loudly: it either masquerades
    guest traffic onto an internal segment or matches nothing, and both
    report success. Nothing may be written when the WAN is unknown."""
    api = FakeRouterOSApi(
        menus=_wan_menus(
            {
                ("ip", "route"): [
                    {
                        ".id": "*1",
                        "dst-address": "0.0.0.0/0",
                        "gateway": "192.168.1.1",
                        "dynamic": "false",
                        "active": "false",
                    }
                ]
            }
        )
    )
    patch_connect(api)

    with pytest.raises(MikroTikWanInterfaceError):
        await MikroTikAdapter().configure_nat_masquerade(
            mikrotik_creds, rule=_nat_rule()
        )

    assert api.add_calls == []


@pytest.mark.asyncio
async def test_a_gateway_on_no_known_interface_raises(patch_connect, mikrotik_creds):
    """The route is active, but nothing on this router holds an address in
    the gateway's subnet -- so which interface it leaves by is genuinely
    unknown."""
    api = FakeRouterOSApi(
        menus=_wan_menus(
            {
                ("ip", "address"): [
                    {".id": "*1", "address": "10.100.0.1/24", "interface": "vlan100"}
                ],
                ("ip", "dhcp-client"): [],
            }
        )
    )
    patch_connect(api)

    with pytest.raises(MikroTikWanInterfaceError):
        await MikroTikAdapter().configure_nat_masquerade(
            mikrotik_creds, rule=_nat_rule()
        )


@pytest.mark.asyncio
async def test_an_explicit_out_interface_must_still_exist(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi(menus=_wan_menus())
    patch_connect(api)

    with pytest.raises(MikroTikWanInterfaceError):
        await MikroTikAdapter().configure_nat_masquerade(
            mikrotik_creds,
            rule=NatRuleConfig(
                vlan_id=100, src_address="10.100.0.0/24", out_interface="sfp-sfpplus1"
            ),
        )

    assert api.add_calls == []


@pytest.mark.asyncio
async def test_re_pushing_unchanged_nat_is_a_no_op(patch_connect, mikrotik_creds):
    """RouterOS answers a duplicate add with "already have such item", and
    a second identical push is an ordinary thing to do."""
    api = FakeRouterOSApi(menus=_wan_menus())
    patch_connect(api)
    adapter = MikroTikAdapter()

    await adapter.configure_nat_masquerade(mikrotik_creds, rule=_nat_rule())
    first_adds = list(api.add_calls)

    await adapter.configure_nat_masquerade(mikrotik_creds, rule=_nat_rule())

    assert api.add_calls == first_adds
    assert api.update_calls == []


@pytest.mark.asyncio
async def test_a_rule_read_back_with_a_real_bool_is_not_updated_forever(
    patch_connect, mikrotik_creds
):
    """RouterOS accepts ``disabled="no"`` on write and answers reads with a
    real ``bool``. Comparing the raw value against the string is how an
    idempotent write turns into an update issued on every single push."""
    api = FakeRouterOSApi(
        menus=_wan_menus(
            {
                ("ip", "firewall", "nat"): [
                    {
                        ".id": "*1",
                        "chain": "srcnat",
                        "action": "masquerade",
                        "src-address": "10.100.0.0/24",
                        "out-interface": "ether1",
                        "comment": "WyfyGuest VLAN 100",
                        "disabled": False,
                    }
                ]
            }
        )
    )
    patch_connect(api)

    await MikroTikAdapter().configure_nat_masquerade(mikrotik_creds, rule=_nat_rule())

    assert api.add_calls == []
    assert api.update_calls == []


@pytest.mark.asyncio
async def test_a_disabled_rule_is_re_enabled_by_a_re_push(
    patch_connect, mikrotik_creds
):
    """A disabled rule provides no internet access, and a push is the
    operator asking for it."""
    api = FakeRouterOSApi(
        menus=_wan_menus(
            {
                ("ip", "firewall", "nat"): [
                    {
                        ".id": "*1",
                        "chain": "srcnat",
                        "action": "masquerade",
                        "src-address": "10.100.0.0/24",
                        "out-interface": "ether1",
                        "comment": "WyfyGuest VLAN 100",
                        "disabled": True,
                    }
                ]
            }
        )
    )
    patch_connect(api)

    await MikroTikAdapter().configure_nat_masquerade(mikrotik_creds, rule=_nat_rule())

    assert api.add_calls == []
    assert api.update_calls == [
        (("ip", "firewall", "nat"), {".id": "*1", "disabled": "no"})
    ]


@pytest.mark.asyncio
async def test_changing_the_subnet_updates_the_rule_instead_of_adding_a_second(
    patch_connect, mikrotik_creds
):
    """The whole reason the comment is the rule's identity. Keyed on
    ``src-address``, this push would find no match, add a second rule, and
    leave the first one masquerading a subnet nothing uses any more."""
    api = FakeRouterOSApi(menus=_wan_menus())
    patch_connect(api)
    adapter = MikroTikAdapter()

    await adapter.configure_nat_masquerade(mikrotik_creds, rule=_nat_rule())
    await adapter.configure_nat_masquerade(
        mikrotik_creds, rule=_nat_rule(src="10.200.0.0/24")
    )

    assert len(api.add_calls) == 1
    assert api.update_calls == [
        (("ip", "firewall", "nat"), {".id": "*1", "src-address": "10.200.0.0/24"})
    ]
    rules = list(api.path("ip", "firewall", "nat"))
    assert len(rules) == 1
    assert rules[0]["src-address"] == "10.200.0.0/24"


@pytest.mark.asyncio
async def test_a_recabled_wan_updates_the_out_interface_in_place(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi(menus=_wan_menus())
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_nat_masquerade(mikrotik_creds, rule=_nat_rule())

    # The uplink moved to ether2; the router's own routing table says so.
    api._menus[("ip", "address")][0]["interface"] = "ether2"
    api._menus[("ip", "dhcp-client")][0]["interface"] = "ether2"
    await adapter.configure_nat_masquerade(mikrotik_creds, rule=_nat_rule())

    assert len(api.add_calls) == 1
    assert api.update_calls == [
        (("ip", "firewall", "nat"), {".id": "*1", "out-interface": "ether2"})
    ]


@pytest.mark.asyncio
async def test_delete_nat_masquerade_removes_the_rule(patch_connect, mikrotik_creds):
    api = FakeRouterOSApi(menus=_wan_menus())
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_nat_masquerade(mikrotik_creds, rule=_nat_rule())

    await adapter.delete_nat_masquerade(mikrotik_creds, rule=_nat_rule())

    assert list(api.path("ip", "firewall", "nat")) == []


@pytest.mark.asyncio
async def test_deleting_nat_twice_is_a_no_op(patch_connect, mikrotik_creds):
    api = FakeRouterOSApi(menus=_wan_menus())
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_nat_masquerade(mikrotik_creds, rule=_nat_rule())
    await adapter.delete_nat_masquerade(mikrotik_creds, rule=_nat_rule())

    await adapter.delete_nat_masquerade(mikrotik_creds, rule=_nat_rule())  # no raise

    assert list(api.path("ip", "firewall", "nat")) == []


@pytest.mark.asyncio
async def test_delete_finds_the_rule_after_the_subnet_changed(
    patch_connect, mikrotik_creds
):
    """Teardown matches on the VLAN's identity, never on its current
    subnet: a rule left from an older subnet is still this VLAN's rule, and
    matching on the current one is exactly how it would be orphaned."""
    api = FakeRouterOSApi(menus=_wan_menus())
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_nat_masquerade(mikrotik_creds, rule=_nat_rule())

    await adapter.delete_nat_masquerade(
        mikrotik_creds, rule=_nat_rule(src="10.222.0.0/24")
    )

    assert list(api.path("ip", "firewall", "nat")) == []


@pytest.mark.asyncio
async def test_delete_does_not_need_a_reachable_wan(patch_connect, mikrotik_creds):
    """A VLAN has to stay removable from a router whose uplink is down --
    often exactly the state a router is in when its config is being torn
    down."""
    api = FakeRouterOSApi(menus=_wan_menus())
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_nat_masquerade(mikrotik_creds, rule=_nat_rule())
    api._menus[("ip", "route")] = []

    await adapter.delete_nat_masquerade(mikrotik_creds, rule=_nat_rule())

    assert list(api.path("ip", "firewall", "nat")) == []


@pytest.mark.asyncio
async def test_another_vlans_nat_rule_is_left_alone(patch_connect, mikrotik_creds):
    """Two VLANs are two rules, and touching one must not disturb the
    other -- on the write path or the teardown path."""
    api = FakeRouterOSApi(menus=_wan_menus())
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_nat_masquerade(mikrotik_creds, rule=_nat_rule())
    await adapter.configure_nat_masquerade(
        mikrotik_creds, rule=_nat_rule(vlan_id=200, src="10.200.0.0/24")
    )
    assert len(api.add_calls) == 2

    # Re-pushing one is still a no-op with the other's rule sitting there.
    await adapter.configure_nat_masquerade(mikrotik_creds, rule=_nat_rule())
    assert len(api.add_calls) == 2
    assert api.update_calls == []

    await adapter.delete_nat_masquerade(mikrotik_creds, rule=_nat_rule())

    remaining = list(api.path("ip", "firewall", "nat"))
    assert [row["comment"] for row in remaining] == ["WyfyGuest VLAN 200"]
    assert remaining[0]["src-address"] == "10.200.0.0/24"


@pytest.mark.asyncio
async def test_nat_leaves_an_unrelated_port_forward_alone(
    patch_connect, mikrotik_creds
):
    """``/ip firewall nat`` is a shared menu: the dstnat rules port
    forwarding writes there are not ours to update or remove."""
    api = FakeRouterOSApi(
        menus=_wan_menus(
            {
                ("ip", "firewall", "nat"): [
                    {
                        ".id": "*1",
                        "chain": "dstnat",
                        "action": "dst-nat",
                        "protocol": "tcp",
                        "dst-port": "8080",
                        "to-addresses": "10.100.0.50",
                    }
                ]
            }
        )
    )
    patch_connect(api)
    adapter = MikroTikAdapter()

    await adapter.configure_nat_masquerade(mikrotik_creds, rule=_nat_rule())
    await adapter.delete_nat_masquerade(mikrotik_creds, rule=_nat_rule())

    remaining = list(api.path("ip", "firewall", "nat"))
    assert len(remaining) == 1
    assert remaining[0]["chain"] == "dstnat"


# ============================================================================
# Captive portal. Six objects per VLAN, all named from the tag, so one
# VLAN's portal can never touch another's or the router's own hotspot1.
# ============================================================================


def _hotspot(vlan_id: int = 100, gateway: str = "10.100.0.1",
             cidr: str = "10.100.0.0/24", interface: str = "vlan100"):
    return VlanHotspotConfig(
        vlan_id=vlan_id,
        interface=interface,
        cidr=cidr,
        gateway=gateway,
        dns_name=f"vlan{vlan_id}.wifi.example.com",
        html_directory="cloudguest-hotspot",
    )


def _added(api, *segments):
    return [fields for seg, fields in api.add_calls if seg == segments]


@pytest.mark.asyncio
async def test_configure_vlan_hotspot_creates_all_six_objects(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi()
    patch_connect(api)

    await MikroTikAdapter().configure_vlan_hotspot(mikrotik_creds, hotspot=_hotspot())

    assert _added(api, "ip", "pool")[0]["name"] == "vlan100-hs-pool"
    assert _added(api, "ip", "dhcp-server")[0]["name"] == "vlan100-hs-dhcp"
    assert _added(api, "ip", "dhcp-server", "network")[0]["gateway"] == "10.100.0.1"
    assert _added(api, "ip", "hotspot", "profile")[0]["name"] == "vlan100-hsprof"
    assert _added(api, "ip", "dns", "static")[0]["name"] == "vlan100.wifi.example.com"
    server = _added(api, "ip", "hotspot")[0]
    assert server["name"] == "vlan100-hotspot"
    assert server["interface"] == "vlan100"
    assert server["profile"] == "vlan100-hsprof"


@pytest.mark.asyncio
async def test_re_pushing_an_unchanged_hotspot_is_a_no_op(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()

    await adapter.configure_vlan_hotspot(mikrotik_creds, hotspot=_hotspot())
    first = list(api.add_calls)

    await adapter.configure_vlan_hotspot(mikrotik_creds, hotspot=_hotspot())

    assert api.add_calls == first
    assert api.update_calls == []


@pytest.mark.asyncio
async def test_the_pool_never_spans_the_gateway(patch_connect, mikrotik_creds):
    """`_render_vlan_hotspot` emits `first-last` over every host except the
    gateway, which spans it when the gateway is not at an edge -- and the
    DHCP server can then lease the router its own address."""
    api = FakeRouterOSApi()
    patch_connect(api)

    await MikroTikAdapter().configure_vlan_hotspot(
        mikrotik_creds, hotspot=_hotspot(gateway="10.100.0.100")
    )

    import ipaddress

    ranges = _added(api, "ip", "pool")[0]["ranges"]
    start, end = (ipaddress.ip_address(p) for p in ranges.split("-"))
    assert not start <= ipaddress.ip_address("10.100.0.100") <= end
    # The larger of the two gateway-free runs in a /24 split at .100.
    assert ranges == "10.100.0.101-10.100.0.254"


@pytest.mark.asyncio
async def test_a_gateway_at_the_bottom_gives_the_conventional_range(
    patch_connect, mikrotik_creds
):
    """The common shape every VLAN this platform creates -- identical to
    what the renderer would emit, so the two paths agree."""
    api = FakeRouterOSApi()
    patch_connect(api)

    await MikroTikAdapter().configure_vlan_hotspot(mikrotik_creds, hotspot=_hotspot())

    assert _added(api, "ip", "pool")[0]["ranges"] == "10.100.0.2-10.100.0.254"


@pytest.mark.asyncio
async def test_a_subnet_with_nothing_left_to_hand_out_is_refused_unwritten(
    patch_connect, mikrotik_creds
):
    """A portal with an empty pool accepts guests and gives them nothing.
    Refused before the connection rather than half-applied.

    A ``/32`` whose only host is the gateway is the real empty case. A
    ``/31`` is not: RFC 3021 gives it two usable addresses and Python's
    ``ip_network.hosts()`` returns both, so one survives the gateway.
    """
    api = FakeRouterOSApi()
    patch_connect(api)

    with pytest.raises(MikroTikDeviceError):
        await MikroTikAdapter().configure_vlan_hotspot(
            mikrotik_creds,
            hotspot=_hotspot(cidr="10.100.0.1/32", gateway="10.100.0.1"),
        )

    assert api.add_calls == []


@pytest.mark.asyncio
async def test_moving_the_gateway_updates_rather_than_duplicating(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()

    await adapter.configure_vlan_hotspot(mikrotik_creds, hotspot=_hotspot())
    await adapter.configure_vlan_hotspot(
        mikrotik_creds, hotspot=_hotspot(gateway="10.100.0.254")
    )

    assert len(_added(api, "ip", "hotspot", "profile")) == 1
    profile_updates = [
        f for seg, f in api.update_calls if seg == ("ip", "hotspot", "profile")
    ]
    assert profile_updates and profile_updates[-1]["hotspot-address"] == "10.100.0.254"


@pytest.mark.asyncio
async def test_delete_removes_the_whole_portal_and_twice_is_a_no_op(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_vlan_hotspot(mikrotik_creds, hotspot=_hotspot())

    await adapter.delete_vlan_hotspot(mikrotik_creds, hotspot=_hotspot())

    for path in (("ip", "pool"), ("ip", "dhcp-server"), ("ip", "hotspot"),
                 ("ip", "hotspot", "profile"), ("ip", "dns", "static")):
        assert list(api.path(*path)) == [], path

    await adapter.delete_vlan_hotspot(mikrotik_creds, hotspot=_hotspot())  # no raise


@pytest.mark.asyncio
async def test_one_vlans_portal_leaves_another_and_hotspot1_alone(
    patch_connect, mikrotik_creds
):
    """The router's own default `hotspot1` sits on the bridge and must
    survive any per-VLAN portal being torn down."""
    api = FakeRouterOSApi(
        menus={
            ("ip", "hotspot"): [
                {".id": "*1", "name": "hotspot1", "interface": "bridge"}
            ]
        }
    )
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_vlan_hotspot(mikrotik_creds, hotspot=_hotspot(100))
    await adapter.configure_vlan_hotspot(
        mikrotik_creds,
        hotspot=_hotspot(200, gateway="10.200.0.1", cidr="10.200.0.0/24",
                         interface="vlan200"),
    )

    await adapter.delete_vlan_hotspot(mikrotik_creds, hotspot=_hotspot(100))

    remaining = sorted(str(h.get("name")) for h in api.path("ip", "hotspot"))
    assert remaining == ["hotspot1", "vlan200-hotspot"]


@pytest.mark.asyncio
async def test_read_network_snapshot_reports_interfaces_and_addresses(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi(
        menus={
            ("interface"): [],
            ("ip", "address"): [
                {".id": "*1", "address": "10.5.50.1/24", "interface": "bridge"},
                {".id": "*2", "address": "10.9.9.1/24", "interface": "vlan9",
                 "disabled": True},
            ],
        }
    )
    patch_connect(api)

    snapshot = await MikroTikAdapter().read_network_snapshot(mikrotik_creds)

    addresses = {a.address: a for a in snapshot.ip_addresses}
    assert addresses["10.5.50.1/24"].interface == "bridge"
    assert addresses["10.5.50.1/24"].disabled is False
    # A disabled address is in no routing table and collides with nothing --
    # the caller needs the flag, not a pre-filtered list.
    assert addresses["10.9.9.1/24"].disabled is True


# ---------------------------------------------------------------------------
# content filtering
#
# What a blocked site actually becomes on the device: a domain is two
# ``/ip dns static`` entries pointed at 127.0.0.1 (an exact ``name=`` match
# and a ``regexp=`` match for its subdomains -- RouterOS treats the two as
# mutually exclusive per entry), an IP/CIDR is one
# ``/ip firewall address-list`` membership plus the one router-global
# ``/ip firewall filter`` DROP rule that gives that list any effect.
#
# Every one of them carries "WyfyGuest content filter <rule_id>: <label>",
# and the marker in front of the colon is what the next push matches on.
# The tests below are mostly about that choice: the blocked value and the
# label are exactly what a customer edits, so neither can be the handle.
# ---------------------------------------------------------------------------

_RULE_ID = "3f2a1c64-0000-4000-8000-000000000001"


def _domain_rule(
    value: str = "facebook.com",
    label: str = "Block Facebook",
    rule_id: str = _RULE_ID,
) -> ContentFilterRuleConfig:
    return ContentFilterRuleConfig(
        rule_id=rule_id, value_type="domain", value=value, label=label
    )


def _cidr_rule(
    value: str = "203.0.113.0/24",
    label: str = "Block bad range",
    rule_id: str = _RULE_ID,
) -> ContentFilterRuleConfig:
    return ContentFilterRuleConfig(
        rule_id=rule_id, value_type="ip_cidr", value=value, label=label
    )


@pytest.mark.asyncio
async def test_a_blocked_domain_becomes_two_sinkholed_dns_entries(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi()
    patch_connect(api)

    await MikroTikAdapter().configure_content_filter_rule(
        mikrotik_creds, rule=_domain_rule()
    )

    assert api.add_calls == [
        (
            ("ip", "dns", "static"),
            {
                "name": "facebook.com",
                "type": "A",
                "address": "127.0.0.1",
                "comment": (
                    f"WyfyGuest content filter {_RULE_ID}: Block Facebook"
                ),
                "disabled": "no",
            },
        ),
        (
            ("ip", "dns", "static"),
            {
                "regexp": r"^.*\.facebook\.com$",
                "type": "A",
                "address": "127.0.0.1",
                "comment": (
                    f"WyfyGuest content filter {_RULE_ID} (subdomains): "
                    "Block Facebook"
                ),
                "disabled": "no",
            },
        ),
    ]


@pytest.mark.asyncio
async def test_a_blocked_cidr_becomes_a_list_entry_and_the_shared_drop_rule(
    patch_connect, mikrotik_creds
):
    """The address-list on its own blocks nothing. A populated list with no
    filter rule referencing it is the "looks wired up but isn't" shape this
    whole domain exists to stop."""
    api = FakeRouterOSApi()
    patch_connect(api)

    await MikroTikAdapter().configure_content_filter_rule(
        mikrotik_creds, rule=_cidr_rule()
    )

    assert api.add_calls == [
        (
            ("ip", "firewall", "address-list"),
            {
                "list": "wyfyguest-content-filter-blocked",
                "address": "203.0.113.0/24",
                "comment": (
                    f"WyfyGuest content filter {_RULE_ID}: Block bad range"
                ),
                "disabled": "no",
            },
        ),
        (
            ("ip", "firewall", "filter"),
            {
                "chain": "forward",
                "dst-address-list": "wyfyguest-content-filter-blocked",
                "action": "drop",
                "comment": "Wyfy Guest content filtering: block listed addresses",
            },
        ),
    ]


@pytest.mark.asyncio
async def test_re_pushing_an_unchanged_domain_rule_is_a_clean_no_op(
    patch_connect, mikrotik_creds
):
    """Re-pushing is an ordinary operation -- the customer pressing the
    button twice, or a retry after a partial failure. RouterOS answers a
    duplicate add with "already have such item"."""
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_content_filter_rule(mikrotik_creds, rule=_domain_rule())

    await adapter.configure_content_filter_rule(mikrotik_creds, rule=_domain_rule())

    assert len(api.add_calls) == 2  # the first push's two entries, and no more
    assert api.update_calls == []
    assert len(list(api.path("ip", "dns", "static"))) == 2


@pytest.mark.asyncio
async def test_re_pushing_an_unchanged_cidr_rule_is_a_clean_no_op(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_content_filter_rule(mikrotik_creds, rule=_cidr_rule())

    await adapter.configure_content_filter_rule(mikrotik_creds, rule=_cidr_rule())

    assert len(api.add_calls) == 2  # the list entry and the one DROP rule
    assert api.update_calls == []
    assert len(list(api.path("ip", "firewall", "address-list"))) == 1
    assert len(list(api.path("ip", "firewall", "filter"))) == 1


@pytest.mark.asyncio
async def test_a_disabled_entry_is_compared_as_a_boolean_not_a_string(
    patch_connect, mikrotik_creds
):
    """RouterOS accepts "no" on write and answers reads with a real bool.
    String-comparing ``disabled`` makes this "idempotent" write issue a
    pointless update on every single push, forever."""
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_content_filter_rule(mikrotik_creds, rule=_domain_rule())
    for row in api.path("ip", "dns", "static"):
        row["disabled"] = False  # what a real read answers, not the "no" written

    await adapter.configure_content_filter_rule(mikrotik_creds, rule=_domain_rule())

    assert api.update_calls == []


@pytest.mark.asyncio
async def test_an_entry_disabled_by_hand_is_re_enabled_by_a_re_push(
    patch_connect, mikrotik_creds
):
    """A disabled sinkhole answers nothing, so the site is reachable again.
    A re-push is the customer asking for the block back."""
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_content_filter_rule(mikrotik_creds, rule=_domain_rule())
    for row in api.path("ip", "dns", "static"):
        row["disabled"] = True

    await adapter.configure_content_filter_rule(mikrotik_creds, rule=_domain_rule())

    assert [fields["disabled"] for _, fields in api.update_calls] == ["no", "no"]


@pytest.mark.asyncio
async def test_editing_the_blocked_domain_updates_both_entries_in_place(
    patch_connect, mikrotik_creds
):
    """The whole reason the marker is the identity. Keyed on ``name``, this
    push would match nothing, add a second pair of entries, and leave the
    first pair still sinkholing a site the customer already unblocked."""
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_content_filter_rule(mikrotik_creds, rule=_domain_rule())

    await adapter.configure_content_filter_rule(
        mikrotik_creds, rule=_domain_rule(value="instagram.com")
    )

    assert len(api.add_calls) == 2
    assert api.update_calls == [
        (("ip", "dns", "static"), {".id": "*1", "name": "instagram.com"}),
        (
            ("ip", "dns", "static"),
            {".id": "*2", "regexp": r"^.*\.instagram\.com$"},
        ),
    ]
    entries = list(api.path("ip", "dns", "static"))
    assert len(entries) == 2
    assert entries[0]["name"] == "instagram.com"
    assert "facebook" not in str(entries)


@pytest.mark.asyncio
async def test_editing_the_blocked_address_updates_the_list_entry_in_place(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_content_filter_rule(mikrotik_creds, rule=_cidr_rule())

    await adapter.configure_content_filter_rule(
        mikrotik_creds, rule=_cidr_rule(value="198.51.100.0/24")
    )

    assert len(api.add_calls) == 2  # list entry + DROP rule, both from push one
    assert api.update_calls == [
        (
            ("ip", "firewall", "address-list"),
            {".id": "*1", "address": "198.51.100.0/24"},
        )
    ]
    entries = list(api.path("ip", "firewall", "address-list"))
    assert len(entries) == 1
    assert entries[0]["address"] == "198.51.100.0/24"


@pytest.mark.asyncio
async def test_renaming_a_rule_updates_its_comment_rather_than_losing_it(
    patch_connect, mikrotik_creds
):
    """The label lives behind the marker in the same comment field, so it
    is mutable state like any other -- and the marker in front of it is
    what survives the rename and finds the entry."""
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_content_filter_rule(mikrotik_creds, rule=_cidr_rule())

    await adapter.configure_content_filter_rule(
        mikrotik_creds, rule=_cidr_rule(label="Blocked by head office")
    )

    assert len(api.add_calls) == 2
    entries = list(api.path("ip", "firewall", "address-list"))
    assert len(entries) == 1
    assert entries[0]["comment"] == (
        f"WyfyGuest content filter {_RULE_ID}: Blocked by head office"
    )


@pytest.mark.asyncio
async def test_switching_a_rule_from_a_domain_to_an_address_tears_the_old_one_down(
    patch_connect, mikrotik_creds
):
    """Otherwise the DNS sinkhole answers forever for a name nobody is
    blocking any more, and this push reports success."""
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_content_filter_rule(mikrotik_creds, rule=_domain_rule())

    await adapter.configure_content_filter_rule(mikrotik_creds, rule=_cidr_rule())

    assert list(api.path("ip", "dns", "static")) == []
    assert len(list(api.path("ip", "firewall", "address-list"))) == 1


@pytest.mark.asyncio
async def test_switching_a_rule_from_an_address_to_a_domain_tears_the_old_one_down(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_content_filter_rule(mikrotik_creds, rule=_cidr_rule())

    await adapter.configure_content_filter_rule(mikrotik_creds, rule=_domain_rule())

    assert list(api.path("ip", "firewall", "address-list")) == []
    assert len(list(api.path("ip", "dns", "static"))) == 2


@pytest.mark.asyncio
async def test_a_second_rule_gets_its_own_objects(patch_connect, mikrotik_creds):
    """Two rules, two markers. One rule's push must never find, update or
    remove another's -- that is what makes per-rule pushes independent."""
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()
    other_id = "3f2a1c64-0000-4000-8000-000000000002"

    await adapter.configure_content_filter_rule(mikrotik_creds, rule=_domain_rule())
    await adapter.configure_content_filter_rule(
        mikrotik_creds,
        rule=_domain_rule(value="tiktok.com", label="Block TikTok", rule_id=other_id),
    )

    assert api.update_calls == []
    names = sorted(
        str(row["name"]) for row in api.path("ip", "dns", "static") if "name" in row
    )
    assert names == ["facebook.com", "tiktok.com"]


@pytest.mark.asyncio
async def test_delete_removes_this_rules_objects(patch_connect, mikrotik_creds):
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_content_filter_rule(mikrotik_creds, rule=_domain_rule())

    await adapter.delete_content_filter_rule(mikrotik_creds, rule=_domain_rule())

    assert list(api.path("ip", "dns", "static")) == []


@pytest.mark.asyncio
async def test_deleting_a_content_filter_rule_twice_is_a_no_op(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_content_filter_rule(mikrotik_creds, rule=_cidr_rule())
    await adapter.delete_content_filter_rule(mikrotik_creds, rule=_cidr_rule())

    await adapter.delete_content_filter_rule(  # no raise
        mikrotik_creds, rule=_cidr_rule()
    )

    assert list(api.path("ip", "firewall", "address-list")) == []


@pytest.mark.asyncio
async def test_delete_finds_the_rule_after_the_blocked_value_changed(
    patch_connect, mikrotik_creds
):
    """Teardown matches on the rule's identity, never on its current value:
    an entry left from an older domain is still this rule's entry, and
    matching on the current one is exactly how it would be orphaned."""
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_content_filter_rule(mikrotik_creds, rule=_domain_rule())

    await adapter.delete_content_filter_rule(
        mikrotik_creds, rule=_domain_rule(value="something-else.com", label="renamed")
    )

    assert list(api.path("ip", "dns", "static")) == []


@pytest.mark.asyncio
async def test_delete_leaves_another_rule_and_unrelated_entries_alone(
    patch_connect, mikrotik_creds
):
    """The shared DROP rule stays: it is router-global and every other
    ip_cidr rule depends on it, so removing it here would silently unblock
    all of them. So do the operator's own hand-written entries."""
    api = FakeRouterOSApi(
        menus={
            ("ip", "dns", "static"): [
                {".id": "*90", "name": "portal.wyfyguest.local", "address": "10.0.0.1"}
            ],
            ("ip", "firewall", "filter"): [
                {".id": "*91", "chain": "input", "action": "accept"}
            ],
        }
    )
    patch_connect(api)
    adapter = MikroTikAdapter()
    other_id = "3f2a1c64-0000-4000-8000-000000000002"
    await adapter.configure_content_filter_rule(mikrotik_creds, rule=_cidr_rule())
    await adapter.configure_content_filter_rule(
        mikrotik_creds,
        rule=_cidr_rule(value="192.0.2.0/24", label="Other", rule_id=other_id),
    )

    await adapter.delete_content_filter_rule(mikrotik_creds, rule=_cidr_rule())

    remaining = list(api.path("ip", "firewall", "address-list"))
    assert [row["address"] for row in remaining] == ["192.0.2.0/24"]
    assert len(list(api.path("ip", "firewall", "filter"))) == 2
    assert [row["name"] for row in api.path("ip", "dns", "static")] == [
        "portal.wyfyguest.local"
    ]


@pytest.mark.asyncio
async def test_a_device_error_is_wrapped_and_names_the_operation(
    patch_connect, mikrotik_creds
):
    from librouteros.exceptions import LibRouterosError

    class _ExplodingApi(FakeRouterOSApi):
        def path(self, *segments: str):
            raise LibRouterosError("no such command")

    patch_connect(_ExplodingApi())

    with pytest.raises(MikroTikDeviceError, match="configure_content_filter_rule"):
        await MikroTikAdapter().configure_content_filter_rule(
            mikrotik_creds, rule=_domain_rule()
        )


# ============================================================================
# Port forwarding. Same comment-as-identity design as the masquerade rule
# above, and for the same reason: every RouterOS field on a DSTNAT rule is
# one a customer edits, so the row id is the only stable handle. A re-push
# has to find what it wrote last time, not add a second rule beside it.
# ============================================================================


_PF_ID = "9f1c2f2e-0d3a-4c5b-8e7f-1a2b3c4d5e6f"


def _forward(
    *,
    rule_id: str = _PF_ID,
    protocol: str = "tcp",
    external_port: int = 8080,
    internal_ip: str = "192.168.1.10",
    internal_port: int = 80,
    dst_address: str | None = None,
    src_address: str | None = None,
) -> PortForwardConfig:
    return PortForwardConfig(
        rule_id=rule_id,
        protocol=protocol,
        external_port=external_port,
        internal_ip=internal_ip,
        internal_port=internal_port,
        dst_address=dst_address,
        src_address=src_address,
    )


def _nat_rows(api) -> list[dict[str, object]]:
    return list(api.path("ip", "firewall", "nat"))


@pytest.mark.asyncio
async def test_port_forward_is_built_from_the_customers_own_values(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi()
    patch_connect(api)

    await MikroTikAdapter().configure_port_forward(
        mikrotik_creds,
        rule=_forward(dst_address="203.0.113.9", src_address="198.51.100.0/24"),
    )

    assert api.add_calls == [
        (
            ("ip", "firewall", "nat"),
            {
                "chain": "dstnat",
                "action": "dst-nat",
                "protocol": "tcp",
                "dst-port": "8080",
                "to-addresses": "192.168.1.10",
                "to-ports": "80",
                "dst-address": "203.0.113.9",
                "src-address": "198.51.100.0/24",
                "comment": f"WyfyGuest PF {_PF_ID} tcp",
                "disabled": "no",
            },
        )
    ]


@pytest.mark.asyncio
async def test_unset_matchers_are_omitted_rather_than_sent_blank(
    patch_connect, mikrotik_creds
):
    """"Any source" is the absence of a src-address, not an empty one -- an
    add naming a field with no value is a different request."""
    api = FakeRouterOSApi()
    patch_connect(api)

    await MikroTikAdapter().configure_port_forward(mikrotik_creds, rule=_forward())

    fields = api.add_calls[0][1]
    assert "src-address" not in fields
    assert "dst-address" not in fields


@pytest.mark.asyncio
async def test_re_pushing_an_unchanged_rule_is_a_clean_no_op(
    patch_connect, mikrotik_creds
):
    """The whole point of the comment identity. This used to be an
    unconditional add, so the second push died on "already have such item"
    -- and re-pushing is an ordinary operation, not a recovery step."""
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()

    await adapter.configure_port_forward(mikrotik_creds, rule=_forward())
    after_first = list(api.add_calls)

    await adapter.configure_port_forward(mikrotik_creds, rule=_forward())

    assert api.add_calls == after_first
    # No update either: ``disabled`` reads back as a real bool, and
    # string-comparing it is how an idempotent write issues an update on
    # every single push.
    assert api.update_calls == []
    assert len(_nat_rows(api)) == 1


@pytest.mark.asyncio
async def test_a_disabled_boolean_read_back_does_not_provoke_an_update(
    patch_connect, mikrotik_creds
):
    """RouterOS accepts "no" on write and answers reads with ``False``."""
    api = FakeRouterOSApi(
        menus={
            ("ip", "firewall", "nat"): [
                {
                    ".id": "*1",
                    "chain": "dstnat",
                    "action": "dst-nat",
                    "protocol": "tcp",
                    "dst-port": "8080",
                    "to-addresses": "192.168.1.10",
                    "to-ports": "80",
                    "disabled": False,
                    "comment": f"WyfyGuest PF {_PF_ID} tcp",
                }
            ]
        }
    )
    patch_connect(api)

    await MikroTikAdapter().configure_port_forward(mikrotik_creds, rule=_forward())

    assert api.update_calls == []
    assert api.add_calls == []


@pytest.mark.asyncio
async def test_a_rule_someone_disabled_by_hand_is_re_enabled(
    patch_connect, mikrotik_creds
):
    """A disabled rule forwards nothing, and a re-push is the operator
    asking for it back."""
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_port_forward(mikrotik_creds, rule=_forward())
    _nat_rows(api)[0]["disabled"] = True

    await adapter.configure_port_forward(mikrotik_creds, rule=_forward())

    assert api.update_calls[-1][1]["disabled"] == "no"
    assert len(_nat_rows(api)) == 1


@pytest.mark.asyncio
async def test_moving_the_internal_host_updates_the_rule_instead_of_adding_one(
    patch_connect, mikrotik_creds
):
    """Keyed on to-addresses instead, this push would match nothing, add a
    second rule, and leave the first forwarding a live public port at a
    host that has moved."""
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_port_forward(mikrotik_creds, rule=_forward())

    await adapter.configure_port_forward(
        mikrotik_creds, rule=_forward(internal_ip="192.168.1.55", internal_port=8000)
    )

    rows = _nat_rows(api)
    assert len(rows) == 1
    assert rows[0]["to-addresses"] == "192.168.1.55"
    assert rows[0]["to-ports"] == "8000"
    assert len(api.add_calls) == 1


@pytest.mark.asyncio
async def test_moving_the_published_port_updates_the_same_rule(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_port_forward(mikrotik_creds, rule=_forward())

    await adapter.configure_port_forward(
        mikrotik_creds, rule=_forward(external_port=9090)
    )

    rows = _nat_rows(api)
    assert len(rows) == 1
    assert rows[0]["dst-port"] == "9090"


@pytest.mark.asyncio
async def test_clearing_a_source_restriction_really_clears_it(
    patch_connect, mikrotik_creds
):
    """Left in place, the rule keeps forwarding only for a network the
    operator has stopped restricting it to -- working-looking and wrong."""
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_port_forward(
        mikrotik_creds, rule=_forward(src_address="198.51.100.0/24")
    )

    await adapter.configure_port_forward(mikrotik_creds, rule=_forward())

    assert _nat_rows(api)[0]["src-address"] == ""


@pytest.mark.asyncio
async def test_a_both_protocol_rule_becomes_one_device_rule_per_transport(
    patch_connect, mikrotik_creds
):
    """RouterOS will not take dst-port without a tcp/udp protocol, and
    "both" is this domain's own default -- so it is realized, not refused."""
    api = FakeRouterOSApi()
    patch_connect(api)

    await MikroTikAdapter().configure_port_forward(
        mikrotik_creds, rule=_forward(protocol="both")
    )

    rows = _nat_rows(api)
    assert sorted(str(row["protocol"]) for row in rows) == ["tcp", "udp"]
    assert sorted(str(row["comment"]) for row in rows) == [
        f"WyfyGuest PF {_PF_ID} tcp",
        f"WyfyGuest PF {_PF_ID} udp",
    ]


@pytest.mark.asyncio
async def test_re_pushing_a_both_protocol_rule_is_also_a_no_op(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_port_forward(
        mikrotik_creds, rule=_forward(protocol="both")
    )

    await adapter.configure_port_forward(
        mikrotik_creds, rule=_forward(protocol="both")
    )

    assert len(api.add_calls) == 2
    assert api.update_calls == []


@pytest.mark.asyncio
async def test_narrowing_both_to_tcp_reaps_the_udp_rule(
    patch_connect, mikrotik_creds
):
    """Left behind, the udp rule keeps forwarding a port the operator has
    stopped publishing on it."""
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_port_forward(
        mikrotik_creds, rule=_forward(protocol="both")
    )

    await adapter.configure_port_forward(
        mikrotik_creds, rule=_forward(protocol="tcp")
    )

    rows = _nat_rows(api)
    assert [str(row["protocol"]) for row in rows] == ["tcp"]


@pytest.mark.asyncio
async def test_delete_port_forward_removes_the_rule(patch_connect, mikrotik_creds):
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_port_forward(mikrotik_creds, rule=_forward())

    await adapter.delete_port_forward(mikrotik_creds, rule=_forward())

    assert _nat_rows(api) == []


@pytest.mark.asyncio
async def test_delete_finds_the_rule_by_id_not_by_its_current_values(
    patch_connect, mikrotik_creds
):
    """A row left from an earlier port is still this rule's row. Matching on
    what the row says now is how one gets orphaned -- still forwarding a
    public port, with nothing in this platform pointing at it."""
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_port_forward(mikrotik_creds, rule=_forward())

    await adapter.delete_port_forward(
        mikrotik_creds,
        rule=_forward(external_port=1, internal_ip="10.0.0.9", internal_port=1),
    )

    assert _nat_rows(api) == []


@pytest.mark.asyncio
async def test_deleting_twice_is_a_no_op(patch_connect, mikrotik_creds):
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_port_forward(mikrotik_creds, rule=_forward())
    await adapter.delete_port_forward(mikrotik_creds, rule=_forward())
    removes_after_first = len(api.remove_calls)

    await adapter.delete_port_forward(mikrotik_creds, rule=_forward())

    assert len(api.remove_calls) == removes_after_first
    assert _nat_rows(api) == []


@pytest.mark.asyncio
async def test_delete_removes_both_rules_of_a_both_protocol_rule(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_port_forward(
        mikrotik_creds, rule=_forward(protocol="both")
    )

    await adapter.delete_port_forward(mikrotik_creds, rule=_forward(protocol="both"))

    assert _nat_rows(api) == []


@pytest.mark.asyncio
async def test_another_rule_and_an_unrelated_masquerade_are_left_alone(
    patch_connect, mikrotik_creds
):
    """The comment scopes every write to one row. A second customer rule and
    the VLAN masquerade share the same ``/ip firewall nat`` menu."""
    other_id = "11111111-2222-3333-4444-555555555555"
    api = FakeRouterOSApi(
        menus={
            ("ip", "firewall", "nat"): [
                {
                    ".id": "*9",
                    "chain": "srcnat",
                    "action": "masquerade",
                    "src-address": "10.100.0.0/24",
                    "out-interface": "ether1",
                    "comment": "WyfyGuest VLAN 100",
                }
            ]
        }
    )
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_port_forward(mikrotik_creds, rule=_forward())
    await adapter.configure_port_forward(
        mikrotik_creds, rule=_forward(rule_id=other_id, external_port=2222)
    )

    await adapter.delete_port_forward(mikrotik_creds, rule=_forward())

    remaining = sorted(str(row.get("comment")) for row in _nat_rows(api))
    assert remaining == [
        f"WyfyGuest PF {other_id} tcp",
        "WyfyGuest VLAN 100",
    ]


@pytest.mark.asyncio
async def test_a_router_that_refuses_the_write_raises(patch_connect, mikrotik_creds):
    api = FakeRouterOSApi(missing_menus={("ip", "firewall", "nat")})
    patch_connect(api)

    with pytest.raises(MikroTikDeviceError) as excinfo:
        await MikroTikAdapter().configure_port_forward(
            mikrotik_creds, rule=_forward()
        )

    assert "configure_port_forward" in excinfo.value.detail


# ============================================================================
# Findings from the first hardware verification run. Every one of these was
# invisible to the fake-transport tests that shipped with the features --
# they asserted rows, and these are defects in *which* rows and *how often*.
# ============================================================================


@pytest.mark.asyncio
async def test_deleting_a_dhcp_pool_leaves_a_portals_network_row_alone(
    patch_connect, mikrotik_creds
):
    """The one that can break a live captive portal.

    Both features write an `/ip dhcp-server network` row, and RouterOS
    identifies that row by subnet alone. Observed on hardware: tearing down
    a DHCP pool removed the portal's row, taking its gateway and DNS with
    it -- no error, no warning. The portal then hands out addresses with no
    way off the subnet.
    """
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()

    await adapter.configure_vlan_hotspot(mikrotik_creds, hotspot=_hotspot())
    portal_rows = list(api.path("ip", "dhcp-server", "network"))
    assert len(portal_rows) == 1

    # A pool on the same subnet, torn down again.
    same_subnet = DhcpPoolConfig(
        interface="vlan100",
        range_start="10.100.0.20",
        range_end="10.100.0.30",
        gateway="10.100.0.1",
        dns_servers=["1.1.1.1"],
        lease_time_seconds=600,
    )
    await adapter.delete_dhcp_pool(mikrotik_creds, pool=same_subnet)

    surviving = list(api.path("ip", "dhcp-server", "network"))
    assert len(surviving) == 1, "the portal's network row was destroyed"
    assert surviving[0].get("gateway") == "10.100.0.1"


@pytest.mark.asyncio
async def test_a_network_row_we_did_not_write_is_never_removed(
    patch_connect, mikrotik_creds
):
    """A row with no marker was written by a human or an older build.
    Leaving a stale row is visible and correctable; deleting someone
    else's is silent and breaks a running service."""
    api = FakeRouterOSApi(
        menus={
            ("ip", "dhcp-server", "network"): [
                {".id": "*9", "address": "10.30.30.0/24", "gateway": "10.30.30.9"}
            ]
        }
    )
    patch_connect(api)

    await MikroTikAdapter().delete_dhcp_pool(
        mikrotik_creds,
        pool=DhcpPoolConfig(
            interface="vlan300",
            range_start="10.30.30.100",
            range_end="10.30.30.200",
            gateway="10.30.30.1",
            dns_servers=[],
            lease_time_seconds=600,
        ),
    )

    assert len(list(api.path("ip", "dhcp-server", "network"))) == 1


@pytest.mark.asyncio
async def test_an_interface_already_serving_dhcp_is_refused_before_anything_is_created(
    patch_connect, mikrotik_creds
):
    """Observed on hardware: the pool add succeeded, the server add failed
    with "server or relay with such interface already exists", and the pool
    was left orphaned with nothing referencing it -- while the caller
    recorded a failed push."""
    api = FakeRouterOSApi(
        menus={
            ("ip", "dhcp-server"): [
                {".id": "*1", "name": "someone-elses-dhcp", "interface": "vlan100"}
            ]
        }
    )
    patch_connect(api)

    with pytest.raises(MikroTikDeviceError):
        await MikroTikAdapter().configure_dhcp_pool(
            mikrotik_creds,
            pool=DhcpPoolConfig(
                interface="vlan100",
                range_start="10.100.0.20",
                range_end="10.100.0.30",
                gateway="10.100.0.1",
                dns_servers=[],
                lease_time_seconds=600,
            ),
        )

    assert list(api.path("ip", "pool")) == [], "an orphaned pool was left behind"
    assert api.add_calls == []


@pytest.mark.asyncio
async def test_lease_time_is_compared_as_a_duration_not_a_string(
    patch_connect, mikrotik_creds
):
    """RouterOS accepts `600s` and reads it back as `10m`. A string
    comparison can never match, so the guarded write re-issues its `set`
    on every push, forever. Observed on hardware."""
    api = FakeRouterOSApi(
        menus={
            ("ip", "dhcp-server"): [
                {
                    ".id": "*4",
                    "name": "vlan300-dhcp",
                    "interface": "vlan300",
                    "address-pool": "vlan300-pool",
                    "lease-time": "10m",      # what the device reports
                    "disabled": False,
                }
            ]
        }
    )
    patch_connect(api)

    await MikroTikAdapter().configure_dhcp_pool(
        mikrotik_creds,
        pool=DhcpPoolConfig(
            interface="vlan300",
            range_start="10.30.30.100",
            range_end="10.30.30.200",
            gateway="10.30.30.1",
            dns_servers=[],
            lease_time_seconds=600,           # what we send: "600s"
        ),
    )

    server_updates = [
        f for seg, f in api.update_calls if seg == ("ip", "dhcp-server")
    ]
    assert server_updates == [], f"pointless set re-issued: {server_updates}"


@pytest.mark.asyncio
async def test_html_directory_is_compared_as_a_path_not_a_string(
    patch_connect, mikrotik_creds
):
    """Written as `cloudguest-hotspot`, stored by RouterOS as
    `flash/cloudguest-hotspot`. Same defect as lease-time, same effect."""
    api = FakeRouterOSApi(
        menus={
            ("ip", "hotspot", "profile"): [
                {
                    ".id": "*2",
                    "name": "vlan100-hsprof",
                    "hotspot-address": "10.100.0.1",
                    "html-directory": "flash/cloudguest-hotspot",
                    "dns-name": "vlan100.wifi.example.com",
                    # An already-converged profile: RouterOS answers the read
                    # with a real bool for use-radius, which is why the
                    # comparison cannot be a string compare.
                    "use-radius": True,
                    "login-by": "http-pap",
                }
            ]
        }
    )
    patch_connect(api)

    await MikroTikAdapter().configure_vlan_hotspot(mikrotik_creds, hotspot=_hotspot())

    profile_updates = [
        f for seg, f in api.update_calls if seg == ("ip", "hotspot", "profile")
    ]
    assert profile_updates == [], f"pointless set re-issued: {profile_updates}"


def test_routeros_durations_that_mean_the_same_span_compare_equal():
    assert _same_routeros_duration("10m", "600s")
    assert _same_routeros_duration("1h", "3600s")
    assert _same_routeros_duration("1d", "86400s")
    assert _same_routeros_duration("600", "10m")     # bare seconds
    assert not _same_routeros_duration("10m", "601s")
    assert not _same_routeros_duration("none", "600s")
    assert not _same_routeros_duration(None, "600s")


def test_routeros_paths_that_name_the_same_directory_compare_equal():
    assert _same_routeros_path("flash/cloudguest-hotspot", "cloudguest-hotspot")
    assert _same_routeros_path("cloudguest-hotspot", "cloudguest-hotspot")
    assert not _same_routeros_path("flash/hotspot", "cloudguest-hotspot")
    assert not _same_routeros_path(None, "cloudguest-hotspot")


# ----------------------------------------------------------------------
# QoS packet marks -- the mangle half that had no writer at all until now.
# A queue tree referencing a mark nothing sets matches zero packets, so
# these assert the mark is written, kept identifiable across an edit, and
# torn down with its rule.
# ----------------------------------------------------------------------


def _qos_rule(**overrides):
    fields = {
        "rule_id": "rule-1",
        "packet_mark": "cloudguest-qos-rule-1",
        "label": "VoIP",
        "priority": 1,
        "protocol": "udp",
        "port_range_start": 10000,
        "port_range_end": 20000,
    }
    fields.update(overrides)
    return QosPacketMarkConfig(**fields)


@pytest.mark.asyncio
async def test_configure_qos_packet_mark_writes_the_port_range_match(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi()
    patch_connect(api)

    await MikroTikAdapter().configure_qos_packet_mark(mikrotik_creds, rule=_qos_rule())

    assert api.add_calls == [
        (
            ("ip", "firewall", "mangle"),
            {
                "chain": "prerouting",
                "protocol": "udp",
                "dst-port": "10000-20000",
                "action": "mark-packet",
                "new-packet-mark": "cloudguest-qos-rule-1",
                "passthrough": "no",
                "comment": "WyfyGuest qos rule-1: VoIP (priority=1)",
                "disabled": "no",
            },
        )
    ]


@pytest.mark.asyncio
async def test_configure_qos_packet_mark_dscp_rule_carries_no_port_match(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi()
    patch_connect(api)

    rule = _qos_rule(
        protocol=None, port_range_start=None, port_range_end=None, dscp_value=46
    )
    await MikroTikAdapter().configure_qos_packet_mark(mikrotik_creds, rule=rule)

    written = api.add_calls[0][1]
    assert written["dscp"] == "46"
    # A DSCP rule that also carried dst-port/protocol would keep matching
    # the ports the customer just stopped classifying by.
    assert "dst-port" not in written
    assert "protocol" not in written


@pytest.mark.asyncio
async def test_repushing_an_unchanged_qos_mark_writes_nothing(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()

    await adapter.configure_qos_packet_mark(mikrotik_creds, rule=_qos_rule())
    api.add_calls.clear()
    await adapter.configure_qos_packet_mark(mikrotik_creds, rule=_qos_rule())

    assert api.add_calls == []
    assert api.update_calls == []


@pytest.mark.asyncio
async def test_editing_the_label_updates_the_existing_qos_mark_in_place(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()

    await adapter.configure_qos_packet_mark(mikrotik_creds, rule=_qos_rule())
    api.add_calls.clear()
    await adapter.configure_qos_packet_mark(
        mikrotik_creds, rule=_qos_rule(label="Video calls")
    )

    # Found by the marker, not by the label -- so the rename edits the one
    # row rather than adding a second mangle rule beside it.
    assert api.add_calls == []
    assert len(api.update_calls) == 1
    assert (
        api.update_calls[0][1]["comment"]
        == "WyfyGuest qos rule-1: Video calls (priority=1)"
    )


@pytest.mark.asyncio
async def test_retyping_a_qos_rule_to_dscp_removes_the_port_range_row(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()

    await adapter.configure_qos_packet_mark(mikrotik_creds, rule=_qos_rule())
    api.add_calls.clear()
    await adapter.configure_qos_packet_mark(
        mikrotik_creds,
        rule=_qos_rule(
            protocol=None, port_range_start=None, port_range_end=None, dscp_value=46
        ),
    )

    # RouterOS has no "unset these fields", so the old row comes off rather
    # than being updated -- otherwise dst-port would still be matching.
    assert api.remove_calls
    rows = list(api.path("ip", "firewall", "mangle"))
    assert len(rows) == 1
    assert rows[0]["dscp"] == "46"
    assert rows[0].get("dst-port") in (None, "")


@pytest.mark.asyncio
async def test_delete_qos_packet_mark_leaves_other_rules_alone(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()

    await adapter.configure_qos_packet_mark(mikrotik_creds, rule=_qos_rule())
    await adapter.configure_qos_packet_mark(
        mikrotik_creds,
        rule=_qos_rule(
            rule_id="rule-2", packet_mark="cloudguest-qos-rule-2", label="Streaming"
        ),
    )
    # Somebody's own hand-written mangle rule, which this platform must
    # never touch.
    api.path("ip", "firewall", "mangle").add(
        chain="prerouting", action="mark-packet", comment="hand written, keep me"
    )

    await adapter.delete_qos_packet_mark(mikrotik_creds, rule_id="rule-1")

    comments = [row.get("comment") for row in api.path("ip", "firewall", "mangle")]
    assert comments == [
        "WyfyGuest qos rule-2: Streaming (priority=1)",
        "hand written, keep me",
    ]


@pytest.mark.asyncio
async def test_deleting_an_absent_qos_packet_mark_is_a_no_op(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi()
    patch_connect(api)

    await MikroTikAdapter().delete_qos_packet_mark(
        mikrotik_creds, rule_id="never-pushed"
    )

    assert api.remove_calls == []


# ----------------------------------------------------------------------
# Where the content-filter enforcement DROP lands in `forward`.
#
# The chain below is the real one read off the lab hEX lite (RouterOS
# 7.23.3): two dynamic hotspot jumps gated `!auth`, three cloudguest drops,
# then the established/related accept and the invalid drop. Placement is
# only buildable because device test T1 proved `place-before` takes a `.id`
# and T2 proved a static rule can sit above the dynamic rows.
# ----------------------------------------------------------------------

_ENFORCEMENT_COMMENT = "Wyfy Guest content filtering: block listed addresses"


def _lab_forward_chain() -> list[dict]:
    return [
        {".id": "*1", "chain": "forward", "action": "jump",
         "jump-target": "hs-unauth", "dynamic": "true"},
        {".id": "*2", "chain": "forward", "action": "jump",
         "jump-target": "hs-unauth-to", "dynamic": "true"},
        {".id": "*3", "chain": "forward", "action": "drop",
         "comment": "cloudguest-block-dot-udp"},
        {".id": "*4", "chain": "forward", "action": "drop",
         "comment": "cloudguest-block-doh"},
        {".id": "*5", "chain": "forward", "action": "accept",
         "comment": "cloudguest-fw-fwd-established",
         "connection-state": "established,related"},
        {".id": "*6", "chain": "forward", "action": "drop",
         "comment": "cloudguest-fw-fwd-drop-invalid",
         "connection-state": "invalid"},
    ]


def _forward_comments(api) -> list[str]:
    return [
        row.get("comment") or f"<{row.get('action')}>"
        for row in api.path("ip", "firewall", "filter")
        if str(row.get("chain", "")) == "forward"
    ]


@pytest.mark.asyncio
async def test_enforcement_drop_lands_above_the_first_accept(
    patch_connect, mikrotik_creds
):
    """Below the established/related accept, a block only bites on a *new*
    connection -- a flow already open when the customer pressed Block keeps
    flowing. Above it, the block applies to traffic already in flight."""
    api = FakeRouterOSApi(menus={("ip", "firewall", "filter"): _lab_forward_chain()})
    patch_connect(api)

    await MikroTikAdapter().configure_content_filter_rule(
        mikrotik_creds, rule=_cidr_rule()
    )

    order = _forward_comments(api)
    assert order.index(_ENFORCEMENT_COMMENT) < order.index(
        "cloudguest-fw-fwd-established"
    )
    # And above the accept means above it only -- the hotspot jumps and the
    # drops in front of it are untouched.
    assert order[:4] == [
        "<jump>", "<jump>", "cloudguest-block-dot-udp", "cloudguest-block-doh",
    ]


@pytest.mark.asyncio
async def test_enforcement_drop_is_placed_by_id_not_by_an_index(
    patch_connect, mikrotik_creds
):
    """An ordinal goes stale the moment the hotspot adds or removes one of
    its dynamic rules. T1 established that `place-before` takes a `.id`."""
    api = FakeRouterOSApi(menus={("ip", "firewall", "filter"): _lab_forward_chain()})
    patch_connect(api)

    await MikroTikAdapter().configure_content_filter_rule(
        mikrotik_creds, rule=_cidr_rule()
    )

    filter_adds = [
        fields for segments, fields in api.add_calls
        if segments == ("ip", "firewall", "filter")
    ]
    assert filter_adds[0]["place-before"] == "*5"  # the accept's own .id


@pytest.mark.asyncio
async def test_a_misplaced_enforcement_drop_is_moved_up_on_the_next_push(
    patch_connect, mikrotik_creds
):
    """The defect this closes: the rule used to be appended once and then
    never re-checked, so a router carrying it at the bottom stayed that way
    forever."""
    chain = _lab_forward_chain()
    chain.append(
        {".id": "*9", "chain": "forward", "action": "drop",
         "dst-address-list": "wyfyguest-content-filter-blocked",
         "comment": _ENFORCEMENT_COMMENT}
    )
    api = FakeRouterOSApi(menus={("ip", "firewall", "filter"): chain})
    patch_connect(api)

    await MikroTikAdapter().configure_content_filter_rule(
        mikrotik_creds, rule=_cidr_rule()
    )

    order = _forward_comments(api)
    assert order.count(_ENFORCEMENT_COMMENT) == 1
    assert order.index(_ENFORCEMENT_COMMENT) < order.index(
        "cloudguest-fw-fwd-established"
    )
    # Added before the stale row was removed: the chain is never left with
    # no DROP at all. This is a control that must fail closed, so the
    # ordering is asserted against the interleaved log rather than inferred
    # from two separate ones.
    filter_ops = [
        (op, payload)
        for op, segments, payload in api.ops
        if segments == ("ip", "firewall", "filter")
    ]
    assert [op for op, _ in filter_ops] == ["add", "remove"]
    assert filter_ops[1][1] == ("*9",)


@pytest.mark.asyncio
async def test_a_correctly_placed_enforcement_drop_is_left_alone(
    patch_connect, mikrotik_creds
):
    """Re-pushing must not churn the chain: no add, no remove."""
    chain = _lab_forward_chain()
    chain.insert(
        4,
        {".id": "*9", "chain": "forward", "action": "drop",
         "dst-address-list": "wyfyguest-content-filter-blocked",
         "comment": _ENFORCEMENT_COMMENT},
    )
    api = FakeRouterOSApi(menus={("ip", "firewall", "filter"): chain})
    patch_connect(api)

    await MikroTikAdapter().configure_content_filter_rule(
        mikrotik_creds, rule=_cidr_rule()
    )

    filter_writes = [
        segments for segments, _ in api.add_calls
        if segments == ("ip", "firewall", "filter")
    ]
    assert filter_writes == []
    assert [s for s, _ in api.remove_calls if s == ("ip", "firewall", "filter")] == []


@pytest.mark.asyncio
async def test_with_no_accept_in_forward_the_drop_is_appended(
    patch_connect, mikrotik_creds
):
    """Nothing to sit above, so the bottom is where it belongs -- and no
    `place-before` is sent at all."""
    chain = [
        row for row in _lab_forward_chain() if row["action"] != "accept"
    ]
    api = FakeRouterOSApi(menus={("ip", "firewall", "filter"): chain})
    patch_connect(api)

    await MikroTikAdapter().configure_content_filter_rule(
        mikrotik_creds, rule=_cidr_rule()
    )

    filter_adds = [
        fields for segments, fields in api.add_calls
        if segments == ("ip", "firewall", "filter")
    ]
    assert "place-before" not in filter_adds[0]
    assert _forward_comments(api)[-1] == _ENFORCEMENT_COMMENT


# ----------------------------------------------------------------------
# The /radius NAS registration and its CoA listener.
#
# This writer existed with zero callers in app/ and no test at all. Wiring
# it up as it stood would have added a second /radius row on every push,
# and registered a client with no src-address -- which the hub's
# FreeRADIUS matches on, so it could never have authenticated.
# ----------------------------------------------------------------------

_RADIUS_COMMENT = "WyfyGuest RADIUS NAS client"


def _radius_config(**overrides):
    fields = {
        "radius_server_host": "10.20.0.1",
        "radius_secret": "s3cret",
        "src_address": "10.20.0.14",
    }
    fields.update(overrides)
    return RadiusClientConfig(**fields)


def _radius_rows(api):
    return list(api.path("radius"))


@pytest.mark.asyncio
async def test_radius_registration_carries_the_tunnel_source_address(
    patch_connect, mikrotik_creds
):
    """The hub matches a request to a client{} stanza by source address, so
    a row without it is a registration that cannot authenticate."""
    api = FakeRouterOSApi()
    patch_connect(api)

    await MikroTikAdapter().set_radius_client_config(
        mikrotik_creds, config=_radius_config()
    )

    written = next(
        fields for segments, fields in api.add_calls if segments == ("radius",)
    )
    assert written["src-address"] == "10.20.0.14"
    assert written["service"] == "hotspot"
    assert written["comment"] == _RADIUS_COMMENT


@pytest.mark.asyncio
async def test_a_second_push_does_not_add_a_second_radius_row(
    patch_connect, mikrotik_creds
):
    # A real router always carries exactly one /radius incoming row -- it is
    # a settings object, not a list -- so the fake is given one. Starting it
    # empty would model a device that cannot exist.
    api = FakeRouterOSApi(
        menus={("radius", "incoming"): [
            {".id": "*1", "accept": False, "port": "1700"}
        ]}
    )
    patch_connect(api)
    adapter = MikroTikAdapter()

    await adapter.set_radius_client_config(mikrotik_creds, config=_radius_config())
    api.add_calls.clear()
    api.update_calls.clear()
    await adapter.set_radius_client_config(mikrotik_creds, config=_radius_config())

    assert len(_radius_rows(api)) == 1
    assert api.add_calls == []
    assert api.update_calls == []


@pytest.mark.asyncio
async def test_an_existing_hand_written_row_is_adopted_not_duplicated(
    patch_connect, mikrotik_creds
):
    """The lab router's row carries `comment=cloudguest-radius`, which this
    codebase has never written -- somebody set it by hand. Keyed on our own
    comment we would not find it and would add a second registration for
    the same server."""
    api = FakeRouterOSApi(
        menus={
            ("radius",): [
                {".id": "*1", "service": "hotspot", "address": "10.20.0.1",
                 "secret": "old", "authentication-port": "1812",
                 "accounting-port": "1813", "comment": "cloudguest-radius"}
            ]
        }
    )
    patch_connect(api)

    await MikroTikAdapter().set_radius_client_config(
        mikrotik_creds, config=_radius_config()
    )

    rows = _radius_rows(api)
    assert len(rows) == 1
    assert rows[0][".id"] == "*1"  # the same row, not a replacement
    assert rows[0]["src-address"] == "10.20.0.14"
    assert rows[0]["secret"] == "s3cret"
    assert rows[0]["comment"] == _RADIUS_COMMENT  # ours from now on


@pytest.mark.asyncio
async def test_a_radius_row_for_a_different_server_is_left_alone(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi(
        menus={
            ("radius",): [
                {".id": "*1", "service": "hotspot", "address": "192.0.2.9",
                 "secret": "someone-elses", "comment": "not ours"}
            ]
        }
    )
    patch_connect(api)

    await MikroTikAdapter().set_radius_client_config(
        mikrotik_creds, config=_radius_config()
    )

    rows = _radius_rows(api)
    assert len(rows) == 2
    untouched = next(r for r in rows if r[".id"] == "*1")
    assert untouched["secret"] == "someone-elses"
    assert untouched["comment"] == "not ours"


@pytest.mark.asyncio
async def test_coa_listener_is_enabled_on_the_documented_port(
    patch_connect, mikrotik_creds
):
    """RouterOS's own default is 1700; 3799 is the RFC-assigned port and
    what this platform writes."""
    api = FakeRouterOSApi(
        menus={("radius", "incoming"): [
            {".id": "*1", "accept": False, "port": "1700"}
        ]}
    )
    patch_connect(api)

    await MikroTikAdapter().set_radius_client_config(
        mikrotik_creds, config=_radius_config()
    )

    written = next(
        fields for segments, fields in api.update_calls
        if segments == ("radius", "incoming")
    )
    assert written == {"accept": "yes", "port": "3799"}


@pytest.mark.asyncio
async def test_an_already_enabled_coa_listener_is_not_rewritten(
    patch_connect, mikrotik_creds
):
    """`accept` reads back as a real bool. A string compare would see a
    live True as disabled and rewrite it on every single push."""
    api = FakeRouterOSApi(
        menus={("radius", "incoming"): [
            {".id": "*1", "accept": True, "port": "3799"}
        ]}
    )
    patch_connect(api)

    await MikroTikAdapter().set_radius_client_config(
        mikrotik_creds, config=_radius_config()
    )

    assert [
        s for s, _ in api.update_calls if s == ("radius", "incoming")
    ] == []


# ----------------------------------------------------------------------
# Access-mode VLAN: giving the port back.
#
# Access mode pulls a physical port out of its bridge. Until `VlanConfig`
# carried `previous_bridge`, delete left it unbridged -- a venue's access
# point sat on a dead port with the guest network down until an engineer
# restored it by hand.
# ----------------------------------------------------------------------


def _bridged(*interfaces, bridge="bridge", pvid="1"):
    return [
        {".id": f"*{i + 1}", "interface": name, "bridge": bridge, "pvid": pvid}
        for i, name in enumerate(interfaces)
    ]


@pytest.mark.asyncio
async def test_deleting_an_access_vlan_returns_the_port_to_its_bridge(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi(
        menus={
            ("interface", "bridge", "port"): _bridged("ether3", "ether4"),
            ("ip", "address"): [
                {".id": "*9", "address": "10.30.30.1/24", "interface": "ether2"}
            ],
        }
    )
    patch_connect(api)

    await MikroTikAdapter().delete_vlan(
        mikrotik_creds,
        vlan=VlanConfig(
            vlan_id=100,
            name="admin",
            interface="ether2",
            ip_cidr="10.30.30.1/24",
            port_mode="access",
            previous_bridge="bridge",
        ),
    )

    members = {
        str(r.get("interface")): str(r.get("bridge"))
        for r in api.path("interface", "bridge", "port")
    }
    assert members["ether2"] == "bridge"
    # And the address it was given is gone.
    assert [r for r in api.path("ip", "address")] == []


@pytest.mark.asyncio
async def test_the_restored_port_copies_its_siblings_pvid(
    patch_connect, mikrotik_creds
):
    """On a VLAN-filtering bridge the siblings' pvid is what makes untagged
    ingress land where the rest of that segment lands. Defaulting to 1 would
    be a guess dressed as a default."""
    api = FakeRouterOSApi(
        menus={
            ("interface", "bridge", "port"): _bridged("ether3", pvid="20"),
        }
    )
    patch_connect(api)

    await MikroTikAdapter().delete_vlan(
        mikrotik_creds,
        vlan=VlanConfig(
            vlan_id=100, name="admin", interface="ether2", ip_cidr=None,
            port_mode="access", previous_bridge="bridge",
        ),
    )

    added = next(
        fields for segments, fields in api.add_calls
        if segments == ("interface", "bridge", "port")
    )
    assert added["pvid"] == "20"


@pytest.mark.asyncio
async def test_without_a_recorded_bridge_the_port_is_left_unbridged(
    patch_connect, mikrotik_creds
):
    """`None` is the truthful previous state for a port that was in no
    bridge -- rejoining a guessed one would put it on the wrong segment."""
    api = FakeRouterOSApi(
        menus={("interface", "bridge", "port"): _bridged("ether3")}
    )
    patch_connect(api)

    await MikroTikAdapter().delete_vlan(
        mikrotik_creds,
        vlan=VlanConfig(
            vlan_id=100, name="admin", interface="ether2", ip_cidr=None,
            port_mode="access", previous_bridge=None,
        ),
    )

    assert [s for s, _ in api.add_calls if s == ("interface", "bridge", "port")] == []


@pytest.mark.asyncio
async def test_a_port_somebody_already_restored_is_not_added_twice(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi(
        menus={("interface", "bridge", "port"): _bridged("ether3", "ether2")}
    )
    patch_connect(api)

    await MikroTikAdapter().delete_vlan(
        mikrotik_creds,
        vlan=VlanConfig(
            vlan_id=100, name="admin", interface="ether2", ip_cidr=None,
            port_mode="access", previous_bridge="bridge",
        ),
    )

    members = [str(r.get("interface")) for r in api.path("interface", "bridge", "port")]
    assert members.count("ether2") == 1
    assert [s for s, _ in api.add_calls if s == ("interface", "bridge", "port")] == []


@pytest.mark.asyncio
async def test_a_vlan_portal_is_created_able_to_authenticate(
    patch_connect, mikrotik_creds
):
    """RouterOS defaults a new profile to `use-radius=no
    login-by=cookie,http-chap`. A portal created that way renders its page
    and can never accept an OTP, voucher or password, because it checks the
    credential against nothing. Observed on the lab router as
    `vlan95-hsprof use-radius=False`."""
    api = FakeRouterOSApi()
    patch_connect(api)

    await MikroTikAdapter().configure_vlan_hotspot(
        mikrotik_creds,
        hotspot=VlanHotspotConfig(
            vlan_id=100,
            interface="vlan100",
            cidr="10.100.0.0/24",
            gateway="10.100.0.1",
            dns_name="vlan100.wifi.example.com",
            html_directory="cloudguest-hotspot",
        ),
    )

    profile = next(
        fields for segments, fields in api.add_calls
        if segments == ("ip", "hotspot", "profile")
    )
    assert profile["use-radius"] == "yes"
    # http-pap, not CHAP: the portal posts the credential, which CHAP's
    # challenge flow does not carry.
    assert profile["login-by"] == "http-pap"


@pytest.mark.asyncio
async def test_use_radius_is_compared_as_a_bool_not_a_string(
    patch_connect, mikrotik_creds
):
    """The API answers the read with a real bool and accepts "yes" on write.
    Compared as strings, `True != "yes"` and every push re-issues the same
    set forever -- the trap already documented for `disabled` and
    `lease-time`."""
    api = FakeRouterOSApi(
        menus={
            ("ip", "hotspot", "profile"): [
                {
                    ".id": "*2",
                    "name": "vlan100-hsprof",
                    "hotspot-address": "10.100.0.1",
                    "html-directory": "flash/cloudguest-hotspot",
                    "dns-name": "vlan100.wifi.example.com",
                    "use-radius": True,
                    "login-by": "http-pap",
                }
            ]
        }
    )
    patch_connect(api)

    await MikroTikAdapter().configure_vlan_hotspot(
        mikrotik_creds,
        hotspot=VlanHotspotConfig(
            vlan_id=100,
            interface="vlan100",
            cidr="10.100.0.0/24",
            gateway="10.100.0.1",
            dns_name="vlan100.wifi.example.com",
            html_directory="cloudguest-hotspot",
        ),
    )

    assert [
        f for s, f in api.update_calls if s == ("ip", "hotspot", "profile")
    ] == []


# ----------------------------------------------------------------------
# Rogue DHCP detection -- `/ip dhcp-server alert`.
#
# A consumer router in factory configuration appeared on the lab guest
# bridge claiming the WAN gateway's address; a box in that state usually
# serves DHCP too, and a rogue DHCP server wins whenever it answers first.
# The alert only logs -- it blocks nothing -- so what these tests are
# really guarding is that it is actually *on*: RouterOS creates the row
# disabled by default, and a present-but-disabled alert reads in the
# configuration exactly like a guarded router while watching nothing.
# ----------------------------------------------------------------------

ROUTER_MAC = "48:A9:8A:11:22:33"


def _alert(interface: str = "bridge", **overrides) -> RogueDhcpAlertConfig:
    fields = {
        "interface": interface,
        "valid_servers": (ROUTER_MAC,),
        "alert_timeout": "1h",
    }
    fields.update(overrides)
    return RogueDhcpAlertConfig(**fields)


def _dhcp_menus(*interfaces: str, disabled: tuple[str, ...] = ()) -> dict:
    return {
        ("ip", "dhcp-server"): [
            {
                ".id": f"*{index + 1}",
                "name": f"{name}-dhcp",
                "interface": name,
                "disabled": name in disabled,
            }
            for index, name in enumerate(interfaces)
        ]
    }


@pytest.mark.asyncio
async def test_rogue_dhcp_alert_is_created_explicitly_enabled(
    patch_connect, mikrotik_creds
):
    """RouterOS creates an alert row DISABLED unless told otherwise. The
    first by-hand attempt on the lab router left three alerts present and
    switched off -- guarding nothing while looking guarded."""
    api = FakeRouterOSApi(menus=_dhcp_menus("bridge"))
    patch_connect(api)

    await MikroTikAdapter().configure_rogue_dhcp_alerts(
        mikrotik_creds, alerts=[_alert("bridge")]
    )

    assert api.add_calls == [
        (
            ("ip", "dhcp-server", "alert"),
            {
                "interface": "bridge",
                "valid-server": ROUTER_MAC,
                "comment": "cloudguest-rogue-dhcp-watch",
                "alert-timeout": "1h",
                "disabled": "no",
            },
        )
    ]


@pytest.mark.asyncio
async def test_repushing_an_unchanged_rogue_dhcp_alert_writes_nothing(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi(menus=_dhcp_menus("bridge", "vlan12", "vlan95"))
    patch_connect(api)
    adapter = MikroTikAdapter()
    alerts = [_alert("bridge"), _alert("vlan12"), _alert("vlan95")]

    await adapter.configure_rogue_dhcp_alerts(mikrotik_creds, alerts=alerts)
    api.add_calls.clear()
    await adapter.configure_rogue_dhcp_alerts(mikrotik_creds, alerts=alerts)

    assert api.add_calls == []
    assert api.update_calls == []
    assert api.remove_calls == []


@pytest.mark.asyncio
async def test_an_alert_somebody_left_disabled_is_switched_back_on(
    patch_connect, mikrotik_creds
):
    """The worst of the three states: present, so a config review passes,
    and off, so nothing is watched. Enabling it must not depend on any
    other field having changed."""
    api = FakeRouterOSApi(
        menus={
            **_dhcp_menus("bridge"),
            ("ip", "dhcp-server", "alert"): [
                {
                    ".id": "*7",
                    "interface": "bridge",
                    "valid-server": ROUTER_MAC,
                    "alert-timeout": "1h",
                    "comment": "cloudguest-rogue-dhcp-watch",
                    # A real bool, the way the API answers a read.
                    "disabled": True,
                }
            ],
        }
    )
    patch_connect(api)

    await MikroTikAdapter().configure_rogue_dhcp_alerts(
        mikrotik_creds, alerts=[_alert("bridge")]
    )

    assert api.add_calls == []
    assert api.update_calls == [
        (("ip", "dhcp-server", "alert"), {".id": "*7", "disabled": "no"})
    ]


@pytest.mark.asyncio
async def test_no_alert_is_created_for_an_interface_with_no_dhcp_server(
    patch_connect, mikrotik_creds
):
    """An interface this router serves no DHCP on has no offer of our own
    to compare an unknown one against, so an alert there would report
    legitimate neighbours."""
    api = FakeRouterOSApi(menus=_dhcp_menus("bridge"))
    patch_connect(api)

    await MikroTikAdapter().configure_rogue_dhcp_alerts(
        mikrotik_creds, alerts=[_alert("bridge"), _alert("ether5")]
    )

    assert [fields["interface"] for _, fields in api.add_calls] == ["bridge"]


@pytest.mark.asyncio
async def test_a_disabled_dhcp_server_does_not_count_as_serving(
    patch_connect, mikrotik_creds
):
    """`disabled` through `_is_truthy`, not a string compare -- a switched
    off server hands out nothing."""
    api = FakeRouterOSApi(menus=_dhcp_menus("bridge", disabled=("bridge",)))
    patch_connect(api)

    await MikroTikAdapter().configure_rogue_dhcp_alerts(
        mikrotik_creds, alerts=[_alert("bridge")]
    )

    assert api.add_calls == []


@pytest.mark.asyncio
async def test_valid_server_case_and_order_do_not_re_issue_the_same_set(
    patch_connect, mikrotik_creds
):
    """RouterOS answers with its own uppercase form and its own order. A
    string compare on this field is the `disabled`/`lease-time` trap in a
    third shape: the identical `set` re-issued on every push, forever."""
    api = FakeRouterOSApi(
        menus={
            **_dhcp_menus("bridge"),
            ("ip", "dhcp-server", "alert"): [
                {
                    ".id": "*7",
                    "interface": "bridge",
                    "valid-server": f"{ROUTER_MAC},48:A9:8A:44:55:66",
                    "alert-timeout": "1h",
                    "comment": "cloudguest-rogue-dhcp-watch",
                    "disabled": False,
                }
            ],
        }
    )
    patch_connect(api)

    await MikroTikAdapter().configure_rogue_dhcp_alerts(
        mikrotik_creds,
        alerts=[
            _alert("bridge", valid_servers=("48:a9:8a:44:55:66", ROUTER_MAC.lower()))
        ],
    )

    assert api.update_calls == []


@pytest.mark.asyncio
async def test_alert_timeout_is_compared_as_a_duration_not_a_string(
    patch_connect, mikrotik_creds
):
    """`60m` and `1h` are the same hour; RouterOS stores one and reads back
    the other."""
    api = FakeRouterOSApi(
        menus={
            **_dhcp_menus("bridge"),
            ("ip", "dhcp-server", "alert"): [
                {
                    ".id": "*7",
                    "interface": "bridge",
                    "valid-server": ROUTER_MAC,
                    "alert-timeout": "1h",
                    "comment": "cloudguest-rogue-dhcp-watch",
                    "disabled": False,
                }
            ],
        }
    )
    patch_connect(api)

    await MikroTikAdapter().configure_rogue_dhcp_alerts(
        mikrotik_creds, alerts=[_alert("bridge", alert_timeout="60m")]
    )

    assert api.update_calls == []


@pytest.mark.asyncio
async def test_an_existing_unmarked_alert_is_adopted_not_duplicated(
    patch_connect, mikrotik_creds
):
    """RouterOS holds one alert per interface, so the interface -- not our
    comment -- is the row's identity. A row the hand-run probe or a person
    placed is stamped and corrected in place; a second row beside it would
    be a duplicate at best and a rejected write at worst."""
    api = FakeRouterOSApi(
        menus={
            **_dhcp_menus("bridge"),
            ("ip", "dhcp-server", "alert"): [
                {
                    ".id": "*7",
                    "interface": "bridge",
                    "valid-server": "00:00:00:00:00:01",
                    "disabled": True,
                }
            ],
        }
    )
    patch_connect(api)

    await MikroTikAdapter().configure_rogue_dhcp_alerts(
        mikrotik_creds, alerts=[_alert("bridge")]
    )

    assert api.add_calls == []
    assert api.update_calls[0][1] == {
        ".id": "*7",
        "valid-server": ROUTER_MAC,
        "comment": "cloudguest-rogue-dhcp-watch",
        "alert-timeout": "1h",
        "disabled": "no",
    }


@pytest.mark.asyncio
async def test_alert_with_no_valid_servers_is_refused_before_any_write(
    patch_connect, mikrotik_creds
):
    """An alert that trusts nobody reports every legitimate lease, which is
    how a real alert gets ignored. Refused for the whole request, so a bad
    entry cannot leave half the interfaces watched."""
    api = FakeRouterOSApi(menus=_dhcp_menus("bridge", "vlan12"))
    patch_connect(api)

    with pytest.raises(MikroTikDeviceError, match="no valid_servers"):
        await MikroTikAdapter().configure_rogue_dhcp_alerts(
            mikrotik_creds,
            alerts=[_alert("bridge"), _alert("vlan12", valid_servers=())],
        )

    assert api.add_calls == []


@pytest.mark.asyncio
async def test_a_valid_server_that_is_not_a_mac_is_refused(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi(menus=_dhcp_menus("bridge"))
    patch_connect(api)

    with pytest.raises(MikroTikDeviceError, match="not a MAC address"):
        await MikroTikAdapter().configure_rogue_dhcp_alerts(
            mikrotik_creds, alerts=[_alert("bridge", valid_servers=("192.168.1.1",))]
        )

    assert api.add_calls == []


@pytest.mark.asyncio
async def test_two_alerts_for_one_interface_are_refused(patch_connect, mikrotik_creds):
    api = FakeRouterOSApi(menus=_dhcp_menus("bridge"))
    patch_connect(api)

    with pytest.raises(MikroTikDeviceError, match="one per interface"):
        await MikroTikAdapter().configure_rogue_dhcp_alerts(
            mikrotik_creds,
            alerts=[_alert("bridge"), _alert("bridge", valid_servers=(ROUTER_MAC,))],
        )

    assert api.add_calls == []


@pytest.mark.asyncio
async def test_read_reports_a_dhcp_interface_with_no_alert_as_unguarded(
    patch_connect, mikrotik_creds
):
    """The finding worth having, and the one with no row of its own to be
    listed by: this segment hands out addresses and nothing watches it."""
    api = FakeRouterOSApi(menus=_dhcp_menus("bridge", "vlan12"))
    patch_connect(api)

    statuses = await MikroTikAdapter().read_rogue_dhcp_alerts(mikrotik_creds)

    assert [s.interface for s in statuses] == ["bridge", "vlan12"]
    assert all(s.serves_dhcp and not s.alert_present for s in statuses)
    assert not any(s.guarded for s in statuses)


@pytest.mark.asyncio
async def test_read_reports_a_present_but_disabled_alert_as_not_guarded(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi(
        menus={
            **_dhcp_menus("bridge"),
            ("ip", "dhcp-server", "alert"): [
                {
                    ".id": "*7",
                    "interface": "bridge",
                    "valid-server": ROUTER_MAC.lower(),
                    "alert-timeout": "1h",
                    "comment": "cloudguest-rogue-dhcp-watch",
                    "disabled": True,
                    "unknown-server": "AA:BB:CC:DD:EE:FF",
                }
            ],
        }
    )
    patch_connect(api)

    (status,) = await MikroTikAdapter().read_rogue_dhcp_alerts(mikrotik_creds)

    assert status.alert_present is True
    assert status.enabled is False
    assert status.guarded is False
    assert status.managed is True
    assert status.valid_servers == (ROUTER_MAC,)
    # What the router already saw answering that it does not trust -- the
    # one field here that is evidence rather than configuration.
    assert status.unknown_server == "AA:BB:CC:DD:EE:FF"


@pytest.mark.asyncio
async def test_read_reports_an_enabled_alert_as_guarded_and_writes_nothing(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi(
        menus={
            **_dhcp_menus("bridge"),
            ("ip", "dhcp-server", "alert"): [
                {
                    ".id": "*7",
                    "interface": "bridge",
                    "valid-server": ROUTER_MAC,
                    "comment": "somebody else's row",
                    "disabled": False,
                }
            ],
        }
    )
    patch_connect(api)

    (status,) = await MikroTikAdapter().read_rogue_dhcp_alerts(mikrotik_creds)

    assert status.guarded is True
    # Provenance is reported, not corrected: this is the read path.
    assert status.managed is False
    assert api.ops == []
