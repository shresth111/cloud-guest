"""Write operations ported from ``network_config/renderers.py``'s real
RouterOS command shapes (``/interface vlan add``, ``/ip address add``,
``/ip pool add``, ``/ip dhcp-server add``, ``/ip dhcp-server network
add``), issued directly over the structured API instead of as script
text."""

from __future__ import annotations

import pytest

from tests.fake_write_transport import FakeRouterOSApi
from wyfy_device_gateway.contract import DhcpPoolConfig, VlanConfig
from wyfy_device_gateway.mikrotik_adapter import MikroTikAdapter


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
