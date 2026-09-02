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
