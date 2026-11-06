"""Reading the router's own address pools: ``/ip pool`` joined to the DHCP
server that hands each one out and the network row that covers it, against
a fake RouterOS API.

Most routers' pool was made by the setup script, not the platform, so this
read is the only way the IP Addresses page can show what guests get.
"""

from __future__ import annotations

import pytest

from tests.fake_write_transport import FakeRouterOSApi
from wyfy_device_gateway.mikrotik_adapter import MikroTikAdapter, MikroTikDeviceError

_POOL = ("ip", "pool")
_SERVER = ("ip", "dhcp-server")
_NETWORK = ("ip", "dhcp-server", "network")


def _api(pools, servers, networks) -> FakeRouterOSApi:
    return FakeRouterOSApi(
        menus={
            _POOL: [dict(r) for r in pools],
            _SERVER: [dict(r) for r in servers],
            _NETWORK: [dict(r) for r in networks],
        }
    )


async def test_pool_is_joined_to_its_server_and_network(patch_connect, mikrotik_creds):
    api = _api(
        pools=[
            {".id": "*1", "name": "hs-pool", "ranges": "10.5.50.2-10.5.50.254"},
            {".id": "*2", "name": "spare", "ranges": "172.16.0.10-172.16.0.20"},
        ],
        servers=[
            {
                ".id": "*A",
                "name": "dhcp-guest",
                "interface": "bridge-guest",
                "address-pool": "hs-pool",
                "lease-time": "1h",
                "disabled": "false",
            }
        ],
        networks=[
            {".id": "*N", "address": "10.5.50.0/24", "gateway": "10.5.50.1", "dns-server": "10.5.50.1,8.8.8.8"}
        ],
    )
    patch_connect(api)
    pools = await MikroTikAdapter().read_dhcp_pools(mikrotik_creds)

    assert [p.pool_name for p in pools] == ["hs-pool", "spare"]
    hs, spare = pools
    assert hs.ranges == ("10.5.50.2-10.5.50.254",)
    assert (hs.server, hs.interface, hs.lease_time) == ("dhcp-guest", "bridge-guest", "1h")
    assert hs.server_disabled is False
    assert (hs.network, hs.gateway) == ("10.5.50.0/24", "10.5.50.1")
    assert hs.dns_servers == ("10.5.50.1", "8.8.8.8")
    # A pool no server uses is still reported, with nothing invented for it.
    assert (spare.server, spare.interface, spare.network, spare.gateway) == (None, None, None, None)
    assert spare.dns_servers == ()
    assert api.closed
    assert [op for op in api.ops if op[0] != "command"] == []


async def test_multi_range_and_cidr_pools_find_their_network(patch_connect, mikrotik_creds):
    api = _api(
        pools=[
            {".id": "*1", "name": "lan", "ranges": "192.168.88.10-192.168.88.100,192.168.88.150-192.168.88.200"},
            {".id": "*2", "name": "cidr", "ranges": "10.9.0.0/24"},
        ],
        servers=[],
        networks=[
            {".id": "*N1", "address": "192.168.88.0/24", "gateway": "192.168.88.1"},
            {".id": "*N2", "address": "10.9.0.0/24", "gateway": "10.9.0.1"},
        ],
    )
    patch_connect(api)
    lan, cidr = await MikroTikAdapter().read_dhcp_pools(mikrotik_creds)
    assert lan.ranges == ("192.168.88.10-192.168.88.100", "192.168.88.150-192.168.88.200")
    assert lan.gateway == "192.168.88.1"
    assert cidr.gateway == "10.9.0.1"


async def test_failed_read_raises_rather_than_answering_empty(patch_connect, mikrotik_creds):
    api = FakeRouterOSApi(menus={_POOL: [], _SERVER: []}, missing_menus={_NETWORK})
    patch_connect(api)
    with pytest.raises(MikroTikDeviceError):
        await MikroTikAdapter().read_dhcp_pools(mikrotik_creds)


# --------------------------------------------------------------------------
# Editing the router's own pool in place (the setup script's hotspot-pool)
# --------------------------------------------------------------------------


def _hotspot_router() -> FakeRouterOSApi:
    return _api(
        pools=[{".id": "*1", "name": "hotspot-pool", "ranges": "10.5.50.10-10.5.50.254"}],
        servers=[
            {
                ".id": "*A",
                "name": "dhcp1",
                "interface": "bridge",
                "address-pool": "hotspot-pool",
                "lease-time": "30m",
            }
        ],
        networks=[
            {".id": "*N", "address": "10.5.50.0/24", "gateway": "10.5.50.1", "dns-server": "10.5.50.1"}
        ],
    )


def _menu(api: FakeRouterOSApi, path) -> list[dict]:
    return list(api.path(*path))


async def test_edit_changes_the_existing_rows_in_place(patch_connect, mikrotik_creds):
    api = _hotspot_router()
    patch_connect(api)
    state = await MikroTikAdapter().update_dhcp_pool_in_place(
        mikrotik_creds,
        pool_name="hotspot-pool",
        ranges="10.5.50.20-10.5.50.200",
        lease_time="1h",
        dns_servers=("1.1.1.1", "8.8.8.8"),
    )
    assert state.ranges == ("10.5.50.20-10.5.50.200",)
    assert state.lease_time == "1h"
    assert state.dns_servers == ("1.1.1.1", "8.8.8.8")
    # Same rows, edited -- nothing added, gateway and network untouched.
    assert [op for op in api.ops if op[0] == "add"] == []
    assert [p["name"] for p in _menu(api, _POOL)] == ["hotspot-pool"]
    assert [s["name"] for s in _menu(api, _SERVER)] == ["dhcp1"]
    net = _menu(api, _NETWORK)[0]
    assert (net["address"], net["gateway"]) == ("10.5.50.0/24", "10.5.50.1")


async def test_unchanged_fields_are_not_written(patch_connect, mikrotik_creds):
    api = _hotspot_router()
    patch_connect(api)
    await MikroTikAdapter().update_dhcp_pool_in_place(
        mikrotik_creds,
        pool_name="hotspot-pool",
        ranges="10.5.50.10-10.5.50.254",
        lease_time="30m",
        dns_servers=("10.5.50.1",),
    )
    assert [op for op in api.ops if op[0] != "command"] == []


async def test_unknown_pool_raises_without_writing(patch_connect, mikrotik_creds):
    api = _hotspot_router()
    patch_connect(api)
    with pytest.raises(MikroTikDeviceError):
        await MikroTikAdapter().update_dhcp_pool_in_place(
            mikrotik_creds, pool_name="nope", ranges="10.5.50.20-10.5.50.30"
        )
    assert [op for op in api.ops if op[0] != "command"] == []
