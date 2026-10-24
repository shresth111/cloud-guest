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
