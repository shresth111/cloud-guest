"""Interface listing + filtering rules, ported from
``router/device_adapters.py::_list_sync``: excludes ``lo``, any interface
bound to a ``/ip dhcp-server``, and any ``/ip dhcp-client`` interface."""

from __future__ import annotations

import pytest

from tests.fake_write_transport import FakeRouterOSApi
from wyfy_device_gateway.mikrotik_adapter import MikroTikAdapter


@pytest.mark.asyncio
async def test_interface_list_filters_lo_dhcp_server_and_dhcp_client(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi(
        menus={
            ("interface",): [
                {"name": "lo", "type": "loopback", "running": True, "disabled": False},
                {"name": "ether1", "type": "ether", "running": True, "disabled": False},
                {"name": "ether2", "type": "ether", "running": True, "disabled": False},
                {"name": "ether3", "type": "ether", "running": False, "disabled": True},
            ],
            ("interface", "bridge", "port"): [
                {"interface": "ether3", "bridge": "bridge1"},
            ],
            ("ip", "address"): [
                {"interface": "ether2", "address": "192.168.1.1/24"},
            ],
            ("ip", "dhcp-server"): [
                {"interface": "ether1"},  # ether1 already serves DHCP -> excluded
            ],
            ("ip", "dhcp-client"): [
                {"interface": "ether2"},  # ether2 is the WAN uplink -> excluded
            ],
        }
    )
    patch_connect(api)

    result = await MikroTikAdapter().get_interface_list(mikrotik_creds)

    names = {i.name for i in result}
    assert names == {"ether3"}
    assert api.closed is True

    ether3 = next(i for i in result if i.name == "ether3")
    assert ether3.bridge == "bridge1"
    assert ether3.running is False
    assert ether3.disabled is True
    assert ether3.has_ip_address is False


@pytest.mark.asyncio
async def test_interface_list_skips_nameless_rows(patch_connect, mikrotik_creds):
    api = FakeRouterOSApi(
        menus={
            ("interface",): [{"type": "ether", "running": "true"}],  # no "name"
        }
    )
    patch_connect(api)

    result = await MikroTikAdapter().get_interface_list(mikrotik_creds)

    assert result == []
