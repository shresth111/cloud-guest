"""WAN health: ping parsing, dynamic-default-gateway lookup (never filtered
by interface name), and the PPPoE stale-interface-name single-candidate
fallback -- all ported from ``isp/device_adapters.py``."""

from __future__ import annotations

import pytest

from tests.fake_write_transport import FakeRouterOSApi
from wyfy_device_gateway.mikrotik_adapter import MikroTikAdapter


@pytest.mark.asyncio
async def test_wan_health_happy_path_dhcp_link(patch_connect, mikrotik_creds):
    api = FakeRouterOSApi(
        command_replies={
            "/tool/ping": [
                {"sent": "4", "received": "4", "packet-loss": "0", "avg-rtt": "1ms200us"},
            ],
        },
        menus={
            ("ip", "route"): [
                {"dst-address": "0.0.0.0/0", "dynamic": "true", "gateway": "203.0.113.1", "interface": "ether1"},
                {"dst-address": "10.0.0.0/24", "dynamic": "false", "gateway": "0.0.0.0"},
            ],
            ("interface", "pppoe-client"): [],
            ("interface",): [
                {"name": "ether1", "rx-byte": "1000", "tx-byte": "2000"},
            ],
        },
    )
    patch_connect(api)

    health = await MikroTikAdapter().get_wan_health(mikrotik_creds, target_ip="8.8.8.8")

    assert health.reachable is True
    assert health.dynamic_gateway == "203.0.113.1"
    assert health.ppp_status is None  # no pppoe client on this router at all
    assert health.rx_bytes == 1000
    assert health.tx_bytes == 2000
    assert health.latency_ms == 1.2
    assert health.packet_loss_percent == 0.0


@pytest.mark.asyncio
async def test_wan_health_unreachable_ping_is_total_loss(patch_connect, mikrotik_creds):
    api = FakeRouterOSApi(
        command_replies={"/tool/ping": []},
        menus={("ip", "route"): [], ("interface", "pppoe-client"): [], ("interface",): []},
    )
    patch_connect(api)

    health = await MikroTikAdapter().get_wan_health(mikrotik_creds, target_ip="8.8.8.8")

    assert health.reachable is False
    assert health.packet_loss_percent == 100.0
    assert health.latency_ms is None
    assert health.dynamic_gateway is None


@pytest.mark.asyncio
async def test_wan_health_pppoe_stale_name_single_candidate_fallback(
    patch_connect, mikrotik_creds
):
    """The route table names a WAN interface ("pppoe-out1-old") that no
    longer matches any real pppoe-client row -- but exactly one real
    candidate exists, so it's used anyway (same fallback semantics as
    isp/device_adapters.py::_get_pppoe_interface_status_sync)."""
    api = FakeRouterOSApi(
        command_replies={
            "/tool/ping": [{"sent": "1", "received": "1", "packet-loss": "0", "avg-rtt": "5ms"}],
        },
        menus={
            ("ip", "route"): [
                {
                    "dst-address": "0.0.0.0/0",
                    "dynamic": "true",
                    "gateway": "198.51.100.1",
                    "interface": "pppoe-out1-old",
                },
            ],
            ("interface", "pppoe-client"): [
                {"name": "pppoe-out1", "running": "true", "disabled": "false"},
            ],
            ("interface",): [
                {"name": "pppoe-out1", "rx-byte": "500", "tx-byte": "600"},
            ],
        },
    )
    patch_connect(api)

    health = await MikroTikAdapter().get_wan_health(mikrotik_creds, target_ip="1.1.1.1")

    assert health.ppp_status is True
    assert health.rx_bytes == 500
    assert health.tx_bytes == 600


@pytest.mark.asyncio
async def test_wan_health_pppoe_ambiguous_candidates_gives_none(patch_connect, mikrotik_creds):
    api = FakeRouterOSApi(
        command_replies={"/tool/ping": []},
        menus={
            ("ip", "route"): [],
            ("interface", "pppoe-client"): [
                {"name": "pppoe-out1", "running": "true", "disabled": "false"},
                {"name": "pppoe-out2", "running": "false", "disabled": "false"},
            ],
            ("interface",): [],
        },
    )
    patch_connect(api)

    health = await MikroTikAdapter().get_wan_health(mikrotik_creds, target_ip="1.1.1.1")

    # No route-derived interface name, and 2 candidates -- genuinely
    # ambiguous, never guessed.
    assert health.ppp_status is None
