"""ISP-specific WAN link telemetry: dynamic default gateway lookup (never
filtered by interface), PPPoE interface status (with stale-name
single-candidate fallback / ambiguity error), interface traffic counters
-- all ported from ``isp/device_adapters.py``."""

from __future__ import annotations

import pytest

from tests.fake_write_transport import FakeRouterOSApi
from wyfy_device_gateway.mikrotik_adapter import MikroTikAdapter, MikroTikDeviceError


@pytest.mark.asyncio
async def test_get_active_default_gateway_found(patch_connect, mikrotik_creds):
    api = FakeRouterOSApi(
        menus={
            ("ip", "route"): [
                {
                    "dst-address": "0.0.0.0/0",
                    "dynamic": "true",
                    "gateway": "203.0.113.1",
                },
                {"dst-address": "10.0.0.0/24", "dynamic": "false", "gateway": "0.0.0.0"},
            ],
        }
    )
    patch_connect(api)

    gateway = await MikroTikAdapter().get_active_default_gateway(mikrotik_creds)

    assert gateway == "203.0.113.1"
    assert api.closed is True


@pytest.mark.asyncio
async def test_get_active_default_gateway_none_when_no_dynamic_default_route(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi(menus={("ip", "route"): []})
    patch_connect(api)

    gateway = await MikroTikAdapter().get_active_default_gateway(mikrotik_creds)

    assert gateway is None


@pytest.mark.asyncio
async def test_get_pppoe_interface_status_exact_match(patch_connect, mikrotik_creds):
    api = FakeRouterOSApi(
        menus={
            ("interface", "pppoe-client"): [
                {"name": "pppoe-out1", "running": "true", "disabled": "false"},
            ],
        }
    )
    patch_connect(api)

    status = await MikroTikAdapter().get_pppoe_interface_status(
        mikrotik_creds, interface_name="pppoe-out1"
    )

    assert status is True


@pytest.mark.asyncio
async def test_get_pppoe_interface_status_stale_name_single_candidate_fallback(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi(
        menus={
            ("interface", "pppoe-client"): [
                {"name": "pppoe-out1", "running": "true", "disabled": "false"},
            ],
        }
    )
    patch_connect(api)

    status = await MikroTikAdapter().get_pppoe_interface_status(
        mikrotik_creds, interface_name="pppoe-out1-old"
    )

    assert status is True


@pytest.mark.asyncio
async def test_get_pppoe_interface_status_ambiguous_candidates_raises(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi(
        menus={
            ("interface", "pppoe-client"): [
                {"name": "pppoe-out1", "running": "true", "disabled": "false"},
                {"name": "pppoe-out2", "running": "false", "disabled": "false"},
            ],
        }
    )
    patch_connect(api)

    with pytest.raises(MikroTikDeviceError):
        await MikroTikAdapter().get_pppoe_interface_status(
            mikrotik_creds, interface_name="pppoe-out1-old"
        )


@pytest.mark.asyncio
async def test_get_pppoe_interface_status_zero_candidates_raises(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi(menus={("interface", "pppoe-client"): []})
    patch_connect(api)

    with pytest.raises(MikroTikDeviceError):
        await MikroTikAdapter().get_pppoe_interface_status(
            mikrotik_creds, interface_name="pppoe-out1"
        )


@pytest.mark.asyncio
async def test_get_pppoe_interface_status_disabled_is_false(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi(
        menus={
            ("interface", "pppoe-client"): [
                {"name": "pppoe-out1", "running": "true", "disabled": "true"},
            ],
        }
    )
    patch_connect(api)

    status = await MikroTikAdapter().get_pppoe_interface_status(
        mikrotik_creds, interface_name="pppoe-out1"
    )

    assert status is False


@pytest.mark.asyncio
async def test_get_interface_traffic_counters_found(patch_connect, mikrotik_creds):
    api = FakeRouterOSApi(
        menus={
            ("interface",): [
                {"name": "ether1", "rx-byte": "1000", "tx-byte": "2000"},
            ],
        }
    )
    patch_connect(api)

    counters = await MikroTikAdapter().get_interface_traffic_counters(
        mikrotik_creds, interface_name="ether1"
    )

    assert counters == (1000, 2000)


@pytest.mark.asyncio
async def test_get_interface_traffic_counters_missing_interface_returns_none(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi(menus={("interface",): []})
    patch_connect(api)

    counters = await MikroTikAdapter().get_interface_traffic_counters(
        mikrotik_creds, interface_name="ether1"
    )

    assert counters is None
