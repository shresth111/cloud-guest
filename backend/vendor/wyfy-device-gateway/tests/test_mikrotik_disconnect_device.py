"""``disconnect_device``: best-effort wireless kick, then the DHCP-lease
removal that actually matters. Ported from the upstream
wyfy-device-gateway repo's ``test_mikrotik_connected_devices.py`` when this
vendored copy became the canonical one -- that file here was rewritten by
cloud-guest #151 and no longer carried these two."""

from __future__ import annotations

import pytest

from tests.fake_write_transport import FakeRouterOSApi
from wyfy_device_gateway.mikrotik_adapter import MikroTikAdapter


@pytest.mark.asyncio
async def test_disconnect_device_removes_wireless_and_lease_rows(patch_connect, mikrotik_creds):
    api = FakeRouterOSApi(
        menus={
            ("interface", "wireless", "registration-table"): [
                {".id": "*1", "mac-address": "aa:bb:cc:dd:ee:01"},
            ],
            ("ip", "dhcp-server", "lease"): [
                {".id": "*7", "mac-address": "aa:bb:cc:dd:ee:01"},
            ],
        }
    )
    patch_connect(api)

    await MikroTikAdapter().disconnect_device(
        mikrotik_creds, mac_address="AA:BB:CC:DD:EE:01", interface=None
    )

    assert api.remove_calls == [
        (("interface", "wireless", "registration-table"), ("*1",)),
        (("ip", "dhcp-server", "lease"), ("*7",)),
    ]


@pytest.mark.asyncio
async def test_disconnect_device_survives_missing_wireless_menu(patch_connect, mikrotik_creds):
    """A wired-only router (no wireless package at all -- the hEX lite /
    RB750r2 every venue runs) has no ``interface wireless
    registration-table`` menu. That alone must not abort the DHCP-lease
    removal, which is the part that actually matters for a wired device."""
    api = FakeRouterOSApi(
        menus={
            ("ip", "dhcp-server", "lease"): [
                {".id": "*7", "mac-address": "aa:bb:cc:dd:ee:01"},
            ],
        },
        missing_menus={("interface", "wireless", "registration-table")},
    )
    patch_connect(api)

    await MikroTikAdapter().disconnect_device(
        mikrotik_creds, mac_address="AA:BB:CC:DD:EE:01", interface=None
    )

    assert api.remove_calls == [
        (("ip", "dhcp-server", "lease"), ("*7",)),
    ]
