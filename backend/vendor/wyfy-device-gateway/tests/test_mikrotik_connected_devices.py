"""Device discovery reads the two menus that can answer, and stops asking
the one that cannot.

``list_connected_devices`` used to issue a third read,
``/interface/wireless/registration-table``, on every router on every sync
tick. Every router this platform deploys is a wired hEX lite with no radio
and no ``wireless`` package, so that menu does not exist: the query raised
``no such command or directory (wireless)``, ``_safe_query`` swallowed it
into ``[]``, and the caller could not distinguish "no wireless clients"
from "this router has no concept of wireless clients". The fleet-wide sync
sweep paid for that round trip every five minutes, per router, forever.

The tests below assert both halves of the fix, and each is written so it
fails against the old behaviour:

* the wireless menu is never touched at all -- not "tolerated when
  missing", not asked;
* the resulting unknowability is reported as ``is_wireless=None``, never
  ``False``, because ``False`` is a positive claim ("this guest is on a
  cable") that is wrong for every Wi-Fi guest on the fleet.
"""

from __future__ import annotations

import pytest
from wyfy_device_gateway.mikrotik_adapter import MikroTikAdapter

from tests.fake_write_transport import FakeRouterOSApi

_LEASES = ("ip", "dhcp-server", "lease")
_ARP = ("ip", "arp")
_WIRELESS = ("interface", "wireless", "registration-table")


def _api(*, leases=(), arp=(), missing=None) -> FakeRouterOSApi:
    return FakeRouterOSApi(
        menus={_LEASES: list(leases), _ARP: list(arp)},
        missing_menus=missing or set(),
    )


# ============================================================================
# The dead read is gone
# ============================================================================


@pytest.mark.asyncio
async def test_wireless_registration_table_is_never_queried(
    patch_connect, mikrotik_creds
):
    """The regression that matters. ``FakeRouterOSApi.path`` records every
    menu it is asked for by ``setdefault``-ing it into ``_menus``, so the
    absence of the wireless key is proof the sentence never went on the
    wire -- not merely that its failure was handled."""
    api = _api(arp=[{"mac-address": "AA:BB:CC:DD:EE:01", "address": "10.5.50.20"}])
    patch_connect(api)

    await MikroTikAdapter().list_connected_devices(mikrotik_creds)

    assert _WIRELESS not in api._menus, (
        "the wireless registration table must not be queried at all -- "
        "it cannot exist on this fleet's hardware"
    )
    assert set(api._menus) == {_LEASES, _ARP}


@pytest.mark.asyncio
async def test_discovery_still_works_when_the_wireless_menu_would_have_raised(
    patch_connect, mikrotik_creds
):
    """Belt and braces: even on a fake device that raises for the wireless
    menu, discovery returns the wired devices. Before the removal this
    passed only because of an explicit try/except; now it passes because
    nothing asks."""
    api = _api(
        leases=[
            {
                "mac-address": "AA:BB:CC:DD:EE:01",
                "active-address": "10.5.50.20",
                "host-name": "pixel-7",
            }
        ],
        missing={_WIRELESS},
    )
    patch_connect(api)

    devices = await MikroTikAdapter().list_connected_devices(mikrotik_creds)

    assert [d.mac_address for d in devices] == ["AA:BB:CC:DD:EE:01"]
    assert devices[0].hostname == "pixel-7"


# ============================================================================
# The unknowable is reported as unknown, not as "no"
# ============================================================================


@pytest.mark.asyncio
async def test_is_wireless_is_none_not_false(patch_connect, mikrotik_creds):
    """``False`` would assert the device is wired. The router cannot know
    that: a guest's phone on the venue Wi-Fi and a laptop on a cable both
    arrive through the same bridge port from a third-party access point."""
    api = _api(
        leases=[{"mac-address": "AA:BB:CC:DD:EE:01", "active-address": "10.5.50.20"}],
        arp=[{"mac-address": "AA:BB:CC:DD:EE:02", "address": "10.5.50.21"}],
    )
    patch_connect(api)

    devices = await MikroTikAdapter().list_connected_devices(mikrotik_creds)

    assert len(devices) == 2
    for device in devices:
        assert device.is_wireless is None, "must be None (unknowable), never False"
        assert device.signal_strength_dbm is None


# ============================================================================
# The merge behaviour the two surviving menus still owe us
# ============================================================================


@pytest.mark.asyncio
async def test_a_device_in_both_menus_is_one_row_with_both_menus_data(
    patch_connect, mikrotik_creds
):
    """ARP carries the interface; the lease carries the hostname. A device
    in both is one device, and neither menu's contribution is lost."""
    api = _api(
        leases=[
            {
                "mac-address": "aa:bb:cc:dd:ee:01",
                "active-address": "10.5.50.20",
                "host-name": "pixel-7",
            }
        ],
        arp=[
            {
                "mac-address": "AA:BB:CC:DD:EE:01",
                "address": "10.5.50.20",
                "interface": "bridge",
            }
        ],
    )
    patch_connect(api)

    devices = await MikroTikAdapter().list_connected_devices(mikrotik_creds)

    assert len(devices) == 1, "case-different MACs are the same device"
    assert devices[0].hostname == "pixel-7", "from the lease"
    assert devices[0].interface == "bridge", "from ARP, kept because the lease has none"
    assert devices[0].ip_address == "10.5.50.20"


@pytest.mark.asyncio
async def test_a_missing_dhcp_server_menu_does_not_cost_the_arp_half(
    patch_connect, mikrotik_creds
):
    """The reason ``_safe_query`` survives the wireless removal: a router
    running no DHCP server has no lease menu, and that must not take
    ARP-based discovery down with it."""
    api = _api(
        arp=[{"mac-address": "AA:BB:CC:DD:EE:02", "address": "10.5.50.21"}],
        missing={_LEASES},
    )
    patch_connect(api)

    devices = await MikroTikAdapter().list_connected_devices(mikrotik_creds)

    assert [d.mac_address for d in devices] == ["AA:BB:CC:DD:EE:02"]


@pytest.mark.asyncio
async def test_rows_without_a_mac_are_skipped(patch_connect, mikrotik_creds):
    """A lease row mid-negotiation can carry no MAC. It is not a device."""
    api = _api(
        leases=[{"active-address": "10.5.50.99"}],
        arp=[{"mac-address": "AA:BB:CC:DD:EE:03", "address": "10.5.50.22"}],
    )
    patch_connect(api)

    devices = await MikroTikAdapter().list_connected_devices(mikrotik_creds)

    assert [d.mac_address for d in devices] == ["AA:BB:CC:DD:EE:03"]
