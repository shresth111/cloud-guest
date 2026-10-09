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
_ROUTES = ("ip", "route")
_ADDRESSES = ("ip", "address")
_INTERFACES = ("interface",)
_DHCP_CLIENTS = ("ip", "dhcp-client")


def _api(
    *,
    leases=(),
    arp=(),
    routes=(),
    addresses=(),
    interfaces=(),
    dhcp_clients=(),
    missing=None,
) -> FakeRouterOSApi:
    return FakeRouterOSApi(
        menus={
            _LEASES: list(leases),
            _ARP: list(arp),
            _ROUTES: list(routes),
            _ADDRESSES: list(addresses),
            _INTERFACES: list(interfaces),
            _DHCP_CLIENTS: list(dhcp_clients),
        },
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
    assert set(api._menus) == {
        _LEASES,
        _ARP,
        _ROUTES,
        _ADDRESSES,
        _INTERFACES,
        _DHCP_CLIENTS,
    }


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


# ============================================================================
# A lease row is bookkeeping, not liveness (bug: AP down but still "UP")
# ============================================================================


@pytest.mark.asyncio
async def test_expired_lease_row_is_not_a_seen_device(patch_connect, mikrotik_creds):
    """RouterOS keeps a powered-off client's lease row after the lease time
    elapses, its ``status`` now ``expired``. The 15-minute device sync used
    to treat that row as a seen device and kept refreshing the device's
    ``is_active``/``last_seen_at``, so a venue access point that physically
    went down stayed "UP" forever (bug report: "AP Hall Lobby went down but
    the console still shows UP"). An expired lease must not surface as a
    device at all -- then the sync's own absent-device flip marks it down."""
    api = _api(
        leases=[
            {
                "mac-address": "AA:BB:CC:DD:EE:04",
                "active-address": "10.5.50.23",
                "status": "expired",
            },
            {
                "mac-address": "AA:BB:CC:DD:EE:05",
                "active-address": "10.5.50.24",
                "status": "waiting",
            },
        ],
        arp=[],
    )
    patch_connect(api)

    devices = await MikroTikAdapter().list_connected_devices(mikrotik_creds)

    assert devices == [], (
        "neither an expired nor a waiting lease is a live client -- "
        "both must be invisible to the sync so their devices flip down"
    )


@pytest.mark.asyncio
async def test_bound_lease_row_is_a_seen_device(patch_connect, mikrotik_creds):
    """The counterpart: a genuinely bound lease is still served by the
    router and must keep surfacing as a device."""
    api = _api(
        leases=[
            {
                "mac-address": "AA:BB:CC:DD:EE:06",
                "active-address": "10.5.50.25",
                "host-name": "pixel-7",
                "status": "bound",
            }
        ],
        arp=[],
    )
    patch_connect(api)

    devices = await MikroTikAdapter().list_connected_devices(mikrotik_creds)

    assert [d.mac_address for d in devices] == ["AA:BB:CC:DD:EE:06"]
    assert devices[0].hostname == "pixel-7"


@pytest.mark.asyncio
async def test_lease_row_without_a_status_field_stays_visible(
    patch_connect, mikrotik_creds
):
    """``status`` is absent on this project's older fake transports and some
    RouterOS print shapes -- absence must keep the row (backward
    compatible); only an explicit non-``bound`` status drops it."""
    api = _api(
        leases=[
            {
                "mac-address": "AA:BB:CC:DD:EE:07",
                "active-address": "10.5.50.26",
            }
        ],
        arp=[],
    )
    patch_connect(api)

    devices = await MikroTikAdapter().list_connected_devices(mikrotik_creds)

    assert [d.mac_address for d in devices] == ["AA:BB:CC:DD:EE:07"]


# ============================================================================
# Upstream neighbours are not guests
# ============================================================================

# A typical venue: DHCP WAN on ether1 behind an ISP router at
# 192.168.1.1, guest LAN 10.5.50.0/24 on the bridge.
_VENUE_INTERFACES = [{"name": "ether1"}, {"name": "bridge"}, {"name": "wg-cloudguard"}]
_VENUE_ADDRESSES = [
    {"address": "10.5.50.1/24", "interface": "bridge"},
    {"address": "10.20.0.99/24", "interface": "wg-cloudguard"},
    {"address": "192.168.1.200/24", "interface": "ether1"},
]
_VENUE_ROUTES = [
    {"dst-address": "0.0.0.0/0", "gateway": "192.168.1.1", "active": "true"},
]
_VENUE_DHCP_CLIENTS = [{"interface": "ether1", "gateway": "192.168.1.1"}]
_VENUE_ARP = [
    {
        "mac-address": "02:00:00:00:01:01",
        "address": "192.168.1.1",
        "interface": "ether1",
    },
    {
        "mac-address": "02:00:00:00:01:02",
        "address": "192.168.1.19",
        "interface": "ether1",
    },
    {
        "mac-address": "02:00:00:00:01:03",
        "address": "192.168.1.214",
        "interface": "ether1",
    },
    {
        "mac-address": "02:00:00:00:02:01",
        "address": "10.5.50.254",
        "interface": "bridge",
    },
    {
        "mac-address": "02:00:00:00:02:02",
        "address": "10.5.50.10",
        "interface": "bridge",
    },
]


@pytest.mark.asyncio
async def test_arp_neighbours_on_the_wan_are_not_connected_devices(
    patch_connect, mikrotik_creds
):
    """``/ip/arp`` lists the ISP router and everything else on the upstream
    LAN. Those are not guests of this venue; reporting them made the
    dashboard look like devices were online without a login."""
    api = _api(
        arp=_VENUE_ARP,
        routes=_VENUE_ROUTES,
        addresses=_VENUE_ADDRESSES,
        interfaces=_VENUE_INTERFACES,
        dhcp_clients=_VENUE_DHCP_CLIENTS,
    )
    patch_connect(api)

    devices = await MikroTikAdapter().list_connected_devices(mikrotik_creds)

    assert sorted(d.mac_address for d in devices) == [
        "02:00:00:00:02:01",
        "02:00:00:00:02:02",
    ]


@pytest.mark.asyncio
async def test_every_default_route_egress_counts_as_uplink(
    patch_connect, mikrotik_creds
):
    """Failover/load-balance routers carry one default route per WAN; a
    neighbour on the backup WAN is no more a guest than one on the
    primary. Static WAN (no dhcp-client) is named from the route itself."""
    api = _api(
        arp=[
            {
                "mac-address": "AA:00:00:00:00:01",
                "address": "203.0.113.1",
                "interface": "ether1",
            },
            {
                "mac-address": "AA:00:00:00:00:02",
                "address": "198.51.100.1",
                "interface": "ether2",
            },
            {
                "mac-address": "AA:00:00:00:00:03",
                "address": "10.5.50.30",
                "interface": "bridge",
            },
        ],
        routes=[
            {
                "dst-address": "0.0.0.0/0",
                "gateway": "203.0.113.1%ether1",
                "active": "true",
            },
            {"dst-address": "0.0.0.0/0", "gateway": "198.51.100.1", "distance": "2"},
        ],
        addresses=[
            {"address": "203.0.113.2/30", "interface": "ether1"},
            {"address": "198.51.100.2/30", "interface": "ether2"},
            {"address": "10.5.50.1/24", "interface": "bridge"},
        ],
        interfaces=[{"name": "ether1"}, {"name": "ether2"}, {"name": "bridge"}],
    )
    patch_connect(api)

    devices = await MikroTikAdapter().list_connected_devices(mikrotik_creds)

    assert [d.mac_address for d in devices] == ["AA:00:00:00:00:03"]


@pytest.mark.asyncio
async def test_unreadable_route_menu_keeps_every_arp_row(patch_connect, mikrotik_creds):
    """If the router will not say which interface is the WAN, hiding rows
    on a guess could hide real guests. Fall back to the old behaviour."""
    api = _api(arp=_VENUE_ARP, missing={_ROUTES, _DHCP_CLIENTS})
    patch_connect(api)

    devices = await MikroTikAdapter().list_connected_devices(mikrotik_creds)

    assert len(devices) == len(_VENUE_ARP)
