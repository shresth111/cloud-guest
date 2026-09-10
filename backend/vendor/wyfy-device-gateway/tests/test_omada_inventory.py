"""Sites, SSIDs, devices, clients: paths, pagination and normalization."""

from __future__ import annotations

import random
from datetime import UTC, datetime

import httpx
import pytest

from wyfy_device_gateway.controller_contract import (
    ControllerAuthMode,
    ControllerClient,
    ControllerDevice,
    ControllerSite,
)
from wyfy_device_gateway.omada.adapter import OmadaControllerAdapter
from wyfy_device_gateway.omada.clients import parse_client
from wyfy_device_gateway.omada.devices import parse_device
from wyfy_device_gateway.omada.errors import (
    OmadaSiteNotFoundError,
    OmadaUnsupportedApiError,
)
from wyfy_device_gateway.omada.types import (
    epoch_to_utc,
    normalize_device_status,
    normalize_device_type,
    normalize_mac,
)

from omada_support import OMADAC_ID, FakeOmadaController, envelope, make_creds, no_sleep, paged

SITE_ID = "site-abc123"


def _adapter(controller: FakeOmadaController) -> OmadaControllerAdapter:
    return OmadaControllerAdapter(
        transport=controller.transport(), sleep=no_sleep, rng=random.Random(11)
    )


# --- sites -----------------------------------------------------------------


async def test_list_sites_hits_the_expected_path_and_parses_rows():
    controller = FakeOmadaController()
    controller.routes["/sites"] = paged(
        [
            {"siteId": SITE_ID, "name": "Lobby", "deviceCount": 3, "clientCount": 12},
            {"id": "site-2", "siteName": "Cafe"},
        ]
    )
    sites = await _adapter(controller).list_sites(make_creds())

    assert f"/openapi/v1/{OMADAC_ID}/sites" in controller.paths()
    assert sites == [
        ControllerSite(site_id=SITE_ID, name="Lobby", device_count=3, client_count=12),
        ControllerSite(site_id="site-2", name="Cafe", device_count=None, client_count=None),
    ]


async def test_site_row_without_an_identifier_is_dropped_not_invented():
    controller = FakeOmadaController()
    controller.routes["/sites"] = paged([{"name": "Nameless"}, {"siteId": "ok", "name": "Fine"}])
    sites = await _adapter(controller).list_sites(make_creds())
    assert [s.site_id for s in sites] == ["ok"]


async def test_get_site_returns_the_matching_site():
    controller = FakeOmadaController()
    controller.routes["/sites"] = paged(
        [{"siteId": "a", "name": "A"}, {"siteId": SITE_ID, "name": "Lobby"}]
    )
    site = await _adapter(controller).get_site(make_creds(), SITE_ID)
    assert site.name == "Lobby"


async def test_get_site_raises_site_not_found_when_it_is_gone():
    controller = FakeOmadaController()
    controller.routes["/sites"] = paged([{"siteId": "other", "name": "Other"}])
    with pytest.raises(OmadaSiteNotFoundError) as excinfo:
        await _adapter(controller).get_site(make_creds(), SITE_ID)
    assert excinfo.value.code == "OMADA_SITE_NOT_FOUND"


async def test_pagination_walks_every_page():
    controller = FakeOmadaController()
    pages = {
        1: paged([{"siteId": f"s{i}", "name": f"S{i}"} for i in range(100)], total=150),
        2: paged([{"siteId": f"s{i}", "name": f"S{i}"} for i in range(100, 150)], total=150),
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/info":
            return controller._info_response()
        if request.url.path == "/openapi/authorize/token":
            return controller._token_response(request)
        page = int(request.url.params.get("page", 1))
        return httpx.Response(200, json=envelope(pages[page]))

    controller.handler_override = handler
    sites = await _adapter(controller).list_sites(make_creds())
    assert len(sites) == 150


async def test_pagination_stops_on_a_short_page_even_if_total_rows_lies():
    controller = FakeOmadaController()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/info":
            return controller._info_response()
        if request.url.path == "/openapi/authorize/token":
            return controller._token_response(request)
        # Claims 9999 rows but serves 2. Must not spin.
        return httpx.Response(
            200,
            json=envelope(paged([{"siteId": "a", "name": "A"}, {"siteId": "b", "name": "B"}], total=9999)),
        )

    controller.handler_override = handler
    sites = await _adapter(controller).list_sites(make_creds())
    assert len(sites) == 2


# --- SSIDs -----------------------------------------------------------------


async def test_list_ssids_walks_wlan_groups_then_ssids():
    controller = FakeOmadaController()

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/info":
            return controller._info_response()
        if path == "/openapi/authorize/token":
            return controller._token_response(request)
        if path.endswith("/wireless-network/wlans"):
            return httpx.Response(200, json=envelope(paged([{"id": "wlan-1", "name": "Default"}])))
        if path.endswith("/wlans/wlan-1/ssids"):
            return httpx.Response(
                200,
                json=envelope(
                    paged([{"id": "ssid-1", "name": "Wyfy Guest", "portalEnable": True}])
                ),
            )
        return httpx.Response(200, json=envelope(paged([])))

    controller.handler_override = handler
    ssids = await _adapter(controller).list_ssids(make_creds(), SITE_ID)

    assert len(ssids) == 1
    assert ssids[0].name == "Wyfy Guest"
    assert ssids[0].ssid_id == "ssid-1"
    assert ssids[0].wlan_group_id == "wlan-1"
    assert ssids[0].portal_enabled is True


# --- devices ---------------------------------------------------------------


async def test_list_devices_path_and_parsing():
    controller = FakeOmadaController()
    controller.routes["/devices"] = paged(
        [
            {
                "mac": "aa:bb:cc:dd:ee:ff",
                "name": "Lobby AP",
                "type": "ap",
                "model": "EAP245",
                "status": 1,
                "ip": "10.0.0.5",
                "firmwareVersion": "5.0.3",
                "uptime": 86400,
                "clientNum": 7,
            }
        ]
    )
    devices = await _adapter(controller).list_devices(make_creds(), SITE_ID)

    assert f"/openapi/v1/{OMADAC_ID}/sites/{SITE_ID}/devices" in controller.paths()
    assert devices == [
        ControllerDevice(
            mac="AA-BB-CC-DD-EE-FF",
            name="Lobby AP",
            device_type="ap",
            model="EAP245",
            status="connected",
            ip_address="10.0.0.5",
            firmware_version="5.0.3",
            uptime_seconds=86400,
            client_count=7,
        )
    ]


async def test_device_without_a_mac_is_dropped():
    controller = FakeOmadaController()
    controller.routes["/devices"] = paged([{"name": "ghost", "type": "ap"}])
    assert await _adapter(controller).list_devices(make_creds(), SITE_ID) == []


def test_unknown_device_type_and_status_become_unknown_not_a_raw_code():
    parsed = parse_device({"mac": "AABBCCDDEEFF", "type": "toaster", "status": 77})
    assert parsed is not None
    assert parsed.device_type == "unknown"
    assert parsed.status == "unknown"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("ap", "ap"), ("EAP", "ap"), ("switch", "switch"), ("gateway", "gateway"),
     (0, "ap"), (1, "switch"), (2, "gateway"), ("nonsense", "unknown"), (None, "unknown")],
)
def test_device_type_normalization(raw, expected):
    assert normalize_device_type(raw) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("connected", "connected"), ("OFFLINE", "disconnected"), (1, "connected"),
     (0, "disconnected"), (3, "pending"), ("adopting", "pending"), (None, "unknown")],
)
def test_device_status_normalization(raw, expected):
    assert normalize_device_status(raw) == expected


# --- clients ---------------------------------------------------------------


async def test_list_clients_uses_the_v1_get_endpoint():
    controller = FakeOmadaController()
    controller.routes["/clients"] = paged(
        [
            {
                "mac": "11:22:33:44:55:66",
                "name": "Pixel",
                "ip": "10.0.0.99",
                "ssid": "Wyfy Guest",
                "apMac": "AA-BB-CC-DD-EE-FF",
                "radioId": 1,
                "vid": 30,
                "guest": True,
                "authorized": True,
                "connectTime": 1725945600,
                "duration": 1200,
                "download": 5000,
                "upload": 900,
                "rssi": -55,
            }
        ]
    )
    clients = await _adapter(controller).list_clients(make_creds(), SITE_ID)

    request = controller.request_for("/clients")
    assert request.method == "GET"
    assert f"/openapi/v1/{OMADAC_ID}/sites/{SITE_ID}/clients" in controller.paths()

    assert clients == [
        ControllerClient(
            mac="11-22-33-44-55-66",
            name="Pixel",
            ip_address="10.0.0.99",
            ssid="Wyfy Guest",
            ap_mac="AA-BB-CC-DD-EE-FF",
            radio_id=1,
            vlan_id=30,
            is_guest=True,
            is_authorized=True,
            connected_since=datetime(2024, 9, 10, 5, 20, tzinfo=UTC),
            duration_seconds=1200,
            traffic_down_bytes=5000,
            traffic_up_bytes=900,
            signal_dbm=-55,
        )
    ]


async def test_get_client_matches_regardless_of_mac_separator_style():
    controller = FakeOmadaController()
    controller.routes["/clients"] = paged([{"mac": "AA-BB-CC-DD-EE-FF", "name": "Phone"}])

    found = await _adapter(controller).get_client(make_creds(), SITE_ID, "aa:bb:cc:dd:ee:ff")
    assert found is not None
    assert found.name == "Phone"


async def test_get_client_returns_none_when_not_connected():
    """A guest whose phone dropped off is a normal state, not an error."""
    controller = FakeOmadaController()
    controller.routes["/clients"] = paged([{"mac": "AA-BB-CC-DD-EE-FF"}])

    assert await _adapter(controller).get_client(make_creds(), SITE_ID, "00-00-00-00-00-01") is None


def test_unknown_authorization_state_stays_none_rather_than_false():
    parsed = parse_client({"mac": "AABBCCDDEEFF"})
    assert parsed is not None
    assert parsed.is_authorized is None
    assert parsed.is_guest is None


# --- coercion helpers ------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF"),
        ("AA-BB-CC-DD-EE-FF", "AA-BB-CC-DD-EE-FF"),
        ("aabbccddeeff", "AA-BB-CC-DD-EE-FF"),
        ("aabb.ccdd.eeff", "AA-BB-CC-DD-EE-FF"),
        (None, None),
    ],
)
def test_mac_normalization(raw, expected):
    assert normalize_mac(raw) == expected


def test_unrecognised_mac_is_kept_not_dropped():
    assert normalize_mac("not-a-mac") == "not-a-mac"


def test_epoch_seconds_and_milliseconds_are_both_handled():
    assert epoch_to_utc(1725945600) == datetime(2024, 9, 10, 5, 20, tzinfo=UTC)
    assert epoch_to_utc(1725945600000) == datetime(2024, 9, 10, 5, 20, tzinfo=UTC)
    assert epoch_to_utc(0) is None
    assert epoch_to_utc(None) is None
    assert epoch_to_utc("garbage") is None


# --- legacy mode cannot do inventory --------------------------------------


@pytest.mark.parametrize(
    "call",
    [
        lambda a, c: a.list_sites(c),
        lambda a, c: a.get_site(c, SITE_ID),
        lambda a, c: a.list_ssids(c, SITE_ID),
        lambda a, c: a.list_devices(c, SITE_ID),
        lambda a, c: a.list_clients(c, SITE_ID),
        lambda a, c: a.get_client(c, SITE_ID, "AA-BB-CC-DD-EE-FF"),
    ],
)
async def test_inventory_in_legacy_mode_raises_unsupported_with_a_useful_message(call):
    """A hotspot operator credential cannot read inventory. Say that,
    instead of sending a request that fails as 'wrong password'."""
    controller = FakeOmadaController()
    creds = make_creds(ControllerAuthMode.LEGACY)

    with pytest.raises(OmadaUnsupportedApiError) as excinfo:
        await call(_adapter(controller), creds)

    assert excinfo.value.code == "OMADA_API_UNSUPPORTED"
    assert "Open API" in str(excinfo.value)
    # It never even opened a connection.
    assert controller.requests == []
