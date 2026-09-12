"""Unit tests for ``ReadOnlyDeviceReader`` -- allowlist, sanitization,
and structural read-only-ness. Uses ``tests/fake_transport.py``; never a
live MikroTik.
"""

from __future__ import annotations

import inspect

import pytest
from librouteros.exceptions import LibRouterosError
from fake_transport import make_connect_fn
from wyfy_device_gateway.contract import DeviceCredentials, DeviceVendor
from wyfy_device_gateway.mikrotik_adapter import MikroTikConnectionError
from wyfy_device_gateway.read_only_reader import (
    READ_ONLY_SECTION_PATHS,
    SANITIZED_ROW_FIELDS,
    ReadOnlyDeviceReader,
    ReadOnlyViolationError,
)

CREDS = DeviceCredentials(
    vendor=DeviceVendor.MIKROTIK,
    host="10.0.0.1",
    username="admin",
    secret="secret",
)


def _reader(sections=None, *, failing=(), connect_error=None) -> tuple[ReadOnlyDeviceReader, list]:
    connect_fn, opened = make_connect_fn(
        sections or {}, failing=failing, connect_error=connect_error
    )
    return ReadOnlyDeviceReader(CREDS, connect_fn=connect_fn), opened


def test_section_names_cover_spec_p1_categories() -> None:
    names = set(ReadOnlyDeviceReader.section_names())
    # A–F coverage: system, interfaces, bridges, WAN, DNS, services.
    assert {"system_resource", "system_routerboard", "system_identity"} <= names
    assert {"interfaces", "vlan_interfaces", "interface_lists"} <= names
    assert {"bridges", "bridge_ports", "bridge_vlans"} <= names
    assert {"dhcp_clients", "pppoe_clients", "routes", "ip_addresses"} <= names
    assert "dns" in names
    assert {"dhcp_servers", "hotspot_servers", "radius", "wireguard_interfaces"} <= names
    assert "firewall_filter" in names and "firewall_nat" in names


def test_public_surface_has_no_mutating_methods() -> None:
    forbidden = {
        "push_config",
        "restore",
        "backup",
        "upload_file",
        "execute_raw_command",
        "configure_vlan",
        "reboot_device",
        "provision_device",
    }
    public = {
        name
        for name, member in inspect.getmembers(ReadOnlyDeviceReader)
        if not name.startswith("_") and callable(member)
    }
    assert public == {"section_names", "read_section", "read_all"}
    assert forbidden.isdisjoint(dir(ReadOnlyDeviceReader))


@pytest.mark.asyncio
async def test_unknown_section_raises_before_any_socket_io() -> None:
    reader, opened = _reader()
    with pytest.raises(ReadOnlyViolationError) as exc_info:
        await reader.read_section("not_a_real_section")
    assert exc_info.value.section == "not_a_real_section"
    assert opened == []


@pytest.mark.asyncio
async def test_read_all_sanitizes_secret_fields() -> None:
    sections = {
        ("interface", "pppoe-client"): [
            {"name": "pppoe-wan1", "password": "super-secret", "disabled": False}
        ],
        ("interface", "wireguard"): [
            {"name": "wg-cloud", "private-key": "WGPRIVATE", "listen-port": 51820}
        ],
        ("radius",): [{"address": "10.9.0.1", "secret": "rad-secret", "service": "hotspot"}],
        ("system", "scheduler"): [
            {
                "name": "cloudguest-heartbeat",
                "on-event": '/tool fetch url="https://api.example/agent/heartbeat?token=abc"',
            }
        ],
        ("interface",): [{"name": "ether1", "type": "ether", "running": True}],
    }
    reader, opened = _reader(sections)
    capture = await reader.read_all(
        sections=(
            "pppoe_clients",
            "wireguard_interfaces",
            "radius",
            "system_schedulers",
            "interfaces",
        )
    )

    assert opened[0].closed is True
    assert "password" not in capture.sections["pppoe_clients"][0]
    assert capture.sections["pppoe_clients"][0]["has_password"] is True
    assert "private-key" not in capture.sections["wireguard_interfaces"][0]
    assert capture.sections["wireguard_interfaces"][0]["has_private_key"] is True
    assert "secret" not in capture.sections["radius"][0]
    assert capture.sections["radius"][0]["has_secret"] is True
    assert "on-event" not in capture.sections["system_schedulers"][0]
    assert capture.sections["system_schedulers"][0]["has_on_event"] is True
    # Non-secret rows pass through untouched.
    assert capture.sections["interfaces"][0]["name"] == "ether1"


@pytest.mark.asyncio
async def test_read_all_captures_per_section_errors_without_aborting() -> None:
    sections = {
        ("interface",): [{"name": "ether1"}],
        ("ip", "address"): [{"address": "10.0.0.1/24", "interface": "bridgeLocal"}],
    }
    reader, _ = _reader(
        sections,
        failing={("interface", "wireguard")},
    )
    capture = await reader.read_all(
        sections=("interfaces", "ip_addresses", "wireguard_interfaces")
    )
    assert "interfaces" in capture.sections
    assert "ip_addresses" in capture.sections
    assert "wireguard_interfaces" not in capture.sections
    assert "wireguard_interfaces" in capture.errors


@pytest.mark.asyncio
async def test_read_section_propagates_device_menu_error() -> None:
    reader, _ = _reader({}, failing={("routing", "table")})
    with pytest.raises(LibRouterosError):
        await reader.read_section("routing_tables")


@pytest.mark.asyncio
async def test_connect_failure_becomes_mikrotik_connection_error() -> None:
    reader, opened = _reader(connect_error=OSError("connection refused"))
    with pytest.raises(MikroTikConnectionError):
        await reader.read_all(sections=("interfaces",))
    assert opened == []


@pytest.mark.asyncio
async def test_every_allowlisted_path_is_reachable_via_fake_transport() -> None:
    """Regression: the allowlist map and the fake path keys stay aligned
    so a typo in READ_ONLY_SECTION_PATHS cannot silently skip a section."""
    canned = {path: [{"_section": name}] for name, path in READ_ONLY_SECTION_PATHS.items()}
    reader, opened = _reader(canned)
    capture = await reader.read_all()
    assert set(capture.sections) == set(READ_ONLY_SECTION_PATHS)
    assert capture.errors == {}
    # Every allowlisted path was actually requested exactly once.
    assert sorted(opened[0].path_calls) == sorted(READ_ONLY_SECTION_PATHS.values())


def test_sanitized_fields_do_not_include_public_key() -> None:
    assert "public-key" not in SANITIZED_ROW_FIELDS
    assert "private-key" in SANITIZED_ROW_FIELDS
    assert "password" in SANITIZED_ROW_FIELDS
    assert "secret" in SANITIZED_ROW_FIELDS


# ============================================================================
# Venue diagnostics read-set (section G)
# ============================================================================


def test_venue_diagnostic_sections_are_allowlisted_at_the_right_paths() -> None:
    """The four reads the Connection Tools redesign is built on. The exact
    path tuples matter -- a plausible-but-wrong one (``ip/hotspot/hosts``,
    ``interface/bridge/hosts``) raises on the device, and per-section error
    capture would degrade that to a quietly missing tile rather than a
    failure anyone notices."""
    assert READ_ONLY_SECTION_PATHS["hotspot_hosts"] == ("ip", "hotspot", "host")
    assert READ_ONLY_SECTION_PATHS["bridge_hosts"] == (
        "interface",
        "bridge",
        "host",
    )
    assert READ_ONLY_SECTION_PATHS["neighbors"] == ("ip", "neighbor")
    assert READ_ONLY_SECTION_PATHS["dns_cache"] == ("ip", "dns", "cache")


@pytest.mark.asyncio
async def test_venue_diagnostic_sections_read_real_rows() -> None:
    """Each of the four returns its rows through the reader unchanged --
    these carry no secret-bearing fields, so sanitization must not eat
    anything. Rows are shaped as the real menus reply."""
    canned = {
        ("ip", "hotspot", "host"): [
            {"mac-address": "AA:BB:CC:DD:EE:01", "address": "10.5.50.20",
             "authorized": "false", "bypassed": "false"},
        ],
        ("interface", "bridge", "host"): [
            {"mac-address": "C0:3A:55:11:22:33", "on-interface": "ether2",
             "bridge": "bridge", "local": "false"},
        ],
        ("ip", "neighbor"): [
            {"interface": "ether2", "address": "192.168.0.254",
             "identity": "AP-1", "platform": "TP-Link", "board": "EAP225"},
        ],
        ("ip", "dns", "cache"): [
            {"name": "wifi.wyfyguest.com", "type": "A",
             "data": "10.5.50.1", "ttl": "1d"},
        ],
    }
    reader, _ = _reader(canned)

    hotspot_hosts = await reader.read_section("hotspot_hosts")
    bridge_hosts = await reader.read_section("bridge_hosts")
    neighbors = await reader.read_section("neighbors")
    dns_cache = await reader.read_section("dns_cache")

    # The whole point of hotspot_hosts: "on the network but not logged in"
    # is a state the platform previously could not see at all.
    assert hotspot_hosts[0]["authorized"] == "false"
    # The whole point of bridge_hosts: which physical port, hence which AP.
    assert bridge_hosts[0]["on-interface"] == "ether2"
    assert neighbors[0]["identity"] == "AP-1"
    assert dns_cache[0]["data"] == "10.5.50.1"


@pytest.mark.asyncio
async def test_absent_venue_diagnostic_menu_degrades_one_section_only() -> None:
    """A router with no hotspot configured has no ``/ip/hotspot/host``
    menu, and an AP that speaks no LLDP leaves ``/ip/neighbor`` empty.
    Neither may cost the other three sections -- this is the property that
    lets a diagnostics page show a dead tile instead of a dead page."""
    reader, _ = _reader(
        {
            ("interface", "bridge", "host"): [{"mac-address": "AA:BB:CC:DD:EE:01"}],
            ("ip", "neighbor"): [],
            ("ip", "dns", "cache"): [{"name": "example.com"}],
        },
        failing=[("ip", "hotspot", "host")],
    )

    capture = await reader.read_all(
        ["hotspot_hosts", "bridge_hosts", "neighbors", "dns_cache"]
    )

    assert "hotspot_hosts" in capture.errors
    assert capture.sections["bridge_hosts"] == [{"mac-address": "AA:BB:CC:DD:EE:01"}]
    # Empty is a real, expected answer for neighbour discovery on this
    # fleet -- distinct from the error above, and it must not be conflated.
    assert capture.sections["neighbors"] == []
    assert capture.sections["dns_cache"] == [{"name": "example.com"}]


def test_dangerous_tools_are_not_reachable_through_this_reader() -> None:
    """`/tool/bandwidth-test` saturates a live venue's uplink and `/tool/torch`
    streams forever without a server-enforced duration. Neither belongs on
    a customer path. This asserts the omission on purpose, so re-adding one
    has to be a deliberate act that breaks a test naming the reason."""
    paths = set(READ_ONLY_SECTION_PATHS.values())
    assert ("tool", "bandwidth-test") not in paths
    assert ("tool", "torch") not in paths
    assert ("tool", "sniffer") not in paths
    for segments in paths:
        assert segments[:2] != ("tool", "bandwidth-test")
        assert "torch" not in segments
