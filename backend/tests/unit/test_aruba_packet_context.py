"""``aruba_packet_context``: AP MAC / SSID / AP serial from the shared
listener's headers, with the shapes MEASURED on the AP21 (Instant On 3.4.2,
staging capture 2026-10-03): bare lower-case Called-Station-Id, SSID only in
Aruba-Essid-Name, serial in Aruba-Location-Id."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.domains.guest.aruba_packet_context import (
    AP_SERIAL_HEADER,
    ESSID_HEADER,
    aruba_packet_context,
)
from app.domains.guest.ssid_tiers import ssid_from_called_station_id

CSID = "X-RADIUS-Called-Station-Id"


def test_real_ap21_access_request_shape() -> None:
    ctx = aruba_packet_context(
        {
            CSID: "54f0b1c8a90a",
            ESSID_HEADER: "WYFY_ARUBA",
            AP_SERIAL_HEADER: "VNV5M1K1M6",
        }
    )
    assert ctx.ap_mac == "54:F0:B1:C8:A9:0A"
    assert ctx.ssid == "WYFY_ARUBA"
    assert ctx.ssid_source == "vsa"
    assert ctx.ap_serial == "VNV5M1K1M6"
    assert ctx.called_station_id_with_ssid == "54-F0-B1-C8-A9-0A:WYFY_ARUBA"
    # The speed-tier gate's own parser now finds the SSID it never saw.
    assert ssid_from_called_station_id(ctx.called_station_id_with_ssid) == "WYFY_ARUBA"
    assert ssid_from_called_station_id(ctx.called_station_id) is None


def test_interim_has_empty_vendor_headers() -> None:
    """FreeRADIUS expands a missing attribute to an empty string."""
    ctx = aruba_packet_context(
        {CSID: "54f0b1c8a90a", ESSID_HEADER: "", AP_SERIAL_HEADER: ""}
    )
    assert ctx.ap_mac == "54:F0:B1:C8:A9:0A"
    assert ctx.ssid is None and ctx.ssid_source is None and ctx.ap_serial is None
    assert ctx.called_station_id_with_ssid == "54f0b1c8a90a"


def test_rfc3580_suffix_still_works_without_the_vsa() -> None:
    ctx = aruba_packet_context({CSID: "54-F0-B1-C8-A9-0A:WYFY_PREMIUM"})
    assert ctx.ssid == "WYFY_PREMIUM"
    assert ctx.ssid_source == "called_station_id"
    assert ctx.called_station_id_with_ssid == "54-F0-B1-C8-A9-0A:WYFY_PREMIUM"


def test_vsa_wins_over_a_suffix() -> None:
    ctx = aruba_packet_context(
        {CSID: "54-F0-B1-C8-A9-0A:OLD", ESSID_HEADER: "WYFY_PREMIUM"}
    )
    assert ctx.ssid == "WYFY_PREMIUM"
    assert ctx.called_station_id_with_ssid == "54-F0-B1-C8-A9-0A:WYFY_PREMIUM"


def test_ssid_with_colon_round_trips() -> None:
    ctx = aruba_packet_context({CSID: "54f0b1c8a90a", ESSID_HEADER: "Cafe:Guest"})
    assert ssid_from_called_station_id(ctx.called_station_id_with_ssid) == "Cafe:Guest"


@pytest.mark.parametrize("bad", ["x" * 33, "bad\nssid", "   ", "a\x00b"])
def test_unusable_ssid_is_none(bad: str) -> None:
    ctx = aruba_packet_context({CSID: "54f0b1c8a90a", ESSID_HEADER: bad})
    assert ctx.ssid is None
    assert ctx.called_station_id_with_ssid == "54f0b1c8a90a"


@pytest.mark.parametrize("bad", ["x" * 33, "VNV 5M1", "a;b", ""])
def test_unusable_serial_is_none(bad: str) -> None:
    assert aruba_packet_context({AP_SERIAL_HEADER: bad}).ap_serial is None


def test_no_called_station_id() -> None:
    ctx = aruba_packet_context({ESSID_HEADER: "WYFY_ARUBA"})
    assert ctx.ap_mac is None and ctx.called_station_id is None
    # No MAC -> nothing synthesized; the resolver refuses this packet anyway.
    assert ctx.called_station_id_with_ssid is None


def test_shared_site_forwards_the_vendor_headers() -> None:
    """The listener must keep forwarding both vendor attributes on authorize
    AND accounting, under the names this module reads."""
    conf = (
        Path(__file__).resolve().parents[2]
        / "ops"
        / "freeradius"
        / "sites-aruba-shared.conf"
    ).read_text()
    assert conf.count(f'"{ESSID_HEADER}: %{{Aruba-Essid-Name}}"') == 2
    assert conf.count(f'"{AP_SERIAL_HEADER}: %{{Aruba-Location-Id}}"') == 2
