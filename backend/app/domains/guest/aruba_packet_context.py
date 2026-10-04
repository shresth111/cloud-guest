"""What a shared-listener RADIUS packet says about WHERE the guest is: the
access point and the WiFi network (SSID). Read from the identity headers
FreeRADIUS's ``wyfy_aruba_shared`` server forwards (``backend/ops/freeradius/
sites-aruba-shared.conf``); nothing here authenticates anything.

## Why this exists (measured on the AP21, Instant On 3.4.2, 2026-10-03)

Every packet the real access point sent carried ``Called-Station-Id`` as the
bare AP MAC in lower-case hex -- ``54f0b1c8a90a`` -- with **no** ``:<SSID>``
suffix (Access-Request, Accounting Start, Interim and Stop alike). The
RFC 3580 ``AA-BB-CC-DD-EE-FF:SSID`` spelling only ever came from QA
``radclient`` runs. The SSID travels in the Aruba vendor attribute
``Aruba-Essid-Name`` (14823/5), on Access-Request and Accounting-Start; the
Access-Request also carries ``Aruba-Location-Id`` (14823/6), which Instant
On fills with the AP's serial number.

So parsing the SSID out of ``Called-Station-Id`` alone (the speed tiers by
WiFi network gate, ``ssid_tiers.ssid_from_called_station_id``) finds nothing
on real hardware and fails open. The listener now forwards the two vendor
attributes as headers, and this module merges them.

Every value here comes from the packet, i.e. from whoever holds the Aruba
shared RADIUS secret -- which every Aruba customer does. Use it to label
and count, never as proof of identity (the resolver's NAS-Identifier + AP MAC
check is the only gate).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

from .aruba_shared import CALLED_STATION_ID_HEADER, ap_mac_from_called_station_id
from .ssid_tiers import MAX_SSID_LENGTH, ssid_from_called_station_id

#: ``Aruba-Essid-Name`` (14823/5) as forwarded by the shared listener.
ESSID_HEADER = "X-RADIUS-Aruba-Essid-Name"
#: ``Aruba-Location-Id`` (14823/6): the AP serial on Instant On.
AP_SERIAL_HEADER = "X-RADIUS-Aruba-Location-Id"

_MAX_SERIAL_LENGTH = 32
_SERIAL_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")


def _clean_ssid(raw: str | None) -> str | None:
    if raw is None:
        return None
    value = raw.strip()
    if not value or len(value) > MAX_SSID_LENGTH or _CONTROL_CHARS_RE.search(value):
        return None
    return value


def _clean_serial(raw: str | None) -> str | None:
    if raw is None:
        return None
    value = raw.strip()
    if not value or len(value) > _MAX_SERIAL_LENGTH or not _SERIAL_RE.match(value):
        return None
    return value


@dataclass(frozen=True, slots=True)
class ArubaPacketContext:
    """``ap_mac`` canonical ``AA:BB:CC:DD:EE:FF`` or None; ``ssid`` from the
    vendor attribute, else from a ``:<SSID>`` suffix, else None;
    ``ssid_source`` says which (``"vsa"`` / ``"called_station_id"``)."""

    called_station_id: str | None
    ap_mac: str | None
    ssid: str | None
    ssid_source: str | None
    ap_serial: str | None

    @property
    def called_station_id_with_ssid(self) -> str | None:
        """``Called-Station-Id`` in the RFC 3580 ``AA-BB-CC-DD-EE-FF:SSID``
        form whenever both halves are known -- the shape the speed-tier gate
        parses -- else the raw value unchanged (so a bare MAC with no SSID
        still reaches the gate and is logged ``radius_authorize_ssid_unknown``
        exactly as before)."""
        if self.ap_mac is None or self.ssid is None:
            return self.called_station_id
        return f"{self.ap_mac.replace(':', '-')}:{self.ssid}"


def aruba_packet_context(headers: Mapping[str, str]) -> ArubaPacketContext:
    raw_csid = headers.get(CALLED_STATION_ID_HEADER)
    called_station_id = raw_csid.strip() if raw_csid and raw_csid.strip() else None
    ap_mac = ap_mac_from_called_station_id(called_station_id)
    ssid = _clean_ssid(headers.get(ESSID_HEADER))
    source = "vsa" if ssid else None
    if ssid is None:
        ssid = ssid_from_called_station_id(called_station_id)
        source = "called_station_id" if ssid else None
    return ArubaPacketContext(
        called_station_id=called_station_id,
        ap_mac=ap_mac,
        ssid=ssid,
        ssid_source=source,
        ap_serial=_clean_serial(headers.get(AP_SERIAL_HEADER)),
    )


__all__ = [
    "AP_SERIAL_HEADER",
    "ESSID_HEADER",
    "ArubaPacketContext",
    "aruba_packet_context",
]
