"""Managed devices (APs, switches, gateways) for one site, via the Open API.

## Sourcing -- VERIFIED (upgraded 2026-09-10)

``GET /openapi/v1/{omadacId}/sites/{siteId}/devices`` is **VERIFIED against a
primary TP-Link source**: ``operationId: getGridSiteDevices``, summary "Get
site device list", in TP-Link's own OpenAPI 3.0.1 specification at
<https://use1-omada-northbound.tplinkcloud.com/v3/api-docs>
(rendered at ``/doc.html``; human docs at
<https://omada-northbound-docs.tplinkcloud.com/>). ``page`` and ``pageSize``
are documented as **required** query parameters, which ``get_all_pages``
already sends.

It was previously marked corroborated-only, from the community client at
<https://github.com/bullitt186/ha-omada-open-api>. That client had the path
exactly right.

## What the spec says is NOT here

Two fields this module reads for do not exist in TP-Link's ``DeviceInfo``
schema, and are left in place only as harmless fallbacks:

* **client count.** There is no ``clientNum``/``clientCount``/``clients``
  field. ``ControllerDevice.client_count`` will therefore be ``None`` for
  every device. Getting a per-AP client count means grouping the client list
  by ``apMac``, which is a caller's decision, not this parser's.
* **uptime as a number.** ``DeviceInfo.uptime`` is typed **string**, not
  integer. If a controller sends a numeric string, ``coerce_int`` parses it;
  if it sends a formatted duration ("2day(s) 3h 4m"), ``coerce_int`` returns
  ``None``. Blank is the right failure here -- a mis-parsed uptime is worse
  than an absent one -- so this is documented rather than guessed at, and
  wants confirming against a real controller.

## Field names are read defensively, on purpose

Omada's device payload differs by device class -- an AP reports
``clientNum``, a switch reports port data, a gateway reports WAN state -- and
the same logical field is spelled differently across firmware generations
(``version`` vs ``firmwareVersion``, ``ip`` vs ``ipAddr``). Every read below
therefore tries the alternatives it has actually been observed under and
falls back to ``None``.

This is not defensive programming for its own sake. This list feeds a
customer-visible inventory table, and the failure mode we are avoiding is
specific: one unfamiliar field name raising inside a list comprehension and
turning "your 12 access points" into a sync error. A device row with a
missing model string is worth far more than no rows at all.
"""

from __future__ import annotations

from typing import Any

from ..controller_contract import ControllerDevice
from .client import OmadaHttpClient
from .types import (
    coerce_int,
    coerce_str,
    normalize_device_status,
    normalize_device_type,
    normalize_mac,
)

#: VERIFIED (TP-Link OpenAPI spec, ``getGridSiteDevices``).
DEVICES_PATH = "/openapi/v1/{omadac_id}/sites/{site_id}/devices"


def _first(row: dict[str, Any], *keys: str) -> Any:
    """First key that is present and not ``None``.

    Note ``is not None`` rather than truthiness: ``0`` and ``""`` are real
    values here (a device with 0 clients, an empty name), and a truthiness
    check would skip past them to the wrong key.
    """
    for key in keys:
        if key in row and row[key] is not None:
            return row[key]
    return None


def parse_device(row: dict[str, Any]) -> ControllerDevice | None:
    """One device row -> ``ControllerDevice``, or ``None`` if unusable.

    A device with no MAC is dropped. The MAC is the only stable identity
    Omada gives us -- names are editable and ids are not consistently
    present -- so a row without one cannot be matched to anything on a later
    sync and would just accumulate duplicates.
    """
    mac = normalize_mac(_first(row, "mac", "macAddress", "deviceMac"))
    if mac is None:
        return None

    return ControllerDevice(
        mac=mac,
        name=coerce_str(_first(row, "name", "deviceName")),
        device_type=normalize_device_type(_first(row, "type", "deviceType")),
        model=coerce_str(_first(row, "model", "showModel", "modelVersion")),
        status=normalize_device_status(_first(row, "status", "statusCategory")),
        ip_address=coerce_str(_first(row, "ip", "ipAddr", "ipAddress")),
        firmware_version=coerce_str(
            _first(row, "firmwareVersion", "version", "swVersion")
        ),
        # ``uptime`` is seconds. ``uptimeLong`` is only consulted as a
        # fallback because we have seen the name but not confirmed its unit;
        # if it turns out to be milliseconds this field is wrong by 1000x for
        # the firmware that omits ``uptime``, which is why the confirmed key
        # is tried first.
        uptime_seconds=coerce_int(_first(row, "uptime", "uptimeLong")),
        client_count=coerce_int(_first(row, "clientNum", "clientCount", "clients")),
    )


async def list_devices(
    client: OmadaHttpClient, omadac_id: str, site_id: str
) -> list[ControllerDevice]:
    """Every managed device in a site."""
    rows = await client.get_all_pages(
        DEVICES_PATH.format(omadac_id=omadac_id, site_id=site_id)
    )
    devices = [parse_device(row) for row in rows]
    return [device for device in devices if device is not None]


__all__ = ["DEVICES_PATH", "list_devices", "parse_device"]
