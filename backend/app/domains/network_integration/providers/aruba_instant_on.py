"""Aruba Instant On provider -- the **read half** of the provider seam.

## What this is, and what it deliberately is not

The read methods of :class:`~.base.NetworkProvider` (``test_connection``,
``get_controller_info``, ``list_sites``, ``list_ssids``, ``list_devices``,
``list_clients``, ``get_client``) plus ``client_capabilities``, which
answers "cannot" for every client action. There is **no** authorize,
deauthorize, configure, rate-limit or block method at all -- not even one
that raises. Guests at an Instant On venue are authorized by RADIUS
(``app.domains.guest``), and the owner's decision on 2026-10-02 was a
read-only integration: an object with no write method cannot be talked into
one.

That is also why this provider is **not** in ``providers._PROVIDER_PATHS``
and ``aruba_instant_on`` is not a ``NetworkProviderKind``: that registry
backs ``network_integrations`` rows, and ``NetworkIntegrationService``
calls write methods on whatever it resolves. An Instant On venue is a
NAS-only fleet ``Router`` row plus an ``instant_on_sites`` row (see
``models.InstantOnSite``), polled by ``instant_on_tasks``.

## Credentials do not come through ``ProviderConnectionConfig``

Every venue is read with the same Wyfy service account (invited per site as
Viewer), so the authenticated :class:`InstantOnClient` is a constructor
argument, and the ``config`` parameters on the seam methods exist only for
signature compatibility. No per-venue secret exists to put in one.

## Mapping rules

Field names are from REAL_DATA_SPIKE.md section 2.2. Where the bundle and a
live read disagree on a spelling (``status`` vs ``operationalState``,
``softwareVersion`` vs ``firmwareVersion``) both are accepted -- the same
alternates the measured ``monitor/check.js`` accepts -- and nothing else is
guessed. An element missing the field that identifies it (a client with no
``macAddress``, a network with no name) is drift and fails the whole read:
half a list presented as the list is the "stale data shown as current"
failure in another form.

``signal_dbm`` is always ``None``: the bundle's client model has
``signalQuality`` (a category) and ``snrInDb`` but no RSSI-in-dBm field.
Hardware check H1 settles it; until then no dBm number is invented.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

from .aruba_instant_on_client import InstantOnApiDriftError, InstantOnClient
from .base import (
    ProviderCapability,
    ProviderClient,
    ProviderClientCapabilities,
    ProviderConnectionConfig,
    ProviderControllerInfo,
    ProviderDevice,
    ProviderSite,
    ProviderSsid,
)

__all__ = [
    "ARUBA_INSTANT_ON_PROVIDER_KIND",
    "ArubaInstantOnProvider",
    "InstantOnAccessPoint",
    "InstantOnAlert",
    "InstantOnClientRecord",
    "InstantOnClientUsage",
    "InstantOnHealth",
    "InstantOnNetwork",
    "map_access_point",
    "map_alert",
    "map_client",
    "map_client_usage",
    "map_health",
    "map_network",
    "to_jsonable",
]

ARUBA_INSTANT_ON_PROVIDER_KIND = "aruba_instant_on"

_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}([:-]?)[0-9A-Fa-f]{2}(\1[0-9A-Fa-f]{2}){4}$")

_UNSUPPORTED_REASON = (
    "Aruba Instant On is connected read-only: device actions are made in the "
    "Instant On app."
)


# ============================================================================
# Normalized records (what the poller stores and the API returns)
# ============================================================================


@dataclass(frozen=True, slots=True)
class InstantOnAccessPoint:
    mac: str | None
    serial_number: str | None
    name: str | None
    model: str | None
    status: str  # online | offline | unknown
    status_raw: str | None
    ip_address: str | None
    firmware_version: str | None
    uptime_seconds: int | None


@dataclass(frozen=True, slots=True)
class InstantOnClientRecord:
    mac: str
    client_id: str | None
    name: str | None
    hostname: str | None
    ip_address: str | None
    connection: str  # wireless | wired
    ssid: str | None
    ssid_id: str | None
    radio_id: str | None
    bands: tuple[str, ...]
    signal_quality: str | None
    snr_db: int | None
    signal_dbm: int | None  # always None until H1 finds a dBm field
    health: str | None
    status: str | None
    downstream_bytes: int | None
    upstream_bytes: int | None
    downstream_bps: int | None
    upstream_bps: int | None
    connected_seconds: int | None


@dataclass(frozen=True, slots=True)
class InstantOnNetwork:
    ssid_id: str | None
    name: str
    enabled: bool | None
    network_type: str | None
    guest_portal_enabled: bool | None


@dataclass(frozen=True, slots=True)
class InstantOnAlert:
    alert_id: str | None
    type: str
    severity: str | None
    status: str | None
    is_cleared: bool | None
    raised_at: str | None  # ISO-8601 UTC
    cleared_at: str | None
    duration_seconds: int | None
    device_name: str | None


@dataclass(frozen=True, slots=True)
class InstantOnClientUsage:
    client_id: str | None
    client_name: str | None
    currently_active: bool | None
    bytes_last_24h: int | None
    application_category: str | None


@dataclass(frozen=True, slots=True)
class InstantOnHealth:
    score: int | None
    status: str | None


def to_jsonable(record: Any) -> dict[str, Any]:
    data = asdict(record)
    return {k: list(v) if isinstance(v, tuple) else v for k, v in data.items()}


# ============================================================================
# Field helpers
# ============================================================================


def _first(d: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = d.get(key)
        if value is not None and value != "":
            return value
    return None


def _str(value: Any) -> str | None:
    if value is None or isinstance(value, dict | list):
        return None
    text = str(value).strip()
    return text or None


def _int(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(float(value.strip()))
        except ValueError:
            return None
    return None


def _bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _mac(value: Any) -> str | None:
    text = _str(value)
    if text is None or not _MAC_RE.match(text):
        return None
    hex_only = re.sub(r"[:-]", "", text).upper()
    return ":".join(hex_only[i : i + 2] for i in range(0, 12, 2))


def _timestamp(value: Any) -> str | None:
    """Epoch seconds/milliseconds or an ISO string -> ISO-8601 UTC. The wire
    format of ``raisedTime`` is UNMEASURED, so an unparseable value becomes
    ``None`` rather than drift: the alert itself is still real."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int | float):
        seconds = value / 1000 if value > 1e11 else value
        try:
            return datetime.fromtimestamp(seconds, tz=UTC).isoformat()
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC).isoformat()
    return None


def _ap_status(raw: str | None) -> str:
    value = (raw or "").lower()
    if value in {"up", "online", "active", "connected"}:
        return "online"
    if value in {"down", "offline", "disconnected", "inactive"}:
        return "offline"
    return "unknown"


def _bands(value: Any) -> tuple[str, ...]:
    if isinstance(value, list):
        return tuple(str(v) for v in value if _str(v))
    text = _str(value)
    return (text,) if text else ()


# ============================================================================
# Mappers -- pure, one per resource
# ============================================================================


def map_access_point(element: dict[str, Any]) -> InstantOnAccessPoint:
    mac = _mac(_first(element, "macAddress", "mac", "id"))
    serial = _str(_first(element, "serialNumber", "serial"))
    name = _str(element.get("name"))
    if mac is None and serial is None and name is None:
        raise InstantOnApiDriftError(
            "inventory element has no mac, serial or name", reason="shape_inventory"
        )
    raw_status = _str(_first(element, "status", "operationalState"))
    return InstantOnAccessPoint(
        mac=mac,
        serial_number=serial,
        name=name,
        model=_str(element.get("model")),
        status=_ap_status(raw_status),
        status_raw=raw_status,
        ip_address=_str(element.get("ipAddress")),
        firmware_version=_str(_first(element, "softwareVersion", "firmwareVersion")),
        uptime_seconds=_int(element.get("uptimeInSeconds")),
    )


def map_client(element: dict[str, Any]) -> InstantOnClientRecord:
    mac = _mac(element.get("macAddress"))
    if mac is None:
        raise InstantOnApiDriftError(
            "clientSummary element has no usable macAddress",
            reason="shape_clientSummary",
        )
    network_id = _str(element.get("wirelessNetworkId"))
    return InstantOnClientRecord(
        mac=mac,
        client_id=_str(element.get("clientId")),
        name=_str(_first(element, "clientName", "hostName")),
        hostname=_str(element.get("hostName")),
        ip_address=_str(element.get("ipAddress")),
        connection="wireless" if network_id else "wired",
        ssid=_str(element.get("wirelessNetworkName")),
        ssid_id=network_id,
        radio_id=_str(element.get("wirelessRadioId")),
        bands=_bands(element.get("wirelessBands")),
        signal_quality=_str(element.get("signalQuality")),
        snr_db=_int(element.get("snrInDb")),
        signal_dbm=None,
        health=_str(element.get("health")),
        status=_str(element.get("status")),
        downstream_bytes=_int(element.get("downstreamDataTransferredInBytes")),
        upstream_bytes=_int(element.get("upstreamDataTransferredInBytes")),
        downstream_bps=_int(element.get("downstreamThroughputInBitsPerSecond")),
        upstream_bps=_int(element.get("upstreamThroughputInBitsPerSecond")),
        connected_seconds=_int(element.get("connectionDurationInSeconds")),
    )


def map_network(element: dict[str, Any]) -> InstantOnNetwork:
    name = _str(_first(element, "networkName", "name"))
    if name is None:
        raise InstantOnApiDriftError(
            "networksSummary element has no name", reason="shape_networksSummary"
        )
    return InstantOnNetwork(
        ssid_id=_str(element.get("id")),
        name=name,
        enabled=_bool(element.get("isEnabled")),
        network_type=_str(_first(element, "type", "usage")),
        guest_portal_enabled=_bool(element.get("isGuestPortalEnabled")),
    )


def map_alert(element: dict[str, Any]) -> InstantOnAlert:
    alert_type = _str(element.get("type"))
    if alert_type is None:
        raise InstantOnApiDriftError("alert element has no type", reason="shape_alerts")
    return InstantOnAlert(
        alert_id=_str(element.get("id")),
        type=alert_type,
        severity=_str(element.get("severity")),
        status=_str(element.get("status")),
        is_cleared=_bool(element.get("isCleared")),
        raised_at=_timestamp(element.get("raisedTime")),
        cleared_at=_timestamp(element.get("clearedTime")),
        duration_seconds=_int(element.get("duration")),
        device_name=_str(element.get("deviceName")),
    )


def map_client_usage(element: dict[str, Any]) -> InstantOnClientUsage:
    client_id = _str(element.get("clientId"))
    client_name = _str(element.get("clientName"))
    if client_id is None and client_name is None:
        raise InstantOnApiDriftError(
            "usage element has no clientId/clientName", reason="shape_client_usage"
        )
    return InstantOnClientUsage(
        client_id=client_id,
        client_name=client_name,
        currently_active=_bool(element.get("clientCurrentlyActive")),
        bytes_last_24h=_int(element.get("dataTransferredDuringLast24HoursInBytes")),
        application_category=_str(element.get("applicationCategory")),
    )


def map_health(payload: dict[str, Any]) -> InstantOnHealth:
    score = _int(_first(payload, "healthScore", "score"))
    status = _str(_first(payload, "status", "healthStatus"))
    if score is None and status is None:
        raise InstantOnApiDriftError(
            "systemHealth has neither score nor status", reason="shape_systemHealth"
        )
    return InstantOnHealth(score=score, status=status)


# ============================================================================
# Provider
# ============================================================================


class ArubaInstantOnProvider:
    """Read-only. See the module docstring for why there are no write
    methods and why this is not in the provider registry."""

    kind = ARUBA_INSTANT_ON_PROVIDER_KIND
    fleet_device_vendor = ARUBA_INSTANT_ON_PROVIDER_KIND

    def __init__(self, client: InstantOnClient) -> None:
        self._client = client

    # -- Instant On reads, normalized ---------------------------------------

    async def read_access_points(self, site_id: str) -> list[InstantOnAccessPoint]:
        return [map_access_point(e) for e in await self._client.get_inventory(site_id)]

    async def read_clients(self, site_id: str) -> list[InstantOnClientRecord]:
        return [map_client(e) for e in await self._client.get_client_summary(site_id)]

    async def read_networks(self, site_id: str) -> list[InstantOnNetwork]:
        return [
            map_network(e) for e in await self._client.get_networks_summary(site_id)
        ]

    async def read_alerts(self, site_id: str) -> list[InstantOnAlert]:
        return [map_alert(e) for e in await self._client.get_alerts(site_id)]

    async def read_health(self, site_id: str) -> InstantOnHealth:
        return map_health(await self._client.get_system_health(site_id))

    async def read_client_usage_24h(self, site_id: str) -> list[InstantOnClientUsage]:
        return [
            map_client_usage(e)
            for e in await self._client.get_client_usage_24h(site_id)
        ]

    # -- NetworkProvider read half ------------------------------------------

    async def test_connection(
        self, config: ProviderConnectionConfig | None = None
    ) -> ProviderControllerInfo:
        await self._client.list_sites()
        return ProviderControllerInfo(
            controller_id="instant-on-cloud", model="Aruba Instant On"
        )

    async def get_controller_info(
        self, config: ProviderConnectionConfig | None = None
    ) -> ProviderControllerInfo:
        return await self.test_connection(config)

    async def list_sites(
        self, config: ProviderConnectionConfig | None = None
    ) -> list[ProviderSite]:
        sites: list[ProviderSite] = []
        for element in await self._client.list_sites():
            site_id = _str(element.get("id"))
            if site_id is None:
                raise InstantOnApiDriftError(
                    "sites element has no id", reason="shape_sites"
                )
            sites.append(
                ProviderSite(site_id=site_id, name=_str(element.get("name")) or site_id)
            )
        return sites

    async def list_ssids(
        self, config: ProviderConnectionConfig | None, site_id: str
    ) -> list[ProviderSsid]:
        return [
            ProviderSsid(
                ssid_id=n.ssid_id, name=n.name, portal_enabled=n.guest_portal_enabled
            )
            for n in await self.read_networks(site_id)
        ]

    async def list_devices(
        self, config: ProviderConnectionConfig | None, site_id: str
    ) -> list[ProviderDevice]:
        return [
            ProviderDevice(
                mac=ap.mac or "",
                name=ap.name,
                device_type="ap",
                model=ap.model,
                status=ap.status,
                ip_address=ap.ip_address,
                firmware_version=ap.firmware_version,
                uptime_seconds=ap.uptime_seconds,
            )
            for ap in await self.read_access_points(site_id)
        ]

    async def list_clients(
        self, config: ProviderConnectionConfig | None, site_id: str
    ) -> list[ProviderClient]:
        """Wireless clients only (SPIKE section 7: the connected-clients card
        is wireless; wired clients have no ``wirelessNetworkId``)."""
        return [
            _provider_client(c)
            for c in await self.read_clients(site_id)
            if c.connection == "wireless"
        ]

    async def get_client(
        self, config: ProviderConnectionConfig | None, site_id: str, client_mac: str
    ) -> ProviderClient | None:
        wanted = _mac(client_mac)
        if wanted is None:
            return None
        for client in await self.read_clients(site_id):
            if client.mac == wanted:
                return _provider_client(client)
        return None

    def client_capabilities(
        self, config: ProviderConnectionConfig | None = None
    ) -> ProviderClientCapabilities:
        no = ProviderCapability(supported=False, reason=_UNSUPPORTED_REASON)
        return ProviderClientCapabilities(
            set_rate_limit=no,
            clear_rate_limit=no,
            block=no,
            unblock=no,
            list_blocked=no,
            disconnect=no,
            client_stats=no,
        )


def _provider_client(client: InstantOnClientRecord) -> ProviderClient:
    return ProviderClient(
        mac=client.mac,
        name=client.name,
        ip_address=client.ip_address,
        ssid=client.ssid,
        duration_seconds=client.connected_seconds,
        traffic_down_bytes=client.downstream_bytes,
        traffic_up_bytes=client.upstream_bytes,
        signal_dbm=None,
    )
