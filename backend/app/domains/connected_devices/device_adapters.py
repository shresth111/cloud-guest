"""Real device I/O adapters for the Connected Device Management domain --
the Strategy/Adapter seam that keeps this domain's own core engine
(``service.py``) completely vendor-agnostic, mirroring
``app.domains.isp.device_adapters``'s identical shape (same
``librouteros`` dependency, same "one vendor registered today" registry,
same honest-about-being-unexercised-against-a-live-device posture).

## Honest scope: real client code, never exercised end-to-end here

:class:`MikroTikConnectedDeviceAdapter` issues genuine RouterOS API
queries -- ``/ip/dhcp-server/lease``, ``/ip/arp``, and
``/interface/wireless/registration-table`` -- via the same
``librouteros.connect(...)`` connection this codebase's other MikroTik
adapters already open, using the ``.path(...)`` menu-iteration form every
other adapter (``queue_management``, ``provisioning_engine``) already
uses -- unlike ``app.domains.isp.device_adapters``, this module never
needs the raw ``Api.__call__`` command form, since listing a menu's rows
is ordinary CRUD-style iteration. There is no live MikroTik device
anywhere in this sandbox -- if actually invoked, this raises a real
:class:`~.exceptions.ConnectedDeviceConnectionError` the moment it tries
to open a real socket, never fabricated device data.

## Legacy wireless registration table, not CAPsMAN

This adapter queries ``/interface/wireless/registration-table`` (the
legacy wireless package). A CAPsMAN-managed deployment's own
``/caps-man/registration-table`` is a real, documented gap -- a genuine
future seam, not silently assumed equivalent.

## Merging three menus by MAC address

Each of the three RouterOS menus above answers a different question
about the same device (DHCP lease -> hostname/IP/active status; ARP ->
IP/interface for non-DHCP devices; wireless registration table ->
wireless-only signal/interface data). ``_merge_discovered_devices``
merges all three by MAC address (case-insensitively, via
``validators.normalize_mac_address``) into one
:class:`DiscoveredDevice` per MAC -- a device present in more than one
source is a single row, never duplicated.

## Disconnect: a real, but partial, action

Removing a device from ``/interface/wireless/registration-table`` is a
genuine wireless "kick" -- the client must re-associate. There is no
equivalent forced disconnect for a *wired* client; removing its ARP/DHCP
lease entry only prevents easy re-association on the same IP, it does
not sever an existing wired link. This is a real, honest limitation,
documented rather than silently overstated.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Protocol

import librouteros
from librouteros.exceptions import LibRouterosError

from .exceptions import (
    ConnectedDeviceConnectionError,
    ConnectedDeviceOperationError,
    UnsupportedConnectedDeviceVendorError,
)
from .validators import normalize_mac_address

logger = logging.getLogger(__name__)

_DEFAULT_API_PORT = 8728


@dataclass(frozen=True, slots=True)
class DeviceCredentials:
    """What an adapter needs to open a real connection -- resolved by the
    caller from the target ``Router``'s own connection fields, mirroring
    ``app.domains.isp.device_adapters.IspCredentials`` exactly."""

    host: str
    username: str
    password: str
    api_port: int = _DEFAULT_API_PORT
    timeout_seconds: int = 10


@dataclass(frozen=True, slots=True)
class DiscoveredDevice:
    """One real device merged from the router's own DHCP-lease/ARP/
    wireless-registration-table replies."""

    mac_address: str
    ip_address: str | None
    hostname: str | None
    interface: str | None
    is_wireless: bool
    signal_strength_dbm: int | None


class BaseConnectedDeviceAdapter(Protocol):
    """What a vendor implements to plug real device discovery/disconnect
    into the Connected Device Management domain. A new vendor is
    exactly: implement this Protocol, register it (mirrors
    ``app.domains.isp.device_adapters``'s own registry pattern)."""

    vendor: str

    async def discover_devices(
        self, credentials: DeviceCredentials
    ) -> list[DiscoveredDevice]:
        """Returns every device currently visible in the router's own
        DHCP-lease/ARP/wireless-registration-table state, merged by MAC
        address."""
        ...

    async def disconnect_device(
        self, credentials: DeviceCredentials, *, mac_address: str, interface: str | None
    ) -> None:
        """Best-effort disconnect -- a real wireless kick if the device
        is wireless, otherwise only an ARP/DHCP-lease removal (see
        module docstring's own "real, but partial" scope note)."""
        ...


class MikroTikConnectedDeviceAdapter:
    """See module docstring for the full "real client code, untested
    end-to-end here" write-up."""

    vendor = "mikrotik"

    async def discover_devices(
        self, credentials: DeviceCredentials
    ) -> list[DiscoveredDevice]:
        return await asyncio.to_thread(self._discover_sync, credentials)

    async def disconnect_device(
        self, credentials: DeviceCredentials, *, mac_address: str, interface: str | None
    ) -> None:
        await asyncio.to_thread(
            self._disconnect_sync, credentials, mac_address, interface
        )

    def _connect_api(self, credentials: DeviceCredentials):  # noqa: ANN202
        try:
            return librouteros.connect(
                host=credentials.host,
                username=credentials.username,
                password=credentials.password,
                port=credentials.api_port,
                timeout=credentials.timeout_seconds,
            )
        except (LibRouterosError, OSError) as exc:
            raise ConnectedDeviceConnectionError(credentials.host, str(exc)) from exc

    def _discover_sync(self, credentials: DeviceCredentials) -> list[DiscoveredDevice]:
        api = self._connect_api(credentials)
        try:
            try:
                leases = list(api.path("ip", "dhcp-server", "lease"))
                arp_entries = list(api.path("ip", "arp"))
                wireless_entries = list(
                    api.path("interface", "wireless", "registration-table")
                )
            except LibRouterosError as exc:
                raise ConnectedDeviceOperationError(
                    "discover_devices", str(exc)
                ) from exc
        finally:
            api.close()
        return _merge_discovered_devices(leases, arp_entries, wireless_entries)

    def _disconnect_sync(
        self,
        credentials: DeviceCredentials,
        mac_address: str,
        interface: str | None,
    ) -> None:
        api = self._connect_api(credentials)
        try:
            try:
                wireless_menu = api.path("interface", "wireless", "registration-table")
                for row in wireless_menu:
                    if _row_mac(row) == mac_address:
                        wireless_menu.remove(row.get(".id"))
                        break
                dhcp_menu = api.path("ip", "dhcp-server", "lease")
                for row in dhcp_menu:
                    if _row_mac(row) == mac_address:
                        dhcp_menu.remove(row.get(".id"))
                        break
            except LibRouterosError as exc:
                raise ConnectedDeviceOperationError(
                    "disconnect_device", str(exc)
                ) from exc
        finally:
            api.close()


def _row_mac(row: dict[str, object]) -> str | None:
    return normalize_mac_address(row.get("mac-address"))  # type: ignore[arg-type]


def _merge_discovered_devices(
    leases: list[dict[str, object]],
    arp_entries: list[dict[str, object]],
    wireless_entries: list[dict[str, object]],
) -> list[DiscoveredDevice]:
    """Merges all three RouterOS replies into one :class:`DiscoveredDevice`
    per MAC address -- see module docstring."""
    wireless_by_mac: dict[str, dict[str, object]] = {}
    for row in wireless_entries:
        mac = _row_mac(row)
        if mac is not None:
            wireless_by_mac[mac] = row

    merged: dict[str, DiscoveredDevice] = {}

    for row in arp_entries:
        mac = _row_mac(row)
        if mac is None:
            continue
        merged[mac] = DiscoveredDevice(
            mac_address=mac,
            ip_address=_safe_str(row.get("address")),
            hostname=None,
            interface=_safe_str(row.get("interface")),
            is_wireless=mac in wireless_by_mac,
            signal_strength_dbm=None,
        )

    for row in leases:
        mac = _row_mac(row)
        if mac is None:
            continue
        existing = merged.get(mac)
        merged[mac] = DiscoveredDevice(
            mac_address=mac,
            ip_address=_safe_str(row.get("active-address") or row.get("address"))
            or (existing.ip_address if existing else None),
            hostname=_safe_str(row.get("host-name")),
            interface=_safe_str(row.get("interface"))
            or (existing.interface if existing else None),
            is_wireless=mac in wireless_by_mac,
            signal_strength_dbm=existing.signal_strength_dbm if existing else None,
        )

    for mac, row in wireless_by_mac.items():
        existing = merged.get(mac)
        merged[mac] = DiscoveredDevice(
            mac_address=mac,
            ip_address=existing.ip_address if existing else None,
            hostname=existing.hostname if existing else None,
            interface=_safe_str(row.get("interface"))
            or (existing.interface if existing else None),
            is_wireless=True,
            signal_strength_dbm=_parse_signal_strength(row.get("signal-strength")),
        )

    return list(merged.values())


def _safe_str(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _parse_signal_strength(value: object) -> int | None:
    """RouterOS reports signal strength as e.g. ``"-55dBm@6Mbps"`` or
    plain ``"-55"`` depending on version -- extracts the leading signed
    integer, or ``None`` if the field is missing/unparsable (never
    crashes a sync over one odd field)."""
    if value is None:
        return None
    text = str(value)
    digits = ""
    for index, char in enumerate(text):
        if (char in "+-" and index == 0) or char.isdigit():
            digits += char
        else:
            break
    try:
        return int(digits)
    except ValueError:
        return None


_CONNECTED_DEVICE_ADAPTERS: dict[str, BaseConnectedDeviceAdapter] = {
    "mikrotik": MikroTikConnectedDeviceAdapter()
}


def get_connected_device_adapter(vendor: str) -> BaseConnectedDeviceAdapter:
    """Raises :class:`~.exceptions.UnsupportedConnectedDeviceVendorError`
    if no adapter is registered for ``vendor``."""
    adapter = _CONNECTED_DEVICE_ADAPTERS.get(vendor)
    if adapter is None:
        raise UnsupportedConnectedDeviceVendorError(vendor)
    return adapter


def list_supported_connected_device_vendors() -> list[str]:
    return sorted(_CONNECTED_DEVICE_ADAPTERS)


__all__ = [
    "DeviceCredentials",
    "DiscoveredDevice",
    "BaseConnectedDeviceAdapter",
    "MikroTikConnectedDeviceAdapter",
    "get_connected_device_adapter",
    "list_supported_connected_device_vendors",
]
