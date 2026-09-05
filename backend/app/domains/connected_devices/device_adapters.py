"""Real device I/O adapters for the Connected Device Management domain --
the Strategy/Adapter seam that keeps this domain's own core engine
(``service.py``) completely vendor-agnostic, mirroring
``app.domains.isp.device_adapters``'s identical shape (same "one vendor
registered today" registry, same honest-about-being-unexercised-against-
a-live-device posture).

## No wireless discovery at all, and that is deliberate

The underlying MikroTik implementation used to query
``/interface/wireless/registration-table`` for a wireless/wired verdict
and a signal reading. That read was removed: every router this platform
deploys is a hEX lite / RB750r2 (RouterOS 7.23.3, mipsbe), a wired
five-port router with **no radio and no ``wireless`` package**, so the
menu does not exist. The query raised on every router, on every sweep
tick, fleet-wide, and its failure was swallowed into an empty list --
which is why nothing noticed.

Guest Wi-Fi at these venues is emitted by separate third-party access
points (TP-Link / Omada in the field) plugged into the bridge ports.
Signal strength, data rate and association state live in those APs, and
this platform does not talk to them. So this is not a gap a different
RouterOS menu would close: it is an access-point integration, tracked
separately. A CAPsMAN deployment's ``/caps-man/registration-table``
remains an equally real and equally unbuilt seam.

The consequence for every consumer of this module is that
``DiscoveredDevice.is_wireless`` is ``None`` -- see that class.

## Merging two menus by MAC address

The two surviving RouterOS menus answer different questions about the
same device (DHCP lease -> hostname/IP/active status; ARP ->
IP/interface for a device that took no lease) -- merged by MAC address
(case-insensitively) into one :class:`DiscoveredDevice` per MAC, so a
device present in both sources is a single row, never duplicated. See
``wyfy_device_gateway.mikrotik_adapter.MikroTikAdapter
.list_connected_devices``/``_merge_connected_devices`` for the real
merge logic this now delegates to.

## Disconnect: a real, but partial, action -- and on this fleet, mostly
## the lease removal

The gateway's ``disconnect_device`` still attempts a wireless
registration-table removal before removing the DHCP lease. That attempt
is a no-op on every router deployed today, for the same reason discovery
no longer queries the menu. It is retained rather than removed because
it runs only on an explicit operator action -- not every five minutes on
every router -- and it is the correct behaviour for genuinely wireless
MikroTik hardware, isolated in its own try/except so its failure cannot
cost the lease removal that actually does something here. Ending a guest
*session* is a different mechanism entirely and lives in
``app.domains.guest_access`` (``/ip hotspot active remove`` over 8728).

Removing a device from the wireless registration table is a genuine
wireless "kick" -- the client must re-associate. There is no equivalent
forced disconnect for a *wired* client; removing its ARP/DHCP lease
entry only prevents easy re-association on the same IP, it does not
sever an existing wired link. This is a real, honest limitation,
documented rather than silently overstated.

## Now delegates to wyfy-device-gateway

Per the ``wyfy-device-gateway`` PRD (section 7, Step 3, item 3),
``MikroTikConnectedDeviceAdapter``'s methods (``discover_devices``,
``disconnect_device``) now call
``wyfy_device_gateway.registry.get_adapter(DeviceVendor.MIKROTIK)``
instead of opening ``librouteros`` directly -- that package is a
straight port of this module's own ``_discover_sync``/
``_merge_discovered_devices``/``_disconnect_sync`` methods, including
the wired-only-router (no wireless package) isolation fix confirmed live
this session: the wireless-kick attempt and the DHCP-lease removal are
two independent try/except blocks in the gateway package too, so a
wired-only router still successfully falls through to the real
DHCP-lease removal even when the wireless registration-table menu
doesn't exist at all. Public signatures/return shapes are unchanged; the
gateway's ``MikroTikConnectionError``/``MikroTikDeviceError``
distinction is translated back into this domain's own
``ConnectedDeviceConnectionError``/``ConnectedDeviceOperationError``
pair.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol

from wyfy_device_gateway.contract import DeviceCredentials as _GatewayDeviceCredentials
from wyfy_device_gateway.contract import DeviceVendor
from wyfy_device_gateway.mikrotik_adapter import (
    MikroTikConnectionError,
    MikroTikDeviceError,
)
from wyfy_device_gateway.registry import get_adapter

from .exceptions import (
    ConnectedDeviceConnectionError,
    ConnectedDeviceOperationError,
    UnsupportedConnectedDeviceVendorError,
)

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
    """One real device merged from the router's own DHCP-lease/ARP
    replies.

    ``is_wireless`` is three-state and mirrors
    ``wyfy_device_gateway.contract.ConnectedDevice.is_wireless`` exactly:
    ``True``/``False`` when the router can answer, and **``None`` when it
    structurally cannot** -- no radio, no wireless package, no menu. The
    MikroTik adapter returns ``None`` for every device on every router
    this platform deploys; see that class's docstring, and
    ``MikroTikAdapter.list_connected_devices``, for why.

    ``None`` must not be collapsed into ``False`` by any consumer. Doing
    so records "this guest's phone is on a cable" for every Wi-Fi guest on
    the fleet. ``service.run_device_sync_sweep`` maps it to
    ``ConnectionType.UNKNOWN`` for exactly that reason.

    ``signal_strength_dbm`` is ``None`` whenever ``is_wireless`` is
    ``None``, permanently: the value lives in the venue's access point,
    which this platform does not talk to. It is not a pending
    measurement, and nothing downstream may substitute a placeholder for
    it.
    """

    mac_address: str
    ip_address: str | None
    hostname: str | None
    interface: str | None
    is_wireless: bool | None
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
        address-level state (DHCP leases and ARP for MikroTik), merged by
        MAC address.

        A vendor whose hardware genuinely cannot report wireless
        association must set ``is_wireless=None`` rather than ``False``
        -- see :class:`DiscoveredDevice`."""
        ...

    async def disconnect_device(
        self, credentials: DeviceCredentials, *, mac_address: str, interface: str | None
    ) -> None:
        """Best-effort disconnect -- a real wireless kick if the device
        is wireless, otherwise only an ARP/DHCP-lease removal (see
        module docstring's own "real, but partial" scope note)."""
        ...


class MikroTikConnectedDeviceAdapter:
    """See module docstring's "now delegates to wyfy-device-gateway"
    write-up."""

    vendor = "mikrotik"

    def _gateway_credentials(
        self, credentials: DeviceCredentials
    ) -> _GatewayDeviceCredentials:
        return _GatewayDeviceCredentials(
            vendor=DeviceVendor.MIKROTIK,
            host=credentials.host,
            username=credentials.username,
            secret=credentials.password,
            port=credentials.api_port,
            timeout_seconds=credentials.timeout_seconds,
        )

    async def discover_devices(
        self, credentials: DeviceCredentials
    ) -> list[DiscoveredDevice]:
        creds = self._gateway_credentials(credentials)
        try:
            results = await get_adapter(DeviceVendor.MIKROTIK).list_connected_devices(
                creds
            )
        except MikroTikConnectionError as exc:
            raise ConnectedDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikDeviceError as exc:
            raise ConnectedDeviceOperationError(
                "discover_devices", exc.detail
            ) from exc
        return [
            DiscoveredDevice(
                mac_address=device.mac_address,
                ip_address=device.ip_address,
                hostname=device.hostname,
                interface=device.interface,
                is_wireless=device.is_wireless,
                signal_strength_dbm=device.signal_strength_dbm,
            )
            for device in results
        ]

    async def disconnect_device(
        self, credentials: DeviceCredentials, *, mac_address: str, interface: str | None
    ) -> None:
        creds = self._gateway_credentials(credentials)
        try:
            await get_adapter(DeviceVendor.MIKROTIK).disconnect_device(
                creds, mac_address=mac_address, interface=interface
            )
        except MikroTikConnectionError as exc:
            raise ConnectedDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikDeviceError as exc:
            raise ConnectedDeviceOperationError(
                "disconnect_device", exc.detail
            ) from exc


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
