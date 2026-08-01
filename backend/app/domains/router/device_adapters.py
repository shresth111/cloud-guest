"""Live RouterOS interface discovery -- backs the dashboard's Interface
picker (DHCP Pool / VLAN forms) with the device's own real interface list
instead of free-text guessing, mirroring
``app.domains.connected_devices.device_adapters``'s identical
``librouteros.connect(...)`` + ``asyncio.to_thread`` shape (same vendor,
same synchronous-library-off-the-event-loop reasoning).

This is a read-only query over the same WireGuard tunnel + RouterOS API
credentials ``get_device_connection`` already resolves -- it never applies
anything, so it stays a backend endpoint like every other live-status read
in this domain (heartbeat, health-check), unlike the config-*push* path,
which is deliberately frontend-driven (see
``app.domains.network_config``'s own module docstring).

## "Already in use" -- what gets filtered out and why

An interface that already has a ``/ip dhcp-server`` bound to it cannot
take a second one (RouterOS rejects it) -- that is a hard constraint, not
a preference. An interface with a ``/ip dhcp-client`` (the WAN uplink,
almost always) is never a sensible place to hand out addresses either.
``lo`` (loopback) is never a real choice. All three are filtered out of
the response entirely rather than merely flagged, since a picker showing
options that can only fail on submit is worse than not offering them.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

import librouteros
from librouteros.exceptions import LibRouterosError

logger = logging.getLogger(__name__)

_DEFAULT_API_PORT = 8728
_DEFAULT_TIMEOUT_SECONDS = 10


class DeviceInterfaceQueryError(Exception):
    def __init__(self, host: str, detail: str) -> None:
        self.host = host
        self.detail = detail
        super().__init__(f"Failed to query interfaces on {host}: {detail}")


@dataclass(frozen=True, slots=True)
class DeviceInterface:
    name: str
    type: str | None
    running: bool
    disabled: bool
    bridge: str | None
    has_ip_address: bool


async def list_available_device_interfaces(
    *, host: str, username: str, password: str
) -> list[DeviceInterface]:
    return await asyncio.to_thread(_list_sync, host, username, password)


async def reboot_device(*, host: str, username: str, password: str) -> None:
    """Issues a real ``/system reboot`` -- the device drops the connection
    the instant it accepts the command (it's already restarting), so a
    connection-reset/timeout on read here is the *expected* success case,
    not a failure: there is no "reboot accepted" acknowledgment a device
    that's already powering down could ever send back. Only a failure to
    even *open* the connection (bad credentials, unreachable host) is a
    real error."""
    await asyncio.to_thread(_reboot_sync, host, username, password)


def _reboot_sync(host: str, username: str, password: str) -> None:
    try:
        api = librouteros.connect(
            host=host,
            username=username,
            password=password,
            port=_DEFAULT_API_PORT,
            timeout=_DEFAULT_TIMEOUT_SECONDS,
        )
    except (LibRouterosError, OSError) as exc:
        raise DeviceInterfaceQueryError(host, str(exc)) from exc

    try:
        try:
            tuple(api.path("system", "reboot")())
        except (LibRouterosError, OSError, EOFError):
            # The device disconnected mid-command -- exactly what a real
            # reboot looks like from the caller's side. See docstring.
            pass
    finally:
        try:
            api.close()
        except (LibRouterosError, OSError, EOFError):
            pass


def _list_sync(host: str, username: str, password: str) -> list[DeviceInterface]:
    try:
        api = librouteros.connect(
            host=host,
            username=username,
            password=password,
            port=_DEFAULT_API_PORT,
            timeout=_DEFAULT_TIMEOUT_SECONDS,
        )
    except (LibRouterosError, OSError) as exc:
        raise DeviceInterfaceQueryError(host, str(exc)) from exc

    try:
        try:
            interfaces = list(api.path("interface"))
            bridge_ports = list(api.path("interface", "bridge", "port"))
            addresses = list(api.path("ip", "address"))
            dhcp_servers = list(api.path("ip", "dhcp-server"))
            dhcp_clients = list(api.path("ip", "dhcp-client"))
        except LibRouterosError as exc:
            raise DeviceInterfaceQueryError(host, str(exc)) from exc
    finally:
        api.close()

    bridge_of: dict[str, str] = {
        str(p.get("interface")): str(p.get("bridge"))
        for p in bridge_ports
        if p.get("interface") and p.get("bridge")
    }
    has_ip: set[str] = {str(a.get("interface")) for a in addresses if a.get("interface")}
    has_dhcp_server: set[str] = {
        str(d.get("interface")) for d in dhcp_servers if d.get("interface")
    }
    has_dhcp_client: set[str] = {
        str(d.get("interface")) for d in dhcp_clients if d.get("interface")
    }

    result: list[DeviceInterface] = []
    for row in interfaces:
        name = row.get("name")
        if not name:
            continue
        name = str(name)
        if name == "lo":
            continue
        if name in has_dhcp_server or name in has_dhcp_client:
            continue
        result.append(
            DeviceInterface(
                name=name,
                type=str(row.get("type")) if row.get("type") else None,
                running=bool(row.get("running", False)),
                disabled=bool(row.get("disabled", False)),
                bridge=bridge_of.get(name),
                has_ip_address=name in has_ip,
            )
        )
    return result


__all__ = [
    "DeviceInterface",
    "DeviceInterfaceQueryError",
    "list_available_device_interfaces",
]
