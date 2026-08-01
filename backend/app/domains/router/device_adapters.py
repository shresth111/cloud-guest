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

## ``list_available_device_interfaces``: now delegates to wyfy-device-gateway

Per the ``wyfy-device-gateway`` PRD (section 7, Step 2 -- the "prove the
seam works end-to-end with zero risk" migration step), this function's
*internal implementation* now calls
``wyfy_device_gateway.registry.get_adapter(DeviceVendor.MIKROTIK)
.get_interface_list(...)`` instead of opening ``librouteros`` directly --
that package is a straight port of the ``_list_sync`` logic this function
used to contain (same filtering rules, same field shapes). This function's
own public signature and return shape (``list[DeviceInterface]``) are
unchanged, and ``DeviceInterfaceQueryError`` is still what callers catch --
this is purely an internal implementation swap, chosen as the
lowest-risk first call site to migrate because it is read-only and
already fully isolated to this one small module. ``reboot_device`` below
is untouched in this step -- it migrates in a later PR per the PRD's
migration plan.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

import librouteros
from librouteros.exceptions import LibRouterosError
from wyfy_device_gateway.contract import DeviceCredentials, DeviceVendor
from wyfy_device_gateway.mikrotik_adapter import MikroTikDeviceError
from wyfy_device_gateway.registry import get_adapter

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
    """See module docstring's "now delegates to wyfy-device-gateway"
    section. Builds a vendor-agnostic ``DeviceCredentials`` from this
    call's already-decrypted plaintext (exactly the lifecycle
    ``wyfy_device_gateway``'s own contract documents -- built by the
    caller, used once, discarded), delegates the real RouterOS query to
    the ported ``MikroTikAdapter``, then maps its vendor-agnostic
    ``InterfaceInfo`` rows back onto this module's own pre-existing
    ``DeviceInterface`` shape (identical fields) so every downstream
    caller (``router.py``'s ``get_device_interfaces`` endpoint,
    ``DeviceInterfaceResponse``) is unaffected byte-for-byte."""
    creds = DeviceCredentials(
        vendor=DeviceVendor.MIKROTIK, host=host, username=username, secret=password
    )
    try:
        interfaces = await get_adapter(DeviceVendor.MIKROTIK).get_interface_list(creds)
    except MikroTikDeviceError as exc:
        raise DeviceInterfaceQueryError(host, exc.detail) from exc
    return [
        DeviceInterface(
            name=i.name,
            type=i.type,
            running=i.running,
            disabled=i.disabled,
            bridge=i.bridge,
            has_ip_address=i.has_ip_address,
        )
        for i in interfaces
    ]


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


__all__ = [
    "DeviceInterface",
    "DeviceInterfaceQueryError",
    "list_available_device_interfaces",
]
