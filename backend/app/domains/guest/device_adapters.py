"""Real device I/O for the router half of a RADIUS NAS registration.

## The gap this closes

Registering a router as a RADIUS client has two halves. The **hub** half --
a ``client{}`` stanza in FreeRADIUS -- has had a real sync path for a while
(``GuestService.record_hub_client_sync``, with ``hub_client_synced_ip`` and
``hub_client_synced_at`` recording that the hub confirmed it). The
**router** half -- the device's own ``/radius`` row and its ``/radius
incoming`` CoA listener -- had none.

The gateway writer for it existed and worked
(``MikroTikAdapter.set_radius_client_config``) and had **zero callers in
this application**, which is the same shape already found and closed in
``vlan``, ``dhcp``, ``port_forwarding``, ``content_filtering`` and ``qos``.
The only thing that could actually write those objects was
``network_config.renderers.render_radius_client``, inside the combined
config script, delivered over SSH -- and a port sweep run from the platform
against a fleet router reached only ``8728``. So in practice the router
half landed once, by hand, when somebody pasted a setup script at
provisioning, and drifted from then on with nothing able to correct it.

The lab router is exactly that: it holds ``/radius incoming accept=false
port=3799``. RouterOS's own default port is ``1700``, so ``3799`` is this
platform's value -- the setting *was* reached once -- while ``accept``,
written in the very same statement, is not what we write. Nothing could
repair it, because nothing could reach it.

## Shape

Mirrors ``app.domains.vlan.device_adapters`` deliberately: its own narrow
credentials dataclass (an independently-defined identical shape, not an
import, so the domains' device-I/O layers stay uncoupled), a Protocol
naming only what this domain needs, a concrete MikroTik implementation
delegating to ``wyfy_device_gateway.registry.get_adapter``, and a small
vendor registry.

## What a successful push does and does not assert

It asserts that the ``/radius`` row for this server exists on the device
with this platform's secret and ``src-address``, and that ``/radius
incoming`` accepts on the CoA port. It does **not** assert that a
Disconnect-Request sent from the hub actually arrives: that is device test
T8 in ``docs/mikrotik/TRUSTED_DEVICES_AND_ACCESS_RULES.md``, it is unrun,
and running it needs a shell on the RADIUS host. ``guest_access``'s block
enforcement is deliberately built not to depend on CoA for that reason --
see ``app.domains.guest_access.enforcement``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from wyfy_device_gateway.contract import DeviceVendor
from wyfy_device_gateway.contract import RadiusClientConfig as _GatewayRadiusConfig
from wyfy_device_gateway.mikrotik_adapter import MikroTikDeviceError
from wyfy_device_gateway.registry import get_adapter

from .exceptions import RadiusNasDeviceOperationError

_DEFAULT_API_PORT = 8728
_DEFAULT_TIMEOUT_SECONDS = 10


@dataclass(frozen=True, slots=True)
class RadiusNasCredentials:
    """What an adapter needs to open a real connection, resolved by the
    caller from the target ``Router``'s own connection fields."""

    host: str
    username: str
    password: str
    api_port: int = _DEFAULT_API_PORT
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS


@dataclass(frozen=True, slots=True)
class RadiusNasDeviceConfig:
    """One router's NAS registration, as this domain knows it.

    ``src_address`` is the router's own address on the management tunnel.
    The hub's FreeRADIUS matches an incoming request to a ``client{}``
    stanza **by source address**, so a registration without it is one the
    hub will never answer. This domain therefore treats it as required,
    even though the gateway's own shape defaults it to ``None`` for vendors
    with no tunnel.
    """

    radius_server_host: str
    radius_secret: str
    src_address: str


class RadiusNasDeviceAdapter(Protocol):
    """Only what this domain needs -- not the gateway's whole surface."""

    vendor: str

    async def push_nas_client(
        self, credentials: RadiusNasCredentials, *, config: RadiusNasDeviceConfig
    ) -> None:
        """Converge the router's ``/radius`` row and its CoA listener.

        Idempotent: re-pushing an unchanged registration writes nothing.
        Raises :class:`RadiusNasDeviceOperationError` on any device
        failure, never a silent success.
        """
        ...


class MikroTikRadiusNasAdapter:
    """Real MikroTik implementation, delegating to the shared gateway."""

    vendor = "mikrotik"

    async def push_nas_client(
        self, credentials: RadiusNasCredentials, *, config: RadiusNasDeviceConfig
    ) -> None:
        try:
            await get_adapter(DeviceVendor.MIKROTIK).set_radius_client_config(
                _gateway_credentials(credentials),
                config=_GatewayRadiusConfig(
                    radius_server_host=config.radius_server_host,
                    radius_secret=config.radius_secret,
                    src_address=config.src_address,
                ),
            )
        except MikroTikDeviceError as exc:
            raise RadiusNasDeviceOperationError(
                "push_nas_client", exc.detail
            ) from exc


def _gateway_credentials(credentials: RadiusNasCredentials):
    from wyfy_device_gateway.contract import DeviceCredentials

    return DeviceCredentials(
        vendor=DeviceVendor.MIKROTIK,
        host=credentials.host,
        username=credentials.username,
        secret=credentials.password,
        port=credentials.api_port,
        timeout_seconds=credentials.timeout_seconds,
    )


_ADAPTERS: dict[str, RadiusNasDeviceAdapter] = {
    MikroTikRadiusNasAdapter.vendor: MikroTikRadiusNasAdapter(),
}


def get_radius_nas_adapter(vendor: str | None) -> RadiusNasDeviceAdapter:
    """The adapter for ``vendor``, or MikroTik when a router carries none.

    Defaulting rather than refusing mirrors this fleet's reality: every
    router this platform manages today is a MikroTik, and routers
    registered before ``vendor`` was populated carry ``None``. A vendor
    that is set and unknown is a different case and does refuse -- pushing
    MikroTik commands at, say, a Ruckus is not a recoverable mistake.
    """
    if vendor is None:
        return _ADAPTERS[MikroTikRadiusNasAdapter.vendor]
    key = vendor.strip().lower()
    if key not in _ADAPTERS:
        raise RadiusNasDeviceOperationError(
            "get_radius_nas_adapter",
            f"no RADIUS NAS device adapter registered for vendor {vendor!r}",
        )
    return _ADAPTERS[key]


__all__ = [
    "MikroTikRadiusNasAdapter",
    "RadiusNasCredentials",
    "RadiusNasDeviceAdapter",
    "RadiusNasDeviceConfig",
    "get_radius_nas_adapter",
]
