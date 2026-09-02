"""Real device I/O for the VLAN domain -- the piece that was missing.

## What this closes

Until now this domain wrote a ``Vlan`` row, returned 201, and never
contacted the router. The operator saw "VLAN created" and the device was
untouched. There was no failure to surface because there was no attempt.

The writer itself was not missing: ``wyfy_device_gateway.mikrotik_adapter
.configure_vlan`` already issued ``/interface vlan add`` + ``/ip address
add`` over **librouteros on port 8728** -- the transport that actually
reaches fleet routers -- and had zero callers anywhere in ``app/``.
Someone built the right thing and never plugged it in. This module is the
plug.

## Why 8728 and not the existing "Push config" pipeline

``network_config``'s push path renders a script and ships it with SFTP +
``/import`` over **asyncssh on port 22**, which is filtered on the fleet.
That path cannot reach a real router, and its handler returns 202
``success: true`` regardless. Anything routed through it inherits both
problems. Every ``configure_*`` method in the gateway, and every read this
platform performs, uses 8728.

## Shape

Mirrors ``app.domains.qos.device_adapters`` deliberately -- own narrow
credentials dataclass, own Protocol naming only what this domain needs, a
concrete MikroTik implementation delegating to
``wyfy_device_gateway.registry.get_adapter``, and a small vendor registry.
Cross-domain composition in this codebase happens at the service layer via
duck-typed Protocols, never by importing another domain's adapter.

One deliberate departure from QoS: the exception ordering below.
``MikroTikConnectionError`` subclasses ``MikroTikDeviceError``, so it must
be caught first or every connection failure is reported as an operation
failure.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol

from wyfy_device_gateway.contract import DeviceCredentials as _GatewayDeviceCredentials
from wyfy_device_gateway.contract import DeviceVendor, VlanConfig
from wyfy_device_gateway.mikrotik_adapter import (
    MikroTikConnectionError,
    MikroTikDeviceError,
)
from wyfy_device_gateway.registry import get_adapter

from .exceptions import (
    UnsupportedVlanVendorError,
    VlanDeviceConnectionError,
    VlanDeviceOperationError,
)

logger = logging.getLogger(__name__)

_DEFAULT_API_PORT = 8728
_DEFAULT_TIMEOUT_SECONDS = 10


@dataclass(frozen=True, slots=True)
class VlanCredentials:
    """What an adapter needs to open a real connection, resolved by the
    caller from the target ``Router``'s own connection fields. Mirrors
    ``app.domains.qos.device_adapters.QosCredentials`` field-for-field --
    an independently-defined identical shape, not an import, so the two
    domains' device-I/O layers stay uncoupled."""

    host: str
    username: str
    password: str
    api_port: int = _DEFAULT_API_PORT
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS


class BaseVlanAdapter(Protocol):
    """What a vendor implements to plug real VLAN operations into this
    domain."""

    vendor: str

    async def configure_vlan(
        self,
        credentials: VlanCredentials,
        *,
        vlan_id: int,
        name: str,
        interface: str,
        ip_cidr: str | None,
        port_mode: str,
    ) -> None:
        """Realizes one VLAN on the device.

        ``port_mode`` changes what is built, not how it looks:

        * ``"trunk"`` -- a tagged ``/interface vlan`` sub-interface named
          ``vlan<id>`` on the parent ``interface``, with the address on it.
        * ``"access"`` -- ``interface`` is a dedicated physical port, pulled
          out of the shared bridge and given the subnet directly, untagged.
          No ``/interface vlan`` entry at all.

        This mirrors ``network_config.renderers.render_vlan``, which is what
        the operator was shown when they chose the mode. Realizing an
        "access" row as a trunk would leave that port on the wrong network.

        Idempotent: re-pushing an unchanged VLAN adds nothing and raises
        nothing.
        """
        ...


class MikroTikVlanAdapter:
    """Real MikroTik implementation, delegating to the shared gateway."""

    vendor = "mikrotik"

    def _gateway_credentials(
        self, credentials: VlanCredentials
    ) -> _GatewayDeviceCredentials:
        return _GatewayDeviceCredentials(
            vendor=DeviceVendor.MIKROTIK,
            host=credentials.host,
            username=credentials.username,
            secret=credentials.password,
            port=credentials.api_port,
            timeout_seconds=credentials.timeout_seconds,
        )

    async def configure_vlan(
        self,
        credentials: VlanCredentials,
        *,
        vlan_id: int,
        name: str,
        interface: str,
        ip_cidr: str | None,
        port_mode: str,
    ) -> None:
        creds = self._gateway_credentials(credentials)
        config = VlanConfig(
            vlan_id=vlan_id,
            name=name,
            interface=interface,
            ip_cidr=ip_cidr,
            port_mode=port_mode,
        )
        try:
            await get_adapter(DeviceVendor.MIKROTIK).configure_vlan(creds, vlan=config)
        # MikroTikConnectionError subclasses MikroTikDeviceError -- catch the
        # narrower one first, or every connection failure is mislabelled.
        except MikroTikConnectionError as exc:
            raise VlanDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikDeviceError as exc:
            raise VlanDeviceOperationError("configure_vlan", exc.detail) from exc


_VLAN_ADAPTERS: dict[str, BaseVlanAdapter] = {"mikrotik": MikroTikVlanAdapter()}


def get_vlan_adapter(vendor: str) -> BaseVlanAdapter:
    """Raises :class:`~.exceptions.UnsupportedVlanVendorError` if no adapter
    is registered for ``vendor``.

    ``Router.vendor`` is a free ``String(50)``, so a row carrying
    ``"MikroTik"`` or ``"mikrotik_routeros"`` lands here rather than in the
    gateway's own enum lookup -- and gets this domain's typed 400 instead of
    an opaque error from inside the gateway.
    """
    adapter = _VLAN_ADAPTERS.get(vendor)
    if adapter is None:
        raise UnsupportedVlanVendorError(vendor)
    return adapter


def list_supported_vlan_vendors() -> list[str]:
    return sorted(_VLAN_ADAPTERS)


__all__ = [
    "BaseVlanAdapter",
    "MikroTikVlanAdapter",
    "VlanCredentials",
    "get_vlan_adapter",
    "list_supported_vlan_vendors",
]
