"""Real device I/O for the DHCP domain -- the piece that was missing.

## What this closes

Until now this domain wrote a ``DhcpPool`` row, returned 201, and never
contacted the router. ``service.py``'s own module docstring said so
plainly -- "No live device push in this pass ... this domain has no
``device_adapters.py`` and no Celery task" -- and deferred real
provisioning to a "not-yet-built Network Configuration Management
domain".

The writer was never the missing piece.
``wyfy_device_gateway.mikrotik_adapter.configure_dhcp_pool`` already
issued the three real RouterOS operations (``/ip pool add``, ``/ip
dhcp-server add``, ``/ip dhcp-server network add``) over **librouteros on
port 8728** -- the transport that actually reaches fleet routers -- and
had zero callers anywhere in ``app/``. Someone built the right thing and
never plugged it in. This module is the plug, exactly as
``app.domains.vlan.device_adapters`` is for VLANs.

The consequence here was worse than the VLAN one. A VLAN with no DHCP
hands out no addresses, so a guest joining a network the dashboard
reported as created gets nothing at all -- which is the failure this
domain's silence actually produced in the field.

## Why 8728 and not the existing "Push config" pipeline

``network_config``'s push path renders a script and ships it with SFTP +
``/import`` over **asyncssh on port 22**, which is filtered on the fleet.
That path cannot reach a real router, and its handler returns 202
``success: true`` regardless. Every ``configure_*`` method in the gateway,
and every read this platform performs, uses 8728.

## Shape

Mirrors ``app.domains.vlan.device_adapters`` deliberately -- own narrow
credentials dataclass, own Protocol naming only what this domain needs, a
concrete MikroTik implementation delegating to
``wyfy_device_gateway.registry.get_adapter``, and a small vendor registry.
Cross-domain composition in this codebase happens at the service layer via
duck-typed Protocols, never by importing another domain's adapter.

``MikroTikConnectionError`` subclasses ``MikroTikDeviceError``, so it must
be caught first or every connection failure is reported as an operation
failure.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol

from wyfy_device_gateway.contract import DeviceCredentials as _GatewayDeviceCredentials
from wyfy_device_gateway.contract import DeviceVendor, DhcpPoolConfig
from wyfy_device_gateway.mikrotik_adapter import (
    MikroTikConnectionError,
    MikroTikDeviceError,
)
from wyfy_device_gateway.registry import get_adapter

from .exceptions import (
    DhcpDeviceConnectionError,
    DhcpDeviceOperationError,
    UnsupportedDhcpVendorError,
)

logger = logging.getLogger(__name__)

_DEFAULT_API_PORT = 8728
_DEFAULT_TIMEOUT_SECONDS = 10


@dataclass(frozen=True, slots=True)
class DhcpCredentials:
    """What an adapter needs to open a real connection, resolved by the
    caller from the target ``Router``'s own connection fields. Mirrors
    ``app.domains.vlan.device_adapters.VlanCredentials`` field-for-field --
    an independently-defined identical shape, not an import, so the two
    domains' device-I/O layers stay uncoupled."""

    host: str
    username: str
    password: str
    api_port: int = _DEFAULT_API_PORT
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS


class BaseDhcpAdapter(Protocol):
    """What a vendor implements to plug real DHCP operations into this
    domain."""

    vendor: str

    async def configure_dhcp_pool(
        self,
        credentials: DhcpCredentials,
        *,
        interface: str,
        range_start: str,
        range_end: str,
        gateway: str,
        dns_servers: list[str],
        lease_time_seconds: int,
    ) -> None:
        """Realizes one DHCP pool on the device: the address pool, the
        server bound to ``interface``, and the network row carrying the
        gateway and DNS.

        Idempotent: re-pushing an unchanged pool adds nothing and raises
        nothing, and re-pushing a *changed* one updates the existing device
        objects rather than failing on "already have such item". The range
        is the field an operator actually edits, so a widened pool really
        widens on the device instead of silently reporting success against
        the old range.
        """
        ...


class MikroTikDhcpAdapter:
    """Real MikroTik implementation, delegating to the shared gateway."""

    vendor = "mikrotik"

    def _gateway_credentials(
        self, credentials: DhcpCredentials
    ) -> _GatewayDeviceCredentials:
        return _GatewayDeviceCredentials(
            vendor=DeviceVendor.MIKROTIK,
            host=credentials.host,
            username=credentials.username,
            secret=credentials.password,
            port=credentials.api_port,
            timeout_seconds=credentials.timeout_seconds,
        )

    async def configure_dhcp_pool(
        self,
        credentials: DhcpCredentials,
        *,
        interface: str,
        range_start: str,
        range_end: str,
        gateway: str,
        dns_servers: list[str],
        lease_time_seconds: int,
    ) -> None:
        creds = self._gateway_credentials(credentials)
        config = DhcpPoolConfig(
            interface=interface,
            range_start=range_start,
            range_end=range_end,
            gateway=gateway,
            dns_servers=dns_servers,
            lease_time_seconds=lease_time_seconds,
        )
        try:
            await get_adapter(DeviceVendor.MIKROTIK).configure_dhcp_pool(
                creds, pool=config
            )
        # MikroTikConnectionError subclasses MikroTikDeviceError -- catch the
        # narrower one first, or every connection failure is mislabelled.
        except MikroTikConnectionError as exc:
            raise DhcpDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikDeviceError as exc:
            raise DhcpDeviceOperationError(
                "configure_dhcp_pool", exc.detail
            ) from exc


_DHCP_ADAPTERS: dict[str, BaseDhcpAdapter] = {"mikrotik": MikroTikDhcpAdapter()}


def get_dhcp_adapter(vendor: str) -> BaseDhcpAdapter:
    """Raises :class:`~.exceptions.UnsupportedDhcpVendorError` if no adapter
    is registered for ``vendor``."""
    adapter = _DHCP_ADAPTERS.get(vendor)
    if adapter is None:
        raise UnsupportedDhcpVendorError(vendor)
    return adapter


def list_supported_dhcp_vendors() -> list[str]:
    return sorted(_DHCP_ADAPTERS)


__all__ = [
    "BaseDhcpAdapter",
    "DhcpCredentials",
    "MikroTikDhcpAdapter",
    "get_dhcp_adapter",
    "list_supported_dhcp_vendors",
]
