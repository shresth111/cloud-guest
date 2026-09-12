"""Real device I/O for the Port Forwarding domain -- the piece that was
missing.

## What this closes

Until now this domain wrote a ``PortForwardingRule`` row, returned 201, and
never contacted the router. This package's own docstring said so and called
it deliberate -- "A pure inventory/rules domain -- no
``device_adapters.py``, no live device push" -- deferring real provisioning
to a "not-yet-built Network Configuration Management domain".

The writer was never the missing piece.
``wyfy_device_gateway.mikrotik_adapter.configure_port_forward`` already
issued the real ``/ip firewall nat add chain=dstnat ... action=dst-nat``
operation over **librouteros on port 8728** -- the transport that actually
reaches fleet routers -- and had zero callers anywhere in ``app/``. Someone
built the right thing and never plugged it in. This module is the plug,
exactly as ``app.domains.vlan.device_adapters`` and
``app.domains.dhcp.device_adapters`` are for theirs.

The visible consequence of the silence is the one a customer notices
fastest: a camera, a PMS terminal or an office NAS listed in the dashboard
as published on a port, answering nothing from outside, with no failure
anywhere to point at.

## Why 8728 and not the existing "Push config" pipeline

``network_config``'s push path renders a script and ships it with SFTP +
``/import`` over **asyncssh on port 22**, which is filtered on the fleet.
That path cannot reach a real router, and its handler returns 202
``success: true`` regardless. Every ``configure_*`` method in the gateway,
and every read this platform performs, uses 8728.

## Shape

Mirrors ``app.domains.dhcp.device_adapters`` deliberately -- own narrow
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
from wyfy_device_gateway.contract import DeviceVendor, PortForwardConfig
from wyfy_device_gateway.mikrotik_adapter import (
    MikroTikConnectionError,
    MikroTikDeviceError,
)
from wyfy_device_gateway.registry import get_adapter

from .exceptions import (
    PortForwardingDeviceConnectionError,
    PortForwardingDeviceOperationError,
    UnsupportedPortForwardingVendorError,
)

logger = logging.getLogger(__name__)

_DEFAULT_API_PORT = 8728
_DEFAULT_TIMEOUT_SECONDS = 10


@dataclass(frozen=True, slots=True)
class PortForwardingCredentials:
    """What an adapter needs to open a real connection, resolved by the
    caller from the target ``Router``'s own connection fields. Mirrors
    ``app.domains.dhcp.device_adapters.DhcpCredentials`` field-for-field --
    an independently-defined identical shape, not an import, so the two
    domains' device-I/O layers stay uncoupled."""

    host: str
    username: str
    password: str
    api_port: int = _DEFAULT_API_PORT
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS


class BasePortForwardingAdapter(Protocol):
    """What a vendor implements to plug real port-forwarding operations
    into this domain."""

    vendor: str

    async def configure_port_forward(
        self,
        credentials: PortForwardingCredentials,
        *,
        rule_id: str,
        protocol: str,
        external_port: int,
        internal_ip: str,
        internal_port: int,
        destination_address: str | None,
        source_address: str | None,
    ) -> None:
        """Realizes one DSTNAT rule on the device.

        ``rule_id`` is the row's own id and is what makes the operation
        repeatable: the vendor adapter writes it into the rule's comment
        and finds the rule by it on every later push. Every other argument
        here is a field the customer edits, so none of them can be the
        handle -- keyed on one, the push after an edit would add a second
        rule and leave the first forwarding a live public port at a host
        that has moved.

        Idempotent: re-pushing an unchanged rule adds nothing and raises
        nothing, and re-pushing a *changed* one updates the rule already
        there rather than failing on "already have such item".
        """
        ...

    async def delete_port_forward(
        self, credentials: PortForwardingCredentials, *, rule_id: str
    ) -> None:
        """Removes what ``configure_port_forward`` created.

        Takes only ``rule_id``: the rule is found by its identity, so a
        rule left over from an earlier port or internal host is still
        removed. Deleting a rule row never touched the device -- the row
        went away and the router kept forwarding the port. Idempotent, so a
        retry after a partial failure completes cleanly.
        """
        ...


class MikroTikPortForwardingAdapter:
    """Real MikroTik implementation, delegating to the shared gateway."""

    vendor = "mikrotik"

    def _gateway_credentials(
        self, credentials: PortForwardingCredentials
    ) -> _GatewayDeviceCredentials:
        return _GatewayDeviceCredentials(
            vendor=DeviceVendor.MIKROTIK,
            host=credentials.host,
            username=credentials.username,
            secret=credentials.password,
            port=credentials.api_port,
            timeout_seconds=credentials.timeout_seconds,
        )

    async def configure_port_forward(
        self,
        credentials: PortForwardingCredentials,
        *,
        rule_id: str,
        protocol: str,
        external_port: int,
        internal_ip: str,
        internal_port: int,
        destination_address: str | None,
        source_address: str | None,
    ) -> None:
        creds = self._gateway_credentials(credentials)
        config = PortForwardConfig(
            rule_id=rule_id,
            protocol=protocol,
            external_port=external_port,
            internal_ip=internal_ip,
            internal_port=internal_port,
            dst_address=destination_address,
            src_address=source_address,
        )
        try:
            await get_adapter(DeviceVendor.MIKROTIK).configure_port_forward(
                creds, rule=config
            )
        # MikroTikConnectionError subclasses MikroTikDeviceError -- catch the
        # narrower one first, or every connection failure is mislabelled.
        except MikroTikConnectionError as exc:
            raise PortForwardingDeviceConnectionError(
                credentials.host, exc.detail
            ) from exc
        except MikroTikDeviceError as exc:
            raise PortForwardingDeviceOperationError(
                "configure_port_forward", exc.detail
            ) from exc

    async def delete_port_forward(
        self, credentials: PortForwardingCredentials, *, rule_id: str
    ) -> None:
        creds = self._gateway_credentials(credentials)
        # Every field but the id is required by the shape and unread on the
        # delete path, which matches on the rule's identity alone -- so the
        # current port and target, whatever they are, cannot change what is
        # removed.
        config = PortForwardConfig(
            rule_id=rule_id,
            protocol="tcp",
            external_port=0,
            internal_ip="",
            internal_port=0,
        )
        try:
            await get_adapter(DeviceVendor.MIKROTIK).delete_port_forward(
                creds, rule=config
            )
        except MikroTikConnectionError as exc:
            raise PortForwardingDeviceConnectionError(
                credentials.host, exc.detail
            ) from exc
        except MikroTikDeviceError as exc:
            raise PortForwardingDeviceOperationError(
                "delete_port_forward", exc.detail
            ) from exc


_PORT_FORWARDING_ADAPTERS: dict[str, BasePortForwardingAdapter] = {
    "mikrotik": MikroTikPortForwardingAdapter()
}


def get_port_forwarding_adapter(vendor: str) -> BasePortForwardingAdapter:
    """Raises :class:`~.exceptions.UnsupportedPortForwardingVendorError` if
    no adapter is registered for ``vendor``."""
    adapter = _PORT_FORWARDING_ADAPTERS.get(vendor)
    if adapter is None:
        raise UnsupportedPortForwardingVendorError(vendor)
    return adapter


def list_supported_port_forwarding_vendors() -> list[str]:
    return sorted(_PORT_FORWARDING_ADAPTERS)


__all__ = [
    "BasePortForwardingAdapter",
    "MikroTikPortForwardingAdapter",
    "PortForwardingCredentials",
    "get_port_forwarding_adapter",
    "list_supported_port_forwarding_vendors",
]
