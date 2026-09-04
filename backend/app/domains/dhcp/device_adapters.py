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
from wyfy_device_gateway.contract import (
    DeviceVendor,
    DhcpPoolConfig,
    RogueDhcpAlertConfig,
)
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


@dataclass(frozen=True, slots=True)
class RogueDhcpInterfaceReading:
    """One interface's rogue-DHCP detection state, as the device reported
    it on a single read.

    An independently-defined shape rather than a re-export of
    ``wyfy_device_gateway.contract.RogueDhcpAlertStatus`` -- the same
    posture ``DhcpCredentials`` above takes towards the gateway's own
    ``DeviceCredentials``. The service layer and the readiness checklist
    consume this; neither imports the vendor contract, so a gateway field
    rename cannot reach into a domain that never asked about RouterOS.

    Carries the two facts separately that must never be merged:
    ``alert_present`` (a row exists) and ``enabled`` (it is switched on).
    RouterOS creates these rows disabled, so presence alone certifies a
    router that is watching nothing -- see
    ``constants.RogueDhcpAlertState``.
    """

    interface: str
    serves_dhcp: bool
    alert_present: bool
    enabled: bool

    @property
    def watched(self) -> bool:
        """Is this interface's DHCP actually being watched right now --
        both halves, never just presence. Mirrors the gateway contract's
        own ``RogueDhcpAlertStatus.guarded`` property deliberately, so the
        two layers cannot drift on what the answer means."""
        return self.alert_present and self.enabled


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

    async def ensure_rogue_dhcp_alert(
        self, credentials: DhcpCredentials, *, interface: str
    ) -> str | None:
        """Ask the device to log any DHCP server on ``interface`` that is not
        the router itself, and report the trusted MAC it used.

        Returns ``None`` when the router has no hardware address on that
        interface, which is the one case where the alert must NOT be
        written: `valid-server` would have to be guessed, and a wrong value
        makes every legitimate lease reply look rogue.
        """
        ...

    async def read_rogue_dhcp_alerts(
        self, credentials: DhcpCredentials
    ) -> list[RogueDhcpInterfaceReading]:
        """Which of this router's interfaces are actually being watched for
        a DHCP server that is not ours. Reads only; writes nothing.

        Every interface serving DHCP appears in the answer whether or not
        it has an alert row. That is not an implementation detail to be
        tidied away: "hands out addresses, nothing watching it" is the
        finding worth having, and it has no alert row of its own to be
        listed by. An answer built only from the rows present would be
        silent about exactly the routers worth knowing about.
        """
        ...

    async def delete_dhcp_pool(
        self,
        credentials: DhcpCredentials,
        *,
        interface: str,
        range_start: str,
        range_end: str,
    ) -> None:
        """Removes the address pool, the DHCP server bound to ``interface``,
        and the network row for this subnet.

        Deleting a pool row never touched the device -- the row went away
        and the DHCP server kept handing out addresses. Idempotent, and the
        server is removed before the pool it references.
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

    async def ensure_rogue_dhcp_alert(
        self, credentials: DhcpCredentials, *, interface: str
    ) -> str | None:
        creds = self._gateway_credentials(credentials)
        gateway = get_adapter(DeviceVendor.MIKROTIK)
        try:
            snapshot = await gateway.read_network_snapshot(creds)
            mac = next(
                (
                    i.mac_address
                    for i in snapshot.interfaces
                    if i.name == interface and i.mac_address
                ),
                None,
            )
            if mac is None:
                # Refuse rather than default. See the Protocol docstring:
                # a guessed trusted server turns every real lease into an
                # alert, which is how a genuine one gets ignored.
                return None
            await gateway.configure_rogue_dhcp_alerts(
                creds,
                alerts=[
                    RogueDhcpAlertConfig(
                        interface=interface, valid_servers=(mac,)
                    )
                ],
            )
            return mac
        except MikroTikConnectionError as exc:
            raise DhcpDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikDeviceError as exc:
            raise DhcpDeviceOperationError(
                "ensure_rogue_dhcp_alert", exc.detail
            ) from exc

    async def read_rogue_dhcp_alerts(
        self, credentials: DhcpCredentials
    ) -> list[RogueDhcpInterfaceReading]:
        creds = self._gateway_credentials(credentials)
        try:
            statuses = await get_adapter(DeviceVendor.MIKROTIK).read_rogue_dhcp_alerts(
                creds
            )
        # MikroTikConnectionError subclasses MikroTikDeviceError -- catch the
        # narrower one first, or every connection failure is mislabelled.
        # The caller relies on the distinction: a connection failure is an
        # unanswered question (RogueDhcpAlertState.UNKNOWN), never a finding.
        except MikroTikConnectionError as exc:
            raise DhcpDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikDeviceError as exc:
            raise DhcpDeviceOperationError(
                "read_rogue_dhcp_alerts", exc.detail
            ) from exc
        return [
            RogueDhcpInterfaceReading(
                interface=status.interface,
                serves_dhcp=status.serves_dhcp,
                alert_present=status.alert_present,
                enabled=status.enabled,
            )
            for status in statuses
        ]

    async def delete_dhcp_pool(
        self,
        credentials: DhcpCredentials,
        *,
        interface: str,
        range_start: str,
        range_end: str,
    ) -> None:
        creds = self._gateway_credentials(credentials)
        # gateway and dns_servers are irrelevant to teardown -- the three
        # objects are found by the interface-derived names and the subnet.
        config = DhcpPoolConfig(
            interface=interface,
            range_start=range_start,
            range_end=range_end,
            gateway="",
            dns_servers=[],
            lease_time_seconds=0,
        )
        try:
            await get_adapter(DeviceVendor.MIKROTIK).delete_dhcp_pool(
                creds, pool=config
            )
        except MikroTikConnectionError as exc:
            raise DhcpDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikDeviceError as exc:
            raise DhcpDeviceOperationError("delete_dhcp_pool", exc.detail) from exc


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
    "RogueDhcpInterfaceReading",
    "MikroTikDhcpAdapter",
    "get_dhcp_adapter",
    "list_supported_dhcp_vendors",
]
