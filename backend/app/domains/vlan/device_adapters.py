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
from wyfy_device_gateway.contract import (
    DeviceVendor,
    NatRuleConfig,
    VlanConfig,
    VlanHotspotConfig,
)
from wyfy_device_gateway.mikrotik_adapter import (
    MikroTikConnectionError,
    MikroTikDeviceError,
    MikroTikWanInterfaceError,
)
from wyfy_device_gateway.registry import get_adapter

from .exceptions import (
    UnsupportedVlanVendorError,
    VlanDeviceConnectionError,
    VlanDeviceOperationError,
    VlanNatWanInterfaceUnresolvedError,
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


@dataclass(frozen=True, slots=True)
class VlanDeviceInterface:
    """One interface as the router currently has it.

    ``is_bridge_port`` is the field ``app.domains.router.device_adapters
    .DeviceInterface`` does not carry, and the VLAN form needs it: an
    access-mode VLAN takes a port *out of* a bridge, so a port that is in
    no bridge is not a candidate. Derivable from ``bridge`` only by a
    caller that already knows the convention, which a frontend picker
    should not have to.
    """

    name: str
    type: str | None
    running: bool
    disabled: bool
    bridge: str | None
    is_bridge_port: bool
    has_ip_address: bool


@dataclass(frozen=True, slots=True)
class VlanDeviceAddress:
    """One row of the router's live ``/ip address`` table."""

    address: str
    interface: str | None
    disabled: bool
    # True when the interface this address names no longer exists. Such a
    # row holds no subnet -- see the field's own note on
    # ``wyfy_device_gateway.contract.IpAddressInfo``.
    invalid: bool = False


@dataclass(frozen=True, slots=True)
class VlanNetworkSnapshot:
    """One router read, answering every device-side precondition at once.

    "Is this router reachable", "does the named interface exist on it" and
    "is this subnet already taken there" are three questions with one
    source. Asking them over three connections triples what an operator
    waits for before a validation failure, and lets the three answers come
    from three different moments.
    """

    interfaces: list[VlanDeviceInterface]
    addresses: list[VlanDeviceAddress]


class BaseVlanAdapter(Protocol):
    """What a vendor implements to plug real VLAN operations into this
    domain."""

    vendor: str

    async def read_network_snapshot(
        self, credentials: VlanCredentials
    ) -> VlanNetworkSnapshot:
        """Reads the router's interfaces and ``/ip address`` table.

        Read-only, and the only device read the push preflight performs.
        Deliberately unfiltered, unlike ``app.domains.router
        .device_adapters.list_available_device_interfaces``: that one
        exists to back a DHCP picker and drops every interface already
        carrying an ``/ip dhcp-server``, which on a real router removes
        ``bridge`` -- exactly the interface a VLAN trunk hangs off.
        """
        ...

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

    async def delete_vlan(
        self,
        credentials: VlanCredentials,
        *,
        vlan_id: int,
        name: str,
        interface: str,
        ip_cidr: str | None,
        port_mode: str,
        previous_bridge: str | None = None,
    ) -> None:
        """Removes what ``configure_vlan`` created, for the same
        ``port_mode``.

        Deleting a VLAN row never touched the device -- the row went away
        and the interface kept carrying traffic. Idempotent: removing what
        is already absent is a no-op, so a retry after a partial failure
        completes cleanly.
        """
        ...

    async def configure_hotspot(
        self,
        credentials: VlanCredentials,
        *,
        vlan_id: int,
        interface: str,
        cidr: str,
        gateway: str,
        dns_name: str,
        html_directory: str,
    ) -> None:
        """Puts this VLAN's own captive portal on ``interface``.

        Six real RouterOS objects (pool, DHCP server, DHCP network,
        hotspot profile, static DNS record, hotspot server), all named
        from ``vlan_id`` and bound to this interface, so one VLAN's portal
        never touches another's or the router's default ``hotspot1``.

        ``interface`` is passed in rather than derived: in trunk mode the
        portal belongs on ``vlan<id>``, in access mode on the physical
        port, and only the caller knows which.

        Idempotent, and updating rather than skipping where a field the
        operator can edit changed -- a portal still pointing at last
        week's subnet after a re-push is a portal that reports success and
        challenges nobody.
        """
        ...

    async def delete_hotspot(
        self,
        credentials: VlanCredentials,
        *,
        vlan_id: int,
        interface: str,
        cidr: str,
        gateway: str,
        dns_name: str,
        html_directory: str,
    ) -> None:
        """Takes this VLAN's captive portal back off the device.

        Serves both intents that reach it -- the operator turned the
        portal off, or deleted the VLAN -- because both mean the same
        thing on the device. Idempotent, so removing a portal that was
        never created is a no-op.
        """
        ...

    async def configure_nat_masquerade(
        self, credentials: VlanCredentials, *, vlan_id: int, src_cidr: str
    ) -> None:
        """Gives this VLAN's subnet real internet access.

        ``configure_vlan`` builds a complete *local* network and stops
        there: guests get a lease, a gateway, and no route off the router.
        This is the source-NAT rule that closes that gap.

        No WAN interface is passed in, deliberately. Which port a site's
        uplink is in is not stored anywhere in this database and differs
        per site, so the vendor adapter derives it from the router's own
        live default route. Naming it here would mean this domain
        inventing a value it cannot know.

        Idempotent on the VLAN's identity rather than on ``src_cidr``:
        re-subnetting a VLAN updates its existing rule instead of leaving
        an orphan behind and adding a second one.
        """
        ...

    async def delete_nat_masquerade(
        self, credentials: VlanCredentials, *, vlan_id: int
    ) -> None:
        """Takes this VLAN's internet access back off the device.

        Takes no ``src_cidr``: the rule is found by the VLAN's identity, so
        a rule left over from an older subnet is still removed. Idempotent,
        and needs no reachable WAN -- a VLAN must stay removable from a
        router whose uplink is down.
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

    async def read_network_snapshot(
        self, credentials: VlanCredentials
    ) -> VlanNetworkSnapshot:
        creds = self._gateway_credentials(credentials)
        try:
            snapshot = await get_adapter(DeviceVendor.MIKROTIK).read_network_snapshot(
                creds
            )
        except MikroTikConnectionError as exc:
            raise VlanDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikDeviceError as exc:
            raise VlanDeviceOperationError("read_network_snapshot", exc.detail) from exc
        return VlanNetworkSnapshot(
            interfaces=[
                VlanDeviceInterface(
                    name=i.name,
                    type=i.type,
                    running=i.running,
                    disabled=i.disabled,
                    bridge=i.bridge,
                    is_bridge_port=i.is_bridge_port,
                    has_ip_address=i.has_ip_address,
                )
                for i in snapshot.interfaces
            ],
            addresses=[
                VlanDeviceAddress(
                    address=a.address,
                    interface=a.interface,
                    disabled=a.disabled,
                    invalid=a.invalid,
                )
                for a in snapshot.ip_addresses
            ],
        )

    def _hotspot_config(
        self,
        *,
        vlan_id: int,
        interface: str,
        cidr: str,
        gateway: str,
        dns_name: str,
        html_directory: str,
    ) -> VlanHotspotConfig:
        return VlanHotspotConfig(
            vlan_id=vlan_id,
            interface=interface,
            cidr=cidr,
            gateway=gateway,
            dns_name=dns_name,
            html_directory=html_directory,
        )

    async def configure_hotspot(
        self,
        credentials: VlanCredentials,
        *,
        vlan_id: int,
        interface: str,
        cidr: str,
        gateway: str,
        dns_name: str,
        html_directory: str,
    ) -> None:
        creds = self._gateway_credentials(credentials)
        hotspot = self._hotspot_config(
            vlan_id=vlan_id,
            interface=interface,
            cidr=cidr,
            gateway=gateway,
            dns_name=dns_name,
            html_directory=html_directory,
        )
        try:
            await get_adapter(DeviceVendor.MIKROTIK).configure_vlan_hotspot(
                creds, hotspot=hotspot
            )
        except MikroTikConnectionError as exc:
            raise VlanDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikDeviceError as exc:
            raise VlanDeviceOperationError("configure_hotspot", exc.detail) from exc

    async def delete_hotspot(
        self,
        credentials: VlanCredentials,
        *,
        vlan_id: int,
        interface: str,
        cidr: str,
        gateway: str,
        dns_name: str,
        html_directory: str,
    ) -> None:
        creds = self._gateway_credentials(credentials)
        hotspot = self._hotspot_config(
            vlan_id=vlan_id,
            interface=interface,
            cidr=cidr,
            gateway=gateway,
            dns_name=dns_name,
            html_directory=html_directory,
        )
        try:
            await get_adapter(DeviceVendor.MIKROTIK).delete_vlan_hotspot(
                creds, hotspot=hotspot
            )
        except MikroTikConnectionError as exc:
            raise VlanDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikDeviceError as exc:
            raise VlanDeviceOperationError("delete_hotspot", exc.detail) from exc

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

    async def delete_vlan(
        self,
        credentials: VlanCredentials,
        *,
        vlan_id: int,
        name: str,
        interface: str,
        ip_cidr: str | None,
        port_mode: str,
        previous_bridge: str | None = None,
    ) -> None:
        creds = self._gateway_credentials(credentials)
        config = VlanConfig(
            vlan_id=vlan_id,
            name=name,
            interface=interface,
            ip_cidr=ip_cidr,
            port_mode=port_mode,
            previous_bridge=previous_bridge,
        )
        try:
            await get_adapter(DeviceVendor.MIKROTIK).delete_vlan(creds, vlan=config)
        except MikroTikConnectionError as exc:
            raise VlanDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikDeviceError as exc:
            raise VlanDeviceOperationError("delete_vlan", exc.detail) from exc

    async def configure_nat_masquerade(
        self, credentials: VlanCredentials, *, vlan_id: int, src_cidr: str
    ) -> None:
        creds = self._gateway_credentials(credentials)
        # out_interface is left None on purpose: that is what tells the
        # gateway to resolve this router's real WAN from its own live
        # default route. See NatRuleConfig's own docstring.
        rule = NatRuleConfig(vlan_id=vlan_id, src_address=src_cidr)
        try:
            await get_adapter(DeviceVendor.MIKROTIK).configure_nat_masquerade(
                creds, rule=rule
            )
        # Both subclasses of MikroTikDeviceError, so both come first. The
        # WAN one is separated because "this router is not telling us where
        # the internet is" is a different, operator-fixable condition that
        # reads as nonsense reported as a NAT write failure.
        except MikroTikWanInterfaceError as exc:
            raise VlanNatWanInterfaceUnresolvedError(
                credentials.host, exc.detail
            ) from exc
        except MikroTikConnectionError as exc:
            raise VlanDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikDeviceError as exc:
            raise VlanDeviceOperationError(
                "configure_nat_masquerade", exc.detail
            ) from exc

    async def delete_nat_masquerade(
        self, credentials: VlanCredentials, *, vlan_id: int
    ) -> None:
        creds = self._gateway_credentials(credentials)
        # src_address is required by the shape but unread on the delete
        # path, which matches on the VLAN's identity alone -- so the
        # current subnet, whatever it is, cannot change what is removed.
        rule = NatRuleConfig(vlan_id=vlan_id, src_address="")
        try:
            await get_adapter(DeviceVendor.MIKROTIK).delete_nat_masquerade(
                creds, rule=rule
            )
        except MikroTikConnectionError as exc:
            raise VlanDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikDeviceError as exc:
            raise VlanDeviceOperationError(
                "delete_nat_masquerade", exc.detail
            ) from exc


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
    "VlanDeviceAddress",
    "VlanDeviceInterface",
    "VlanNetworkSnapshot",
    "get_vlan_adapter",
    "list_supported_vlan_vendors",
]
