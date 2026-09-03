"""DHCP Pool Management domain exceptions.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide exception handler / ``ApiResponse`` envelope exactly like every
other domain's exception hierarchy -- no route needs its own try/except
translation.
"""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError

__all__ = [
    "DhcpError",
    "DhcpPoolNotFoundError",
    "CrossOrganizationDhcpPoolAccessError",
    "InvalidIpAddressError",
    "InvalidAddressRangeError",
    "DhcpPoolRangeConflictError",
    "DhcpPoolNotEnabledError",
    "DhcpPoolMissingInterfaceError",
    "DhcpPoolMissingGatewayError",
    "DhcpPoolHotspotConflictError",
    "DhcpMissingCredentialsError",
    "UnsupportedDhcpVendorError",
    "DhcpDeviceConnectionError",
    "DhcpDeviceOperationError",
]


class DhcpError(CloudGuestError):
    """Base exception for DHCP Pool Management domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class DhcpPoolNotFoundError(DhcpError):
    def __init__(self, pool_id: uuid.UUID | str) -> None:
        super().__init__(
            f"DHCP pool not found: {pool_id}", status_code=status.HTTP_404_NOT_FOUND
        )


class CrossOrganizationDhcpPoolAccessError(DhcpError):
    """A caller acting within organization A attempted to read/mutate a
    DHCP pool belonging to organization B -- mirrors
    ``app.domains.vlan.exceptions.CrossOrganizationVlanAccessError``."""

    def __init__(self) -> None:
        super().__init__(
            "Cannot access a DHCP pool belonging to another organization",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class InvalidIpAddressError(DhcpError):
    """Raised when a gateway/DNS field is supplied but is not a real,
    parseable IP address (validated via Python's own ``ipaddress``
    module)."""

    def __init__(self, field_name: str, value: str) -> None:
        super().__init__(
            f"Invalid {field_name}: '{value}'",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )


class InvalidAddressRangeError(DhcpError):
    """Raised when ``address_range_start``/``address_range_end`` are not
    both real, parseable IP addresses, or when the start is numerically
    greater than the end."""

    def __init__(self, start: str, end: str, reason: str) -> None:
        super().__init__(
            f"Invalid address range '{start}'-'{end}': {reason}",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )


class DhcpPoolRangeConflictError(DhcpError):
    """Raised when a pool's address range overlaps another non-deleted
    pool's own range on the same router and interface -- see
    ``models.DhcpPool``'s own module docstring for why this is a
    service-layer check, not a database constraint."""

    def __init__(self, router_id: uuid.UUID, conflicting_pool_id: uuid.UUID) -> None:
        super().__init__(
            f"Address range overlaps existing DHCP pool "
            f"'{conflicting_pool_id}' on router '{router_id}'",
            status_code=status.HTTP_409_CONFLICT,
        )


# ============================================================================
# Device push -- preconditions checked before a socket is opened, so a
# misconfigured row fails as a 4xx naming the problem rather than as a
# device timeout. All subclass ``CloudGuestError``, so the app-wide handler
# turns them into a real non-2xx: the frontend interceptor unwraps ``data``
# and never reads ``success``, so a 200 carrying ``success: false`` would be
# indistinguishable from a successful push to every caller in the app.
# ============================================================================


class DhcpPoolNotEnabledError(DhcpError):
    """A disabled pool is intent to *not* serve addresses. Pushing one
    would create a live ``/ip dhcp-server`` for a row the operator has
    switched off."""

    def __init__(self, pool_id: uuid.UUID) -> None:
        super().__init__(
            f"DHCP pool '{pool_id}' is disabled and cannot be pushed to a device",
            status_code=status.HTTP_409_CONFLICT,
        )


class DhcpPoolMissingInterfaceError(DhcpError):
    """``interface`` is nullable on this model, and the adapter derives
    both RouterOS identifiers (``<iface>-pool``, ``<iface>-dhcp``) and the
    server's own ``interface=`` from it. Pushing without one would either
    fail obscurely inside the gateway or bind the server to nothing.

    ``render_dhcp_pool`` handles the same case by emitting a comment and
    skipping -- fine for a script, but on a direct push that silence would
    report success for a device that received nothing.
    """

    def __init__(self, pool_id: uuid.UUID) -> None:
        super().__init__(
            f"DHCP pool '{pool_id}' has no interface configured -- set the "
            "interface (e.g. the VLAN it serves, such as vlan300) before "
            "pushing it",
            status_code=status.HTTP_409_CONFLICT,
        )


class DhcpPoolMissingGatewayError(DhcpError):
    """A DHCP server that hands out addresses with no gateway gives guests
    an IP and no route off the subnet -- working-looking and useless.

    Raised rather than defaulted: guessing ``.1`` would be a fabricated
    network fact, and the operator is the only one who knows which address
    the router actually holds on that interface.
    """

    def __init__(self, pool_id: uuid.UUID) -> None:
        super().__init__(
            f"DHCP pool '{pool_id}' has no gateway IP address -- guests would "
            "receive an address with no route off the subnet",
            status_code=status.HTTP_409_CONFLICT,
        )


class DhcpMissingCredentialsError(DhcpError):
    """The target router has no reachable host, API username, or decryptable
    API secret -- raise rather than guess, mirroring ``vlan``/``qos``."""

    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Router '{router_id}' has no usable API credentials for a DHCP push",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class UnsupportedDhcpVendorError(DhcpError):
    """``Router.vendor`` is a free ``String(50)``, so a row carrying
    ``"MikroTik"`` or ``"mikrotik_routeros"`` lands here and gets this
    domain's typed 400 rather than an opaque error from inside the
    gateway."""

    def __init__(self, vendor: str) -> None:
        super().__init__(
            f"No DHCP device adapter is registered for vendor '{vendor}'",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class DhcpDeviceConnectionError(DhcpError):
    """Could not reach the router at all -- a 502, not a 500: the failure is
    upstream of this service, not inside it."""

    def __init__(self, host: str, detail: str) -> None:
        super().__init__(
            f"Could not connect to router at {host}: {detail}",
            status_code=status.HTTP_502_BAD_GATEWAY,
        )


class DhcpDeviceOperationError(DhcpError):
    """The router was reached and refused, or failed, the operation. Carries
    the device's own words verbatim."""

    def __init__(self, operation: str, detail: str) -> None:
        super().__init__(
            f"Router rejected {operation}: {detail}",
            status_code=status.HTTP_502_BAD_GATEWAY,
        )


class DhcpPoolHotspotConflictError(DhcpError):
    """This pool's interface already belongs to a VLAN's captive portal.

    The mirror image of ``app.domains.vlan.exceptions
    .VlanHotspotDhcpPoolConflictError``, and it exists for the same single
    rule: **a VLAN's captive portal owns DHCP on that VLAN's own
    interface.** A portal must create its own ``/ip pool`` and ``/ip
    dhcp-server`` on the interface it challenges, RouterOS permits one
    DHCP server per interface, and this domain's push creates a second.

    Guarding only the VLAN side would have made the rule half-true: the
    collision is reachable from either direction, and the direction that
    stayed open is the one where a customer configures a portal first --
    the normal order -- and then adds a pool.

    Refused rather than resolved by deleting the portal's objects. Both
    are things an operator deliberately created and can still see in the
    dashboard; silently removing one would report a successful push while
    a captive portal that is supposed to be intercepting guests simply
    stops.

    The message names the VLAN so the fix is actionable, and the fix is
    the operator's to choose: point this pool at another interface, or
    turn that VLAN's portal off.
    """

    def __init__(self, pool_id: uuid.UUID, interface: str, vlan_tag: int) -> None:
        super().__init__(
            f"DHCP pool '{pool_id}' serves interface '{interface}', which "
            f"already carries the captive portal of VLAN {vlan_tag} -- a "
            "portal brings its own DHCP server and RouterOS allows only one "
            "per interface. Re-point this pool, or turn that VLAN's portal "
            "off",
            status_code=status.HTTP_409_CONFLICT,
        )
