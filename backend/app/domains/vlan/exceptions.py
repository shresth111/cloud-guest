"""VLAN Management domain exceptions.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide exception handler / ``ApiResponse`` envelope exactly like every
other domain's exception hierarchy -- no route needs its own try/except
translation.
"""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError

from .constants import MAX_VLAN_ID, MIN_VLAN_ID

__all__ = [
    "VlanError",
    "VlanNotFoundError",
    "CrossOrganizationVlanAccessError",
    "VlanIdAlreadyExistsError",
    "InvalidVlanIdError",
    "InvalidCidrError",
    "InvalidGatewayIpAddressError",
    "GatewayOutsideCidrError",
]


class VlanError(CloudGuestError):
    """Base exception for VLAN Management domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class VlanNotFoundError(VlanError):
    def __init__(self, vlan_id: uuid.UUID | str) -> None:
        super().__init__(
            f"VLAN not found: {vlan_id}", status_code=status.HTTP_404_NOT_FOUND
        )


class CrossOrganizationVlanAccessError(VlanError):
    """A caller acting within organization A attempted to read/mutate a
    VLAN belonging to organization B -- mirrors
    ``app.domains.isp.exceptions.CrossOrganizationIspLinkAccessError``."""

    def __init__(self) -> None:
        super().__init__(
            "Cannot access a VLAN belonging to another organization",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class VlanIdAlreadyExistsError(VlanError):
    """A router may not hold two non-deleted ``Vlan`` rows with the same
    ``vlan_id`` -- raised by ``create_vlan``/``update_vlan`` when a
    duplicate is requested for the same router."""

    def __init__(self, router_id: uuid.UUID, vlan_id: int) -> None:
        super().__init__(
            f"Router '{router_id}' already has a VLAN with vlan_id {vlan_id}",
            status_code=status.HTTP_409_CONFLICT,
        )


class InvalidVlanIdError(VlanError):
    """Raised when ``vlan_id`` falls outside IEEE 802.1Q's real 1-4094
    usable range -- see ``constants.MIN_VLAN_ID``/``MAX_VLAN_ID``."""

    def __init__(self, vlan_id: int) -> None:
        super().__init__(
            f"Invalid vlan_id {vlan_id}: must be between "
            f"{MIN_VLAN_ID} and {MAX_VLAN_ID}",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )


class InvalidCidrError(VlanError):
    """Raised when ``cidr`` is supplied but is not a real, parseable CIDR
    block (validated via Python's own ``ipaddress`` module)."""

    def __init__(self, cidr: str) -> None:
        super().__init__(
            f"Invalid CIDR block: '{cidr}'",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )


class InvalidGatewayIpAddressError(VlanError):
    """Raised when ``gateway_ip_address`` is supplied but is not a real,
    parseable IP address (validated via Python's own ``ipaddress``
    module)."""

    def __init__(self, gateway_ip_address: str) -> None:
        super().__init__(
            f"Invalid gateway IP address: '{gateway_ip_address}'",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )


class GatewayOutsideCidrError(VlanError):
    """``gateway_ip_address`` is a real IP address, and ``cidr`` is a real
    block, but the address does not sit inside the block.

    Each value passing its own validator is not enough: the pair is what
    the device is given. ``_device_address`` builds the router's own
    address by pasting the gateway onto the CIDR's prefix length, so a
    gateway outside the block produces an address on a subnet the VLAN
    does not have -- which RouterOS accepts happily and which routes
    nothing. The DHCP network row derived from the same pair then hands
    guests a gateway they cannot reach.
    """

    def __init__(self, gateway_ip_address: str, cidr: str) -> None:
        super().__init__(
            f"Gateway '{gateway_ip_address}' is not inside '{cidr}'",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )


# ---------------------------------------------------------------------------
# Device push
#
# Everything below is raised by ``VlanService.push_vlan_to_device``. They all
# subclass ``CloudGuestError``, so the app-wide handler turns them into a
# real non-2xx response.
#
# That matters more than it looks: the frontend's response interceptor
# (``cloudguest-foundation/src/services/api.ts``) unwraps ``response.data.data``
# and never reads ``envelope.success``. A handler that "reported failure
# honestly" by returning ``200 {"success": false}`` would be indistinguishable
# from success to every caller in the app -- the exact bug this domain is
# being wired up to stop. Failure has to live in the status code.
# ---------------------------------------------------------------------------


class VlanNotEnabledError(VlanError):
    """Asked to push a VLAN whose ``is_enabled`` is ``False``.

    There is nothing correct to push: ``NetworkConfigService
    ._gather_enabled_rows`` filters disabled rows out of the rendered
    script, so device state created here would be state the script pipeline
    never maintains.
    """

    def __init__(self, vlan_pk: uuid.UUID) -> None:
        super().__init__(
            f"VLAN '{vlan_pk}' is disabled and cannot be pushed to a device",
            status_code=status.HTTP_409_CONFLICT,
        )


class VlanMissingInterfaceError(VlanError):
    """Asked to push a VLAN with no parent/physical ``interface``.

    ``Vlan.interface`` is nullable, and ``render_vlan`` handles that by
    emitting a comment and skipping -- harmless in a script, but on a direct
    push the same silence would report success while the device got nothing.
    Rejected before a connection is opened.

    This is not hypothetical: the one real VLAN row in production is
    ``port_mode="access"`` with an empty ``interface``, which access mode
    cannot realize -- there is no port to pull out of the bridge.
    """

    def __init__(self, vlan_pk: uuid.UUID) -> None:
        super().__init__(
            f"VLAN '{vlan_pk}' has no interface configured -- set the parent "
            "trunk (or the dedicated access port) before pushing it",
            status_code=status.HTTP_409_CONFLICT,
        )


class VlanHotspotRequiresSubnetError(VlanError):
    """Asked to push a VLAN with ``enable_hotspot`` set but no ``cidr``,
    no ``gateway_ip_address``, or both.

    A captive portal is not a flag on an interface: it is a pool of real
    addresses to hand out and a real address of its own to answer DHCP,
    DNS and the login page on. ``_render_vlan_hotspot`` refuses the same
    combination by emitting a skip comment; on a direct push the
    equivalent honesty is a 409 before a connection is opened, because
    pushing the interface and silently dropping the portal would report
    success for a VLAN whose guests never see one.

    Deliberately not resolved by inventing a gateway at ``.1``. A network
    fact this platform made up is worse than a refusal that names what is
    missing.
    """

    def __init__(self, vlan_pk: uuid.UUID) -> None:
        super().__init__(
            f"VLAN '{vlan_pk}' has a captive portal enabled but no subnet -- "
            "set both a CIDR and a gateway IP address, or turn the portal off",
            status_code=status.HTTP_409_CONFLICT,
        )


class VlanHotspotDhcpPoolConflictError(VlanError):
    """A captive portal and a separately-configured DHCP Pool both want to
    serve the same interface.

    **The rule this enforces: a VLAN's captive portal owns DHCP on that
    VLAN's own interface, and nothing else may serve it.** A portal is not
    optional about this -- RouterOS's hotspot needs its own ``/ip pool``
    and its own ``/ip dhcp-server`` bound to the hotspot interface -- and
    RouterOS rejects a second ``/ip dhcp-server`` on an interface that
    already has one. Two features on this platform can each create one:
    this VLAN's ``enable_hotspot`` and the DHCP Pool domain's own push.

    Refused, in both directions (pushing the portal while such a pool
    exists, and pushing such a pool while the portal exists), rather than
    resolved by picking a winner. Whichever object lost would be one the
    operator deliberately created and can still see in the dashboard,
    reporting a successful push while serving nobody -- and if the portal
    lost, guests would get leases from a pool with no login page and no
    walled garden, which is a captive portal that is simply off.

    The message names the pool so the operator can act on it, because the
    fix is theirs to choose: delete that pool, point it at another
    interface, or turn the portal off.
    """

    def __init__(self, vlan_pk: uuid.UUID, interface: str, pool_name: str) -> None:
        super().__init__(
            f"VLAN '{vlan_pk}' has a captive portal on '{interface}', but the "
            f"DHCP pool '{pool_name}' already serves that interface -- a "
            "portal brings its own DHCP server and RouterOS allows only one "
            "per interface. Delete or re-point that pool, or turn the portal "
            "off",
            status_code=status.HTTP_409_CONFLICT,
        )


class VlanMissingCredentialsError(VlanError):
    """The VLAN's router has no management IP / API username / decrypted
    secret stored. Mirrors ``QosMissingCredentialsError``."""

    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Router '{router_id}' is missing device connection credentials "
            "(management IP, API username, or API secret)",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class UnsupportedVlanVendorError(VlanError):
    """No VLAN device adapter is registered for the router's vendor."""

    def __init__(self, vendor: str) -> None:
        super().__init__(
            f"No VLAN device adapter is registered for vendor '{vendor}'",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class VlanNatRequiresCidrError(VlanError):
    """Asked to push a VLAN with NAT enabled but no ``cidr``.

    NAT is a rule about a *source subnet*: without one there is nothing to
    masquerade. ``Vlan.cidr`` is nullable and a VLAN legitimately does not
    need one (a tagged interface with no address is a real, valid thing to
    create), so this is a combination the row can genuinely be in.

    Rejected before a connection is opened, and rejected rather than
    quietly skipping the NAT step: skipping would report a successful push
    for a VLAN whose guests have no internet, which is the exact failure
    shape this toggle exists to remove.

    Deliberately not resolved by falling back to the router's WAN subnet
    or to ``0.0.0.0/0``: a masquerade rule with a source address the
    operator did not choose either NATs traffic that should not be NATed
    or matches nothing.
    """

    def __init__(self, vlan_pk: uuid.UUID) -> None:
        super().__init__(
            f"VLAN '{vlan_pk}' has NAT enabled but no CIDR -- set the VLAN's "
            "subnet before pushing it, or turn NAT off",
            status_code=status.HTTP_409_CONFLICT,
        )


class VlanNatWanInterfaceUnresolvedError(VlanError):
    """The router's own WAN-facing interface could not be determined, so
    there is no honest interface to masquerade out of.

    The interface is derived from the router's live default route (see
    ``wyfy_device_gateway.mikrotik_adapter.resolve_wan_interface``) rather
    than stored: nothing in this database knows which port a given site's
    uplink is in, and a hardcoded ``"WAN"``/``"ether1"`` would be wrong at
    the first site that names its ports differently.

    A 502, alongside the other device errors, because it is a statement
    about the device's current state -- no usable default route, or a
    gateway on no known interface -- and not about the request. Usually it
    means the router's own uplink is down, which is worth surfacing as
    exactly that rather than as a NAT-specific failure.
    """

    def __init__(self, host: str, detail: str) -> None:
        super().__init__(
            f"Could not determine the WAN interface on device '{host}': {detail}",
            status_code=status.HTTP_502_BAD_GATEWAY,
        )


class VlanDeviceConnectionError(VlanError):
    """A real connection attempt (RouterOS API, port 8728) failed."""

    def __init__(self, host: str, detail: str) -> None:
        super().__init__(
            f"Could not connect to device at '{host}': {detail}",
            status_code=status.HTTP_502_BAD_GATEWAY,
        )


class VlanDeviceOperationError(VlanError):
    """A device VLAN operation failed after a connection was established."""

    def __init__(self, operation: str, detail: str) -> None:
        super().__init__(
            f"Device operation '{operation}' failed: {detail}",
            status_code=status.HTTP_502_BAD_GATEWAY,
        )



class VlanParentInterfaceNotFoundError(VlanError):
    """The trunk parent this VLAN is tagged on does not exist on the
    router.

    RouterOS does reject an unknown ``interface=`` on ``/interface vlan
    add``, but with a message about an input not matching a value,
    attributed to the VLAN write -- and by then the push has already
    connected and started. Reading the device's own interface list first
    lets the failure name the interface the operator typed, and lets it
    arrive before anything was attempted.

    A 409 rather than a 422: the name is well-formed, and whether it is
    correct is a fact about this particular router's current state, not
    about the request.
    """

    def __init__(self, interface: str, host: str) -> None:
        super().__init__(
            f"No interface named '{interface}' exists on device '{host}'",
            status_code=status.HTTP_409_CONFLICT,
        )


class VlanAccessPortNotFoundError(VlanError):
    """The dedicated physical port an access-mode VLAN claims does not
    exist on the router.

    Separated from :class:`VlanParentInterfaceNotFoundError` because the
    two mean different things to the operator -- one is "your trunk is
    wrong", the other is "there is no such port on this hardware" -- and
    because access mode's own failure is the quieter of the two: the port
    write would otherwise be attempted against a name RouterOS has never
    heard of.
    """

    def __init__(self, port: str, host: str) -> None:
        super().__init__(
            f"No port named '{port}' exists on device '{host}' -- "
            "an access-mode VLAN needs a real physical port",
            status_code=status.HTTP_409_CONFLICT,
        )


class VlanSubnetConflictError(VlanError):
    """This VLAN's subnet overlaps an address the router already carries
    on a different interface.

    Compared against the device's own live ``/ip address`` table, not
    against other ``Vlan`` rows. Those are two different sets: a router
    carries its LAN bridge, its uplink, and anything configured outside
    this platform, none of which has a row here -- and it is the device's
    set, not this database's, that decides whether the push produces a
    routing table with two matching entries and traffic that goes to
    whichever one RouterOS picked.

    Addresses already on *this VLAN's own* bind interface are excluded, or
    every re-push of an unchanged VLAN would conflict with itself.
    """

    def __init__(self, cidr: str, existing_address: str, interface: str) -> None:
        super().__init__(
            f"Subnet '{cidr}' overlaps '{existing_address}', already configured "
            f"on interface '{interface}' of this router",
            status_code=status.HTTP_409_CONFLICT,
        )
