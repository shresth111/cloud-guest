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


class VlanHotspotPushUnsupportedError(VlanError):
    """Asked to push a VLAN with ``enable_hotspot`` set.

    The rendered script realizes that toggle as six further RouterOS
    commands (pool, dhcp-server, dhcp-server network, hotspot profile, dns
    static, hotspot server -- see ``renderers._render_vlan_hotspot``). The
    device adapter implements none of them yet.

    Rejected rather than partially applied: pushing the interface and
    address while silently dropping the captive portal would report success
    for a VLAN whose guests never see a portal, which is precisely the
    failure shape this work exists to remove.
    """

    def __init__(self, vlan_pk: uuid.UUID) -> None:
        super().__init__(
            f"VLAN '{vlan_pk}' has a hotspot enabled, which this push does not "
            "configure yet -- push the router's full configuration instead, or "
            "disable the hotspot on this VLAN",
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
