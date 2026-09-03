"""Port Forwarding Management domain exceptions.

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
    "PortForwardingError",
    "PortForwardingRuleNotFoundError",
    "CrossOrganizationPortForwardingRuleAccessError",
    "InvalidPortError",
    "InvalidAddressError",
    "PortForwardingConflictError",
    "PortForwardingRuleNotEnabledError",
    "PortForwardingMissingCredentialsError",
    "UnsupportedPortForwardingVendorError",
    "PortForwardingDeviceConnectionError",
    "PortForwardingDeviceOperationError",
]


class PortForwardingError(CloudGuestError):
    """Base exception for Port Forwarding Management domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class PortForwardingRuleNotFoundError(PortForwardingError):
    def __init__(self, rule_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Port forwarding rule not found: {rule_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class CrossOrganizationPortForwardingRuleAccessError(PortForwardingError):
    """A caller acting within organization A attempted to read/mutate a
    port forwarding rule belonging to organization B -- mirrors
    ``app.domains.dhcp.exceptions.CrossOrganizationDhcpPoolAccessError``."""

    def __init__(self) -> None:
        super().__init__(
            "Cannot access a port forwarding rule belonging to another organization",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class InvalidPortError(PortForwardingError):
    """Raised when a port field falls outside the real 1-65535 usable
    range."""

    def __init__(self, field_name: str, port: int) -> None:
        super().__init__(
            f"Invalid {field_name} {port}: must be between 1 and 65535",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )


class InvalidAddressError(PortForwardingError):
    """Raised when an address field is supplied but is not a real,
    parseable IP address or CIDR block (validated via Python's own
    ``ipaddress`` module)."""

    def __init__(self, field_name: str, value: str) -> None:
        super().__init__(
            f"Invalid {field_name}: '{value}'",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )


class PortForwardingConflictError(PortForwardingError):
    """Raised when a rule's own (protocol, destination_address,
    destination_port) already matches another non-deleted rule on the
    same router -- two rules can't both claim to forward the same
    external port/protocol/address to different internal targets. See
    ``models.PortForwardingRule``'s own module docstring for why this is
    a service-layer check, not a database constraint."""

    def __init__(self, router_id: uuid.UUID, conflicting_rule_id: uuid.UUID) -> None:
        super().__init__(
            f"Conflicts with existing port forwarding rule "
            f"'{conflicting_rule_id}' on router '{router_id}'",
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


class PortForwardingRuleNotEnabledError(PortForwardingError):
    """A disabled rule is intent to *not* forward. Pushing one would open a
    live inbound path through the router's WAN for a row the operator has
    switched off -- the one direction in this domain where doing the wrong
    thing is an exposure, not just drift."""

    def __init__(self, rule_id: uuid.UUID) -> None:
        super().__init__(
            f"Port forwarding rule '{rule_id}' is disabled and cannot be "
            "pushed to a device",
            status_code=status.HTTP_409_CONFLICT,
        )


class PortForwardingMissingCredentialsError(PortForwardingError):
    """The target router has no reachable host, API username, or decryptable
    API secret -- raise rather than guess, mirroring ``dhcp``/``vlan``."""

    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Router '{router_id}' has no usable API credentials for a port "
            "forwarding push",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class UnsupportedPortForwardingVendorError(PortForwardingError):
    """``Router.vendor`` is a free ``String(50)``, so a row carrying
    ``"MikroTik"`` or ``"mikrotik_routeros"`` lands here and gets this
    domain's typed 400 rather than an opaque error from inside the
    gateway."""

    def __init__(self, vendor: str) -> None:
        super().__init__(
            "No port forwarding device adapter is registered for vendor "
            f"'{vendor}'",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class PortForwardingDeviceConnectionError(PortForwardingError):
    """Could not reach the router at all -- a 502, not a 500: the failure is
    upstream of this service, not inside it."""

    def __init__(self, host: str, detail: str) -> None:
        super().__init__(
            f"Could not connect to router at {host}: {detail}",
            status_code=status.HTTP_502_BAD_GATEWAY,
        )


class PortForwardingDeviceOperationError(PortForwardingError):
    """The router was reached and refused, or failed, the operation. Carries
    the device's own words verbatim."""

    def __init__(self, operation: str, detail: str) -> None:
        super().__init__(
            f"Router rejected {operation}: {detail}",
            status_code=status.HTTP_502_BAD_GATEWAY,
        )
