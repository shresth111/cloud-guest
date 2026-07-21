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
