"""Firewall Rule Management domain exceptions.

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
    "FirewallError",
    "FirewallRuleNotFoundError",
    "CrossOrganizationFirewallRuleAccessError",
    "InvalidFirewallPortError",
    "InvalidFirewallAddressError",
]


class FirewallError(CloudGuestError):
    """Base exception for Firewall Rule Management domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class FirewallRuleNotFoundError(FirewallError):
    def __init__(self, rule_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Firewall rule not found: {rule_id}", status_code=status.HTTP_404_NOT_FOUND
        )


class CrossOrganizationFirewallRuleAccessError(FirewallError):
    """Mirrors ``app.domains.dhcp.exceptions
    .CrossOrganizationDhcpPoolAccessError``'s identical shape."""

    def __init__(self) -> None:
        super().__init__(
            "Cannot access a firewall rule belonging to another organization",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class InvalidFirewallPortError(FirewallError):
    def __init__(self, field_name: str, port: int) -> None:
        super().__init__(
            f"Invalid {field_name}: {port} is outside the usable 1-65535 range",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )


class InvalidFirewallAddressError(FirewallError):
    """Raised when a source/destination address is supplied but is not a
    real, parseable IP address or CIDR block."""

    def __init__(self, field_name: str, value: str) -> None:
        super().__init__(
            f"Invalid {field_name}: '{value}'",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
