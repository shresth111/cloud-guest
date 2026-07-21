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
