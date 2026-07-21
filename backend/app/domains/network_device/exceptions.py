"""Network Device (NAC) domain exceptions.

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
    "NetworkDeviceError",
    "NetworkDeviceNotFoundError",
    "CrossOrganizationNetworkDeviceAccessError",
    "DuplicateNetworkDeviceError",
    "InvalidMacAddressError",
]


class NetworkDeviceError(CloudGuestError):
    """Base exception for Network Device (NAC) domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class NetworkDeviceNotFoundError(NetworkDeviceError):
    def __init__(self, device_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Network device not found: {device_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class CrossOrganizationNetworkDeviceAccessError(NetworkDeviceError):
    """Mirrors ``app.domains.dhcp.exceptions
    .CrossOrganizationDhcpPoolAccessError``'s identical shape."""

    def __init__(self) -> None:
        super().__init__(
            "Cannot access a network device belonging to another organization",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class DuplicateNetworkDeviceError(NetworkDeviceError):
    """Raised when a MAC address is registered twice within the same
    organization -- mirrors ``app.domains.mac_authorization``'s identical
    ``(organization_id, mac_address)`` uniqueness posture."""

    def __init__(self, mac_address: str) -> None:
        super().__init__(
            f"'{mac_address}' is already registered for this organization",
            status_code=status.HTTP_409_CONFLICT,
        )


class InvalidMacAddressError(NetworkDeviceError):
    def __init__(self, value: str) -> None:
        super().__init__(
            f"Invalid MAC address: '{value}'",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
