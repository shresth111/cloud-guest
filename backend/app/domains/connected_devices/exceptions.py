"""Connected Device Management domain exceptions.

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
    "ConnectedDeviceError",
    "ConnectedDeviceNotFoundError",
    "CrossOrganizationConnectedDeviceAccessError",
    "ConnectedDeviceMissingCredentialsError",
    "ConnectedDeviceConnectionError",
    "ConnectedDeviceOperationError",
    "UnsupportedConnectedDeviceVendorError",
]


class ConnectedDeviceError(CloudGuestError):
    """Base exception for Connected Device Management domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class ConnectedDeviceNotFoundError(ConnectedDeviceError):
    def __init__(self, device_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Connected device not found: {device_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class CrossOrganizationConnectedDeviceAccessError(ConnectedDeviceError):
    """A caller acting within organization A attempted to read/mutate a
    connected device belonging to organization B -- mirrors
    ``app.domains.isp.exceptions.CrossOrganizationIspLinkAccessError``."""

    def __init__(self) -> None:
        super().__init__(
            "Cannot access a connected device belonging to another organization",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class ConnectedDeviceMissingCredentialsError(ConnectedDeviceError):
    """Raised when a router has no management IP/username/decrypted
    secret stored -- mirrors
    ``app.domains.isp.exceptions.IspMissingCredentialsError``, applied to
    device-sync/disconnect operations."""

    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Router '{router_id}' is missing device connection credentials "
            "(management IP, API username, or API secret)",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class ConnectedDeviceConnectionError(ConnectedDeviceError):
    """Could not open a real RouterOS API connection to the router at
    all -- mirrors
    ``app.domains.isp.exceptions.IspDeviceConnectionError``."""

    def __init__(self, host: str, reason: str) -> None:
        super().__init__(
            f"Could not connect to router at '{host}': {reason}",
            status_code=status.HTTP_502_BAD_GATEWAY,
        )


class ConnectedDeviceOperationError(ConnectedDeviceError):
    """A connection was opened, but the RouterOS command itself failed
    -- mirrors ``app.domains.isp.exceptions.IspDeviceOperationError``."""

    def __init__(self, operation: str, reason: str) -> None:
        super().__init__(
            f"Connected device operation '{operation}' failed: {reason}",
            status_code=status.HTTP_502_BAD_GATEWAY,
        )


class UnsupportedConnectedDeviceVendorError(ConnectedDeviceError):
    """No sync/disconnect adapter is registered for this router's own
    ``vendor`` -- mirrors
    ``app.domains.isp.exceptions.UnsupportedIspVendorError``."""

    def __init__(self, vendor: str) -> None:
        super().__init__(
            f"No connected-device adapter registered for vendor '{vendor}'",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
