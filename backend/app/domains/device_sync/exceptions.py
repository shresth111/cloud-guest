"""Device Synchronization domain exceptions.

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
    "DeviceSyncError",
    "DeviceSyncRunNotFoundError",
    "CrossOrganizationDeviceSyncRunAccessError",
]


class DeviceSyncError(CloudGuestError):
    """Base exception for Device Synchronization domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class DeviceSyncRunNotFoundError(DeviceSyncError):
    def __init__(self, run_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Device sync run not found: {run_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class CrossOrganizationDeviceSyncRunAccessError(DeviceSyncError):
    """A caller acting within organization A attempted to read a device
    sync run belonging to organization B -- mirrors
    ``app.domains.isp.exceptions.CrossOrganizationIspLinkAccessError``."""

    def __init__(self) -> None:
        super().__init__(
            "Cannot access a device sync run belonging to another organization",
            status_code=status.HTTP_403_FORBIDDEN,
        )
