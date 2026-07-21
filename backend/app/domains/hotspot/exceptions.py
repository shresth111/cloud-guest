"""Hotspot Settings domain exceptions.

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
    "HotspotError",
    "HotspotProfileNotFoundError",
    "CrossOrganizationHotspotProfileAccessError",
    "InvalidWalledGardenHostError",
    "TooManyWalledGardenHostsError",
]


class HotspotError(CloudGuestError):
    """Base exception for Hotspot Settings domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class HotspotProfileNotFoundError(HotspotError):
    def __init__(self, profile_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Hotspot profile not found: {profile_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class CrossOrganizationHotspotProfileAccessError(HotspotError):
    """A caller acting within organization A attempted to read/mutate a
    hotspot profile belonging to organization B -- mirrors
    ``app.domains.dhcp.exceptions.CrossOrganizationDhcpPoolAccessError``."""

    def __init__(self) -> None:
        super().__init__(
            "Cannot access a hotspot profile belonging to another organization",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class InvalidWalledGardenHostError(HotspotError):
    """Raised when a walled-garden entry is not a real, non-empty
    hostname/IP -- e.g. contains whitespace or is blank."""

    def __init__(self, value: str) -> None:
        super().__init__(
            f"Invalid walled-garden host: '{value}'",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )


class TooManyWalledGardenHostsError(HotspotError):
    def __init__(self, limit: int) -> None:
        super().__init__(
            f"A hotspot profile may list at most {limit} walled-garden hosts",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
