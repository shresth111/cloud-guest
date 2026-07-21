"""MAC Authorization domain exceptions.

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
    "MacAuthorizationError",
    "MacAuthorizationEntryNotFoundError",
    "CrossOrganizationMacAuthorizationAccessError",
    "InvalidMacAddressError",
    "InvalidExpiryError",
    "MacAuthorizationAlreadyExistsError",
    "OrganizationRequiredError",
]


class MacAuthorizationError(CloudGuestError):
    """Base exception for MAC Authorization domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class MacAuthorizationEntryNotFoundError(MacAuthorizationError):
    def __init__(self, entry_id: uuid.UUID | str) -> None:
        super().__init__(
            f"MAC authorization entry not found: {entry_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class CrossOrganizationMacAuthorizationAccessError(MacAuthorizationError):
    """A caller acting within organization A attempted to read/mutate a
    MAC authorization entry belonging to organization B -- mirrors
    ``app.domains.vlan.exceptions.CrossOrganizationVlanAccessError``."""

    def __init__(self) -> None:
        super().__init__(
            "Cannot access a MAC authorization entry belonging to another organization",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class InvalidMacAddressError(MacAuthorizationError):
    """Raised when a MAC address is not a real, parseable
    colon/dash-separated six-octet address (see
    ``constants.MAC_ADDRESS_PATTERN``)."""

    def __init__(self, value: str) -> None:
        super().__init__(
            f"Invalid MAC address: '{value}'",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )


class InvalidExpiryError(MacAuthorizationError):
    """Raised when ``expires_at`` disagrees with ``authorization_type``:
    missing or not in the future for ``TEMPORARY``, or present at all for
    ``PERMANENT``."""

    def __init__(self, reason: str) -> None:
        super().__init__(
            f"Invalid expiry: {reason}",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )


class MacAuthorizationAlreadyExistsError(MacAuthorizationError):
    """An organization may not hold two non-deleted entries for the same
    MAC address."""

    def __init__(self, organization_id: uuid.UUID, mac_address: str) -> None:
        super().__init__(
            f"Organization '{organization_id}' already has an authorization "
            f"entry for MAC address '{mac_address}'",
            status_code=status.HTTP_409_CONFLICT,
        )


class OrganizationRequiredError(MacAuthorizationError):
    """Raised when a create/import request carries no
    ``X-Organization-Id`` context (``CurrentOrganization`` returns
    ``None``) -- every ``MacAuthorizationEntry`` belongs to exactly one
    organization (``organization_id`` is not nullable), unlike
    ``app.domains.policy.models.Policy``'s own "nullable org means
    platform-wide" convention."""

    def __init__(self) -> None:
        super().__init__(
            "An X-Organization-Id header is required to create or import "
            "MAC authorization entries",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
