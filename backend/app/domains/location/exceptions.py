"""Location domain exceptions.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide exception handler / ``ApiResponse`` envelope exactly like
``OrganizationError``/``RBACError`` do -- no route needs its own try/except
translation.
"""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError


class LocationError(CloudGuestError):
    """Base exception for location domain errors."""

    def __init__(self, message: str, *, status_code: int) -> None:
        super().__init__(message, status_code=status_code)


class LocationNotFoundError(LocationError):
    def __init__(self, identifier: object) -> None:
        super().__init__(
            f"Location not found: {identifier}", status_code=status.HTTP_404_NOT_FOUND
        )


class DuplicateLocationSlugError(LocationError):
    def __init__(self, organization_id: uuid.UUID, slug: str) -> None:
        super().__init__(
            f"A location with slug '{slug}' already exists in organization "
            f"{organization_id}",
            status_code=status.HTTP_409_CONFLICT,
        )


class LocationArchivedError(LocationError):
    def __init__(self, location_id: uuid.UUID) -> None:
        super().__init__(
            f"Location {location_id} is archived and cannot be modified",
            status_code=status.HTTP_409_CONFLICT,
        )


class LocationOrganizationImmutableError(LocationError):
    """A location's ``organization_id`` cannot be changed after creation --
    see ``docs/location/LOCATION_ARCHITECTURE.md`` for the reasoning."""

    def __init__(self, location_id: uuid.UUID) -> None:
        super().__init__(
            f"Location {location_id}'s organization cannot be changed after "
            "creation",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class CrossOrganizationLocationAccessError(LocationError):
    """A caller acting within organization A attempted to read/mutate a
    location belonging to organization B, where B is neither A itself nor a
    child of A (mirrors ``organization.exceptions.CrossOrganizationAccessError``)."""

    def __init__(
        self,
        message: str = "Cannot access a location outside your own organization scope",
    ) -> None:
        super().__init__(message, status_code=status.HTTP_403_FORBIDDEN)


class LocationOrganizationMismatchError(LocationError):
    """The ``X-Location-Id`` header named a location that does not belong to
    the resolved ``X-Organization-Id`` organization context (RBAC's
    ``CurrentLocation`` -- see ``app/domains/rbac/dependencies.py``)."""

    def __init__(self, location_id: uuid.UUID, organization_id: uuid.UUID) -> None:
        super().__init__(
            f"Location {location_id} does not belong to organization "
            f"{organization_id}",
            status_code=status.HTTP_403_FORBIDDEN,
        )
