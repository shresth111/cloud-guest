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


class NewOrganizationRequiredError(LocationError):
    """Smart Location Provisioning: the caller supplied neither an
    ``existing_organization_id`` (provision a new location for an existing
    customer) nor a full ``new_organization`` payload (create the customer
    too) -- exactly one of the two is required, see
    ``docs/location/FLOW.md``'s "existing-vs-new-organization" section."""

    def __init__(
        self,
        message: str = (
            "Either existing_organization_id or new_organization must be provided"
        ),
    ) -> None:
        super().__init__(message, status_code=status.HTTP_400_BAD_REQUEST)


class DefaultConfigTemplateNotFoundError(LocationError):
    """Smart Location Provisioning: no explicit ``router_config_template_id``
    was supplied and no active system (``is_system_template=True``)
    ``ConfigTemplate`` exists anywhere in ``router_provisioning`` for this
    method to fall back to.

    This is a genuine, honestly-surfaced operational gap, not a bug this
    module papers over -- see ``docs/location/FLOW.md``'s "default router
    config template gap" section: this sandbox's fixture/seed data does not
    ship any system config template, so a real deployment must create at
    least one (``POST /router-provisioning/templates`` with no
    ``X-Organization-Id`` header) before Smart Location Provisioning's
    "apply default router configuration" step can succeed without an
    explicit ``router_config_template_id`` override."""

    def __init__(
        self,
        message: str = (
            "No router_config_template_id was supplied and no active system "
            "config template exists to apply as a default -- create one via "
            "router_provisioning first, or pass an explicit "
            "router_config_template_id"
        ),
    ) -> None:
        super().__init__(message, status_code=status.HTTP_409_CONFLICT)


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
