"""Location business logic: site CRUD, organization-hierarchy validation, and
lifecycle management.

Design notes worth calling out (see
``docs/location/LOCATION_ARCHITECTURE.md`` for the full write-up):

* Hierarchy validation: a location must belong to a real, non-archived
  organization. Rather than re-querying the ``organizations`` table with raw
  SQL (which would duplicate ``OrganizationService``'s own notion of "does
  this organization exist and is it archived"), this service composes with
  ``OrganizationService`` through a narrow, duck-typed
  ``OrganizationLookupProtocol`` (just ``get_organization``) -- the same
  cross-domain-composition-not-duplication pattern
  ``OrganizationService`` itself uses for RBAC's audit log
  (``AuditLogWriter``).
* Tenant scoping mirrors ``OrganizationService``'s own
  ``_enforce_tenant_access``: a caller with no ``requesting_organization_id``
  (a platform-level, GLOBAL-scoped role) may act on any location; a caller
  acting within organization A may only read/mutate locations belonging to A
  itself or to A's children (if A is an MSP that owns the location's
  organization).
* ``organization_id`` is immutable after creation -- see
  ``LocationOrganizationImmutableError`` and
  ``docs/location/LOCATION_ARCHITECTURE.md`` for the reasoning. The
  update schema simply never exposes the field, so there is nothing for
  this service to strip; the immutability is enforced structurally rather
  than defensively re-checked here (mirrored by a direct model/schema test).
* No separate ``LocationMember`` table -- a user's relationship to a
  location is fully expressed by RBAC's ``user_roles`` scoped to
  ``location_id``. See ``docs/location/LOCATION_ARCHITECTURE.md`` §3 for why
  no gap was found that would require one.
* Audit logging reuses RBAC's existing ``audit_log_entries`` table via the
  same narrow, duck-typed ``AuditLogWriter`` protocol shape
  ``OrganizationService`` uses (not imported from there, to avoid a needless
  cross-domain coupling for what is, structurally, a one-method protocol).
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Any, Protocol

from app.common.exceptions import CloudGuestError
from app.database.utils.pagination import PaginationMeta
from app.domains.organization.enums import OrganizationStatus
from app.domains.organization.exceptions import OrganizationArchivedError
from app.domains.organization.models import Organization
from app.domains.rbac.enums import AuditAction

from .enums import LocationStatus, PropertyType
from .exceptions import (
    CrossOrganizationLocationAccessError,
    DuplicateLocationSlugError,
    LocationArchivedError,
    LocationNotFoundError,
)
from .models import Location
from .number_generator import (
    LocationCodeCounterRepositoryProtocol,
    generate_location_code,
    peek_next_location_code,
)
from .repository import LocationRepositoryProtocol

logger = logging.getLogger(__name__)


class OrganizationLookupProtocol(Protocol):
    """The minimal surface this service needs from ``OrganizationService`` to
    validate a location's parent organization, without depending on the rest
    of ``OrganizationService``'s CRUD/membership surface."""

    async def get_organization(
        self, organization_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Organization: ...


class AuditLogWriter(Protocol):
    """The minimal surface this service needs to write into RBAC's shared
    ``audit_log_entries`` table, without depending on the rest of
    ``RBACRepositoryProtocol``."""

    async def create_audit_log_entry(self, **fields: object) -> object: ...


def _normalize_slug(slug: str) -> str:
    return slug.strip().lower()


class LocationService:
    """Core location business logic."""

    def __init__(
        self,
        repository: LocationRepositoryProtocol,
        organization_lookup: OrganizationLookupProtocol,
        *,
        location_code_counter: LocationCodeCounterRepositoryProtocol,
        audit_writer: AuditLogWriter | None = None,
    ) -> None:
        self.repository = repository
        self.organization_lookup = organization_lookup
        self.location_code_counter = location_code_counter
        self.audit_writer = audit_writer

    # -- reads -----------------------------------------------------------------

    async def get_location(
        self,
        location_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Location:
        location = await self.repository.get_by_id(
            location_id, include_deleted=include_deleted
        )
        if location is None:
            raise LocationNotFoundError(location_id)
        await self._enforce_organization_scope(location, requesting_organization_id)
        return location

    async def get_by_slug(self, organization_id: uuid.UUID, slug: str) -> Location:
        location = await self.repository.get_by_slug(
            organization_id, _normalize_slug(slug)
        )
        if location is None:
            raise LocationNotFoundError(slug)
        return location

    async def list_locations(
        self,
        *,
        organization_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
        search: str | None = None,
        status: LocationStatus | None = None,
    ) -> tuple[list[Location], PaginationMeta]:
        await self._assert_organization_accessible(
            organization_id, requesting_organization_id
        )
        return await self.repository.list_locations(
            organization_id=organization_id,
            page=page,
            page_size=page_size,
            search=search,
            status=status.value if status else None,
        )

    async def preview_next_location_code(self) -> str:
        """The ``location_code`` a subsequent ``create_location`` call
        would generate right now -- a genuine dry-run read, never
        consuming the real counter. Backs the Organization Provisioning
        Wizard's "Site ID" preview field (see
        ``app.domains.location.provisioning_service
        .LocationProvisioningService.preview_provision_location``)."""
        return await peek_next_location_code(
            self.location_code_counter, at=datetime.now(UTC)
        )

    # -- writes ------------------------------------------------------------------

    async def create_location(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        organization_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        name: str,
        slug: str,
        address_line1: str,
        city: str,
        state_province: str,
        postal_code: str,
        country: str,
        address_line2: str | None = None,
        timezone: str = "UTC",
        latitude: float | None = None,
        longitude: float | None = None,
        contact_name: str | None = None,
        contact_phone: str | None = None,
        contact_email: str | None = None,
        status: LocationStatus = LocationStatus.ACTIVE,
        settings: dict[str, Any] | None = None,
        property_type: PropertyType | None = None,
    ) -> Location:
        await self._assert_organization_accessible(
            organization_id, requesting_organization_id
        )
        await self._assert_organization_active(organization_id)

        normalized_slug = _normalize_slug(slug)
        if await self.repository.get_by_slug(organization_id, normalized_slug):
            raise DuplicateLocationSlugError(organization_id, normalized_slug)

        # ``location_code`` is auto-generated for *every* location, not just
        # ones created through the Smart Location Provisioning orchestration
        # -- see ``models.LocationCodeCounter``'s docstring for the real,
        # DB-level-atomic mechanism (mirrors
        # ``app.domains.billing.number_generator``'s identical pattern).
        location_code = await generate_location_code(
            self.location_code_counter, at=datetime.now(UTC)
        )

        location = await self.repository.create_location(
            organization_id=organization_id,
            name=name,
            slug=normalized_slug,
            status=status.value,
            property_type=property_type.value if property_type else None,
            location_code=location_code,
            address_line1=address_line1,
            address_line2=address_line2,
            city=city,
            state_province=state_province,
            postal_code=postal_code,
            country=country.upper(),
            timezone=timezone,
            latitude=latitude,
            longitude=longitude,
            contact_name=contact_name,
            contact_phone=contact_phone,
            contact_email=contact_email.lower() if contact_email else None,
            settings=settings or {},
            created_by=actor_user_id,
        )
        await self._audit(
            actor_user_id,
            AuditAction.LOCATION_CREATED,
            entity_id=location.id,
            description=f"Location '{location.name}' created",
            organization_id=organization_id,
            location_id=location.id,
        )
        return location

    async def update_location(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        location_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        data: dict[str, object],
    ) -> Location:
        location = await self.get_location(
            location_id, requesting_organization_id=requesting_organization_id
        )
        if location.status == LocationStatus.ARCHIVED.value:
            raise LocationArchivedError(location_id)

        update_data = dict(data)
        # organization_id is immutable after creation -- the schema layer
        # never exposes it on the update request, so it should never appear
        # here; defensively strip it regardless in case a future caller
        # constructs `data` by hand (e.g. from a script), so behavior can
        # never silently diverge from the documented immutability decision.
        update_data.pop("organization_id", None)

        if update_data.get("slug") is not None:
            normalized = _normalize_slug(str(update_data["slug"]))
            existing = await self.repository.get_by_slug(
                location.organization_id, normalized
            )
            if existing is not None and existing.id != location.id:
                raise DuplicateLocationSlugError(location.organization_id, normalized)
            update_data["slug"] = normalized

        if update_data.get("country") is not None:
            update_data["country"] = str(update_data["country"]).upper()

        if update_data.get("contact_email") is not None:
            update_data["contact_email"] = str(update_data["contact_email"]).lower()

        updated = await self.repository.update_location(
            location, {**update_data, "updated_by": actor_user_id}
        )
        await self._audit(
            actor_user_id,
            AuditAction.LOCATION_UPDATED,
            entity_id=updated.id,
            description=f"Location '{updated.name}' updated",
            organization_id=updated.organization_id,
            location_id=updated.id,
        )
        return updated

    async def archive_location(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        location_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> Location:
        location = await self.get_location(
            location_id, requesting_organization_id=requesting_organization_id
        )

        updated = await self.repository.update_location(
            location,
            {"status": LocationStatus.ARCHIVED.value, "updated_by": actor_user_id},
        )
        updated = await self.repository.soft_delete_location(updated)
        await self._audit(
            actor_user_id,
            AuditAction.LOCATION_ARCHIVED,
            entity_id=updated.id,
            description=f"Location '{updated.name}' archived",
            organization_id=updated.organization_id,
            location_id=updated.id,
        )
        return updated

    async def suspend_location(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        location_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> Location:
        return await self._set_status(
            actor_user_id=actor_user_id,
            location_id=location_id,
            requesting_organization_id=requesting_organization_id,
            new_status=LocationStatus.SUSPENDED,
            action=AuditAction.LOCATION_SUSPENDED,
        )

    async def activate_location(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        location_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> Location:
        return await self._set_status(
            actor_user_id=actor_user_id,
            location_id=location_id,
            requesting_organization_id=requesting_organization_id,
            new_status=LocationStatus.ACTIVE,
            action=AuditAction.LOCATION_ACTIVATED,
        )

    async def _set_status(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        location_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        new_status: LocationStatus,
        action: AuditAction,
    ) -> Location:
        location = await self.get_location(
            location_id, requesting_organization_id=requesting_organization_id
        )
        if location.status == LocationStatus.ARCHIVED.value:
            raise LocationArchivedError(location_id)

        updated = await self.repository.update_location(
            location, {"status": new_status.value, "updated_by": actor_user_id}
        )
        await self._audit(
            actor_user_id,
            action,
            entity_id=updated.id,
            description=f"Location '{updated.name}' {new_status.value}",
            organization_id=updated.organization_id,
            location_id=updated.id,
        )
        return updated

    # -- internal helpers -------------------------------------------------------

    async def _assert_organization_active(self, organization_id: uuid.UUID) -> None:
        """Raises if the parent organization does not exist
        (``OrganizationNotFoundError``, propagated from
        ``OrganizationLookupProtocol.get_organization``) or is archived
        (``OrganizationArchivedError``)."""
        organization = await self.organization_lookup.get_organization(organization_id)
        if organization.status == OrganizationStatus.ARCHIVED.value:
            raise OrganizationArchivedError(organization_id)

    async def _assert_organization_accessible(
        self,
        organization_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> None:
        """Enforces tenant scoping for the *target* organization named by a
        path parameter (list/create), mirroring
        ``OrganizationService._enforce_tenant_access`` -- a platform-level
        caller (``requesting_organization_id is None``) may target any
        organization; an org-scoped caller may only target its own
        organization or (if it is an MSP) one of its children."""
        if requesting_organization_id is None:
            return
        if organization_id == requesting_organization_id:
            return
        organization = await self.organization_lookup.get_organization(
            organization_id, include_deleted=True
        )
        if organization.parent_organization_id == requesting_organization_id:
            return
        raise CrossOrganizationLocationAccessError()

    async def _enforce_organization_scope(
        self, location: Location, requesting_organization_id: uuid.UUID | None
    ) -> None:
        """Enforces tenant scoping for an *existing* location resolved by id
        (read/update/archive/suspend/activate)."""
        if requesting_organization_id is None:
            return
        if location.organization_id == requesting_organization_id:
            return
        organization = await self.organization_lookup.get_organization(
            location.organization_id, include_deleted=True
        )
        if organization.parent_organization_id == requesting_organization_id:
            return
        raise CrossOrganizationLocationAccessError()

    async def _audit(
        self,
        actor_user_id: uuid.UUID | None,
        action: AuditAction,
        *,
        entity_id: uuid.UUID | None,
        description: str,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        metadata: dict[str, object] | None = None,
    ) -> None:
        if self.audit_writer is not None:
            await self.audit_writer.create_audit_log_entry(
                actor_user_id=actor_user_id,
                action=action.value,
                entity_type="location",
                entity_id=entity_id,
                description=description,
                event_metadata=metadata or {},
                organization_id=organization_id,
                location_id=location_id,
            )
        logger.info(
            "location_audit_event",
            extra={
                "action": action.value,
                "entity_id": str(entity_id) if entity_id else None,
            },
        )


__all__ = [
    "LocationService",
    "OrganizationLookupProtocol",
    "AuditLogWriter",
    "CloudGuestError",
]
