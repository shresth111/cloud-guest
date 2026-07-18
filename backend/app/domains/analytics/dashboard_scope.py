"""Dashboard scope resolution (BE-012 Part 2).

Every domain in this codebase already draws a hard line between "*what* is
this caller allowed to do" (RBAC's ``RequirePermission``) and "*which
tenant's* data are they allowed to see it for" (each domain's own
``_enforce_tenant_access``/``_enforce_tenant_scope`` check -- e.g.
``app.domains.guest.service.GuestService._enforce_tenant_scope``,
``app.domains.organization.service.OrganizationService._enforce_tenant_access``).
This module is that same second check for the dashboard read path, real and
independently tested, not merely inferred from whichever
``X-Organization-Id``/``X-Location-Id`` header happened to be sent.

## Why a header-driven permission check alone is not enough here

``app.domains.rbac.dependencies.RequirePermission(scope=...)`` already
verifies the caller holds a role grant whose scope covers whatever
organization/location the request's headers name. That is real and correct
for the *headers as given* -- but it cannot, by itself, express "an MSP
Admin's role assignment is scoped to their MSP organization, yet they should
also be able to view a *rollup across that MSP's child organizations*
without individually holding a grant scoped to each child". Composing a
child organization into a caller's effective dashboard visibility is exactly
what this module adds, by resolving scope from the caller's **real, active
RBAC role assignments** (via ``app.domains.rbac.authorization.RoleResolver``
-- reused directly, never reimplemented) and then expanding any
MSP-organization grant into its children (via
``app.domains.organization.service.OrganizationService.list_children`` --
also reused directly). Every dashboard endpoint calls
:meth:`DashboardScope.require_organization`/``require_location``/
``require_global`` as a **second, independent check** after RBAC's
permission dependency has already run -- so a caller who, say, crafts an
``X-Organization-Id`` header for an organization they do not actually hold
any role in still gets rejected here even in some hypothetical future where
the permission dependency's own header-trust surface changed.

## Composition, not reinvention

* Active role assignments: ``app.domains.rbac.authorization.RoleResolver``.
* MSP-children expansion: ``app.domains.organization.service
  .OrganizationService.list_children`` (via the narrow
  ``OrganizationLookupProtocol`` below).
* A location's owning organization (needed because a ``LOCATION``-scoped
  ``UserRole`` is not required to also carry ``organization_id`` -- see
  ``app.domains.rbac.service.RBACService._validate_scope_assignment``):
  ``app.domains.location.service.LocationService.get_location`` (via
  ``LocationLookupProtocol``).

No file inside ``rbac``/``organization``/``location`` is edited to make this
work -- every composition point above is that domain's own already-public
service method.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from app.domains.location.models import Location
from app.domains.organization.models import Organization
from app.domains.rbac.authorization import RoleResolver
from app.domains.rbac.enums import ScopeType

from .exceptions import DashboardScopeForbiddenError


class DashboardScopeLevel(StrEnum):
    """Which of BE-012 Part 2's four caller categories this resolves to --
    informational (surfaced on the response for transparency), not itself
    the enforcement mechanism (see :class:`DashboardScope`'s own
    ``allows_*``/``require_*`` methods for the real checks)."""

    GLOBAL = "global"
    ORGANIZATION = "organization"
    LOCATION = "location"
    NONE = "none"


class OrganizationLookupProtocol(Protocol):
    """The two ``OrganizationService`` methods this module composes with --
    reused directly, never reimplemented."""

    async def get_organization(
        self, organization_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Organization: ...

    async def list_children(self, organization_id: uuid.UUID) -> list[Organization]: ...


class LocationLookupProtocol(Protocol):
    """The single ``LocationService`` method this module needs -- reused
    directly, never reimplemented."""

    async def get_location(
        self,
        location_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Location: ...


@dataclass(frozen=True, slots=True)
class DashboardScope:
    """The resolved set of organizations/locations one caller may view
    dashboard data for. Mirrors ``app.domains.rbac.authorization
    .ScopeResolver.satisfies``'s own "broader covers narrower" hierarchy
    rule: a ``GLOBAL`` scope allows everything; an ``ORGANIZATION``-level
    scope (which already includes MSP-children expansion, see
    ``DashboardScopeResolver.resolve``) allows every location under any of
    its ``organization_ids``; a ``LOCATION``-level scope allows only the
    explicit ``location_ids`` it was resolved with (and never an
    organization-level view at all -- a location-scoped grant cannot
    satisfy a broader check, the identical asymmetry RBAC's own
    ``ScopeResolver`` already enforces)."""

    level: DashboardScopeLevel
    organization_ids: frozenset[uuid.UUID] = frozenset()
    location_ids: frozenset[uuid.UUID] = frozenset()

    def allows_organization(self, organization_id: uuid.UUID) -> bool:
        if self.level == DashboardScopeLevel.GLOBAL:
            return True
        return organization_id in self.organization_ids

    def allows_location(
        self, location_id: uuid.UUID, organization_id: uuid.UUID
    ) -> bool:
        if self.level == DashboardScopeLevel.GLOBAL:
            return True
        if location_id in self.location_ids:
            return True
        # An organization-level (or MSP-expanded) grant covers every
        # location under one of its organizations -- broader covers
        # narrower.
        return organization_id in self.organization_ids

    def require_global(self) -> None:
        if self.level != DashboardScopeLevel.GLOBAL:
            raise DashboardScopeForbiddenError(
                "Super Admin dashboard requires a platform-wide (global) "
                "role assignment"
            )

    def require_organization(self, organization_id: uuid.UUID) -> None:
        if not self.allows_organization(organization_id):
            raise DashboardScopeForbiddenError(
                f"You do not have dashboard visibility into organization "
                f"{organization_id}"
            )

    def require_location(
        self, location_id: uuid.UUID, organization_id: uuid.UUID
    ) -> None:
        if not self.allows_location(location_id, organization_id):
            raise DashboardScopeForbiddenError(
                f"You do not have dashboard visibility into location {location_id}"
            )


class DashboardScopeResolver:
    """Resolves one user's :class:`DashboardScope` from their real, active
    RBAC role assignments -- see module docstring."""

    def __init__(
        self,
        role_resolver: RoleResolver,
        organization_lookup: OrganizationLookupProtocol,
        location_lookup: LocationLookupProtocol,
    ) -> None:
        self.role_resolver = role_resolver
        self.organization_lookup = organization_lookup
        self.location_lookup = location_lookup

    async def resolve(self, user_id: uuid.UUID) -> DashboardScope:
        assignments = await self.role_resolver.get_active_assignments(user_id)

        if any(
            assignment.grant_scope.scope_type == ScopeType.GLOBAL
            for assignment in assignments
        ):
            return DashboardScope(level=DashboardScopeLevel.GLOBAL)

        organization_ids: set[uuid.UUID] = set()
        location_ids: set[uuid.UUID] = set()
        for assignment in assignments:
            scope = assignment.grant_scope
            if (
                scope.scope_type == ScopeType.ORGANIZATION
                and scope.organization_id is not None
            ):
                organization_ids.add(scope.organization_id)
            elif (
                scope.scope_type == ScopeType.LOCATION and scope.location_id is not None
            ):
                location_ids.add(scope.location_id)
            # ROUTER/DEVICE-scoped assignments grant no dashboard visibility
            # of their own in this part's scope (no router/device-level
            # dashboard exists yet).

        # MSP expansion: an ORGANIZATION-scoped grant on an MSP-type
        # organization also covers every one of its child organizations --
        # composes with OrganizationService.list_children, never
        # reimplemented.
        expanded_organization_ids = set(organization_ids)
        for organization_id in organization_ids:
            organization = await self.organization_lookup.get_organization(
                organization_id
            )
            if organization.is_msp():
                children = await self.organization_lookup.list_children(organization_id)
                expanded_organization_ids.update(child.id for child in children)

        if expanded_organization_ids:
            level = DashboardScopeLevel.ORGANIZATION
        elif location_ids:
            level = DashboardScopeLevel.LOCATION
        else:
            level = DashboardScopeLevel.NONE

        return DashboardScope(
            level=level,
            organization_ids=frozenset(expanded_organization_ids),
            location_ids=frozenset(location_ids),
        )

    async def resolve_location_organization_id(
        self, location_id: uuid.UUID
    ) -> uuid.UUID:
        """Looks up the real owning organization for ``location_id`` -- a
        ``LOCATION``-scoped ``UserRole`` is not required to also carry
        ``organization_id`` (see module docstring), so this cannot be read
        off the assignment row alone."""
        location = await self.location_lookup.get_location(location_id)
        return location.organization_id


__all__ = [
    "DashboardScopeLevel",
    "DashboardScope",
    "DashboardScopeResolver",
    "OrganizationLookupProtocol",
    "LocationLookupProtocol",
]
