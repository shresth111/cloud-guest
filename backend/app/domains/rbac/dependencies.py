"""FastAPI dependencies for the RBAC domain.

Everything here builds on ``app.domains.auth.dependencies.get_current_user``
for identity -- nothing in this module re-derives or duplicates token/
session validation. RBAC only adds *authorization* on top of the identity
auth already establishes.

Design decision -- ``CurrentOrganization`` / ``CurrentLocation``: there is no
Router domain yet (see the module scope boundary), so "what router is this
request acting within" still cannot be resolved by querying real data -- the
caller states it via the ``X-Router-Id`` request header (validated as a
UUID), same as before.

**Module 005 update:** the Organization domain now exists, so
``CurrentOrganization`` no longer trusts ``X-Organization-Id`` at face
value. When the header is present, it now validates (a) the organization
exists (``OrganizationNotFoundError``) and (b) the current user holds an
*active* ``OrganizationMember`` row for it (``OrganizationMembershipRequiredError``)
-- both reused from ``app.domains.organization.exceptions`` /
``app.domains.organization.models`` rather than reinvented here, keeping a
single source of truth for "what does organization membership mean". This
is a deliberately minimal, targeted change: it only touches
``CurrentOrganization`` (the exact seam this module's own docs called out
as "the single place to change"). A request with no ``X-Organization-Id``
header still resolves to ``None`` with no DB lookup at all, so
platform-level (``GLOBAL``-scoped) callers acting without an organization
context -- e.g. creating the very first organization -- are unaffected.

**Module 006 update:** the Location domain now exists, so ``CurrentLocation``
no longer trusts ``X-Location-Id`` at face value either. When the header is
present, it now validates (a) the location exists and is not archived
(``LocationNotFoundError`` -- a soft-deleted/archived location reads as "not
found", the same convention ``CurrentOrganization`` already uses for
archived organizations) and (b) -- when an organization context was already
resolved via ``CurrentOrganization`` -- that the location's
``organization_id`` matches it (``LocationOrganizationMismatchError``
otherwise, a real cross-tenant boundary check: a location belonging to a
different organization than the one named by ``X-Organization-Id`` must be
rejected, not silently trusted). Both reused from
``app.domains.location.exceptions``/``app.domains.location.models`` rather
than reinvented here. A request with no ``X-Location-Id`` header still
resolves to ``None`` with no DB lookup at all. When ``X-Location-Id`` is
present but ``X-Organization-Id`` is not, the mismatch check is skipped
(there is nothing to compare against) -- the location's own existence check
still applies. ``CurrentRouter`` is unchanged, for the reason above (no
Router domain yet).
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable

from fastapi import Depends, Request
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.redis import get_redis_client
from app.database.repositories.generic import GenericRepository
from app.database.session import get_db_session
from app.domains.auth.dependencies import get_current_user
from app.domains.auth.models import AuthUser
from app.domains.location.exceptions import (
    LocationNotFoundError,
    LocationOrganizationMismatchError,
)
from app.domains.location.models import Location
from app.domains.organization.enums import MembershipStatus
from app.domains.organization.exceptions import (
    OrganizationMembershipRequiredError,
    OrganizationNotFoundError,
)
from app.domains.organization.models import Organization, OrganizationMember

from .authorization import AccessValidator, RoleResolver
from .cache import PermissionCache
from .context import ScopeContext
from .enums import ScopeType
from .exceptions import (
    InvalidScopeHeaderError,
    MissingScopeContextError,
    RoleNotHeldError,
)
from .repository import RBACRepository, RBACRepositoryProtocol
from .service import RBACService

# Re-exported as-is: RBAC's notion of "current user" is auth's, unchanged.
CurrentUser = get_current_user


# ============================================================================
# Service / repository / cache wiring
# ============================================================================


def get_rbac_repository(
    db: AsyncSession = Depends(get_db_session),
) -> RBACRepositoryProtocol:
    return RBACRepository(db)


def get_permission_cache(redis: Redis = Depends(get_redis_client)) -> PermissionCache:
    return PermissionCache(redis)


def get_access_validator(
    repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
    cache: PermissionCache = Depends(get_permission_cache),
) -> AccessValidator:
    return AccessValidator(repository, cache=cache)


def get_rbac_service(
    repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
    cache: PermissionCache = Depends(get_permission_cache),
) -> RBACService:
    return RBACService(repository, cache)


# ============================================================================
# Scope context headers
# ============================================================================

_ORG_HEADER = "X-Organization-Id"
_LOCATION_HEADER = "X-Location-Id"
_ROUTER_HEADER = "X-Router-Id"


def _parse_uuid_header(request: Request, header_name: str) -> uuid.UUID | None:
    raw = request.headers.get(header_name)
    if not raw:
        return None
    try:
        return uuid.UUID(raw)
    except ValueError as exc:
        raise InvalidScopeHeaderError(header_name) from exc


async def CurrentOrganization(
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    db: AsyncSession = Depends(get_db_session),
) -> uuid.UUID | None:
    """The organization context for this request, if any (``X-Organization-Id``).

    When the header is present, validates the organization exists and that
    the current user is an *active* member of it (see module docstring for
    why this is no longer a trust-the-header parse). Returns ``None`` (no
    DB lookup performed) when the header is absent."""
    organization_id = _parse_uuid_header(request, _ORG_HEADER)
    if organization_id is None:
        return None

    organization_repo = GenericRepository(Organization, db)
    organization = await organization_repo.get_by_id(organization_id)
    if organization is None:
        raise OrganizationNotFoundError(organization_id)

    member_repo = GenericRepository(OrganizationMember, db)
    active_memberships = await member_repo.get_all(
        filters={
            "organization_id": organization_id,
            "user_id": uuid.UUID(user.id),
            "status": MembershipStatus.ACTIVE.value,
        },
        limit=1,
    )
    if not active_memberships:
        raise OrganizationMembershipRequiredError(organization_id)

    return organization_id


async def CurrentLocation(
    request: Request,
    organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    db: AsyncSession = Depends(get_db_session),
) -> uuid.UUID | None:
    """The location context for this request, if any (``X-Location-Id``).

    When the header is present, validates the location exists and is not
    archived, and -- if an organization context was already resolved via
    ``CurrentOrganization`` -- that the location belongs to it (see module
    docstring for why this is no longer a trust-the-header parse). Returns
    ``None`` (no DB lookup performed) when the header is absent."""
    location_id = _parse_uuid_header(request, _LOCATION_HEADER)
    if location_id is None:
        return None

    location_repo = GenericRepository(Location, db)
    location = await location_repo.get_by_id(location_id)
    if location is None:
        raise LocationNotFoundError(location_id)

    if organization_id is not None and location.organization_id != organization_id:
        raise LocationOrganizationMismatchError(location_id, organization_id)

    return location_id


async def CurrentRouter(request: Request) -> uuid.UUID | None:
    """The router context for this request, if any (``X-Router-Id``)."""
    return _parse_uuid_header(request, _ROUTER_HEADER)


async def _current_scope_context(request: Request) -> ScopeContext:
    return ScopeContext(
        organization_id=_parse_uuid_header(request, _ORG_HEADER),
        location_id=_parse_uuid_header(request, _LOCATION_HEADER),
        router_id=_parse_uuid_header(request, _ROUTER_HEADER),
    )


async def RequireOrganization(
    organization_id: uuid.UUID | None = Depends(CurrentOrganization),
) -> uuid.UUID:
    """400s if no valid organization context (``X-Organization-Id``) is present."""
    if organization_id is None:
        raise MissingScopeContextError("organization")
    return organization_id


async def RequireLocation(
    location_id: uuid.UUID | None = Depends(CurrentLocation),
) -> uuid.UUID:
    """400s if no valid location context (``X-Location-Id``) is present."""
    if location_id is None:
        raise MissingScopeContextError("location")
    return location_id


def RequireScope(
    scope_type: ScopeType,
) -> Callable[[Request], Awaitable[ScopeContext]]:
    """Dependency factory: 400s unless the identifier ``scope_type`` needs is
    present."""

    async def _dependency(request: Request) -> ScopeContext:
        context = await _current_scope_context(request)
        if scope_type == ScopeType.ORGANIZATION and context.organization_id is None:
            raise MissingScopeContextError("organization")
        if scope_type == ScopeType.LOCATION and context.location_id is None:
            raise MissingScopeContextError("location")
        if scope_type == ScopeType.ROUTER and context.router_id is None:
            raise MissingScopeContextError("router")
        return context

    return _dependency


# ============================================================================
# Authorization dependencies
# ============================================================================


def RequirePermission(
    permission_key: str, *, scope: ScopeType | None = None
) -> Callable[..., Awaitable[AuthUser]]:
    """Dependency factory: 403s unless the current user holds ``permission_key``
    at the resolved scope (``scope``, defaulting to ``GLOBAL`` when no scope
    context is supplied)."""

    async def _dependency(
        request: Request,
        user: AuthUser = Depends(CurrentUser),
        access_validator: AccessValidator = Depends(get_access_validator),
    ) -> AuthUser:
        context = await _current_scope_context(request)
        resolved_scope = scope or _infer_scope_type(context)
        await access_validator.check(
            uuid.UUID(user.id),
            permission_key,
            scope_type=resolved_scope,
            scope_context=context,
        )
        return user

    return _dependency


def RequireRole(
    role_slug_or_id: str, *, scope: ScopeType | None = None
) -> Callable[..., Awaitable[AuthUser]]:
    """Dependency factory: 403s unless the current user holds an active
    assignment of the role identified by slug or id (optionally narrowed to
    a scope context)."""

    async def _dependency(
        request: Request,
        user: AuthUser = Depends(CurrentUser),
        repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
    ) -> AuthUser:
        context = await _current_scope_context(request) if scope else None
        resolver = RoleResolver(repository)
        roles = await resolver.get_active_roles(
            uuid.UUID(user.id), scope_context=context
        )
        holds_role = any(
            role.slug == role_slug_or_id or str(role.id) == role_slug_or_id
            for role in roles
        )
        if not holds_role:
            raise RoleNotHeldError(role_slug_or_id)
        return user

    return _dependency


def _infer_scope_type(context: ScopeContext) -> ScopeType:
    """When ``RequirePermission`` isn't given an explicit ``scope=``, infer the
    narrowest scope implied by whichever scope headers were supplied."""
    if context.router_id is not None:
        return ScopeType.ROUTER
    if context.location_id is not None:
        return ScopeType.LOCATION
    if context.organization_id is not None:
        return ScopeType.ORGANIZATION
    return ScopeType.GLOBAL
