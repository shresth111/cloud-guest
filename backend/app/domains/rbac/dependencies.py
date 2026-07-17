"""FastAPI dependencies for the RBAC domain.

Everything here builds on ``app.domains.auth.dependencies.get_current_user``
for identity -- nothing in this module re-derives or duplicates token/
session validation. RBAC only adds *authorization* on top of the identity
auth already establishes.

Design decision -- ``CurrentOrganization`` / ``CurrentLocation``: there is no
Organization/Location domain yet (see the module scope boundary), so
"what organization/location is this request acting within" cannot be
resolved by querying a membership table. Instead, the caller states it
explicitly via ``X-Organization-Id`` / ``X-Location-Id`` / ``X-Router-Id``
request headers (validated as UUIDs). This is a deliberate interim design:
once the Organization domain exists, these dependencies are the single
place to change to instead resolve/validate against real membership data.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable

from fastapi import Depends, Request
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.redis import get_redis_client
from app.database.session import get_db_session
from app.domains.auth.dependencies import get_current_user
from app.domains.auth.models import AuthUser

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


async def CurrentOrganization(request: Request) -> uuid.UUID | None:
    """The organization context for this request, if any (``X-Organization-Id``)."""
    return _parse_uuid_header(request, _ORG_HEADER)


async def CurrentLocation(request: Request) -> uuid.UUID | None:
    """The location context for this request, if any (``X-Location-Id``)."""
    return _parse_uuid_header(request, _LOCATION_HEADER)


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
