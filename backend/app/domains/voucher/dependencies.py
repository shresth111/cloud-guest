"""FastAPI dependencies for the Voucher domain.

Wires the repository/service layer, composing with
``app.domains.organization``/``app.domains.location`` (for tenant/hierarchy
validation, via the narrow ``OrganizationLookupProtocol``/
``LocationLookupProtocol`` shapes ``service.py`` defines -- the real
``OrganizationService``/``LocationService`` already satisfy them
structurally, no adapter needed) and RBAC (for audit logging + the
guest-facing rate limiter's Redis client) rather than duplicating any of
them.

``get_voucher_manage_bypass`` is this module's one FastAPI-dependency-level
addition beyond the OTP-mirrored wiring below: a non-raising check for
whether the current caller holds ``voucher.manage`` (used by
``router.py``'s ``POST /voucher-batches`` handler to decide whether to skip
the approval queue -- see ``service.py``'s module docstring for the full
"fast path" reasoning). It reuses RBAC's own ``AccessValidator
.has_permission`` (a boolean check, distinct from the raising
``RequirePermission`` dependency factory every route's mandatory gate
uses) -- composition with RBAC's public API, not a reimplementation of any
part of it.
"""

from __future__ import annotations

import uuid

from fastapi import Depends, Request
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.redis import get_redis_client
from app.database.session import get_db_session
from app.domains.auth.models import AuthUser
from app.domains.location.dependencies import get_location_service
from app.domains.location.service import LocationService
from app.domains.organization.dependencies import get_organization_service
from app.domains.organization.service import OrganizationService
from app.domains.rbac.authorization import AccessValidator
from app.domains.rbac.context import ScopeContext
from app.domains.rbac.dependencies import (
    CurrentLocation,
    CurrentOrganization,
    CurrentUser,
    get_access_validator,
    get_rbac_repository,
)
from app.domains.rbac.enums import ScopeType
from app.domains.rbac.repository import RBACRepositoryProtocol

from .repository import VoucherRepository, VoucherRepositoryProtocol
from .service import VoucherService


def get_voucher_repository(
    db: AsyncSession = Depends(get_db_session),
) -> VoucherRepositoryProtocol:
    return VoucherRepository(db)


def get_voucher_service(
    repository: VoucherRepositoryProtocol = Depends(get_voucher_repository),
    redis: Redis = Depends(get_redis_client),
    organization_service: OrganizationService = Depends(get_organization_service),
    location_service: LocationService = Depends(get_location_service),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> VoucherService:
    return VoucherService(
        repository,
        redis,
        organization_service,
        location_service,
        audit_writer=audit_repository,
    )


def _infer_scope_type(
    organization_id: uuid.UUID | None, location_id: uuid.UUID | None
) -> ScopeType:
    if location_id is not None:
        return ScopeType.LOCATION
    if organization_id is not None:
        return ScopeType.ORGANIZATION
    return ScopeType.GLOBAL


async def get_voucher_manage_bypass(
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    location_id: uuid.UUID | None = Depends(CurrentLocation),
    access_validator: AccessValidator = Depends(get_access_validator),
) -> bool:
    """Whether the current caller holds ``voucher.manage`` at the scope
    implied by whichever ``X-Organization-Id``/``X-Location-Id`` headers
    were supplied -- see module docstring."""
    context = ScopeContext(organization_id=organization_id, location_id=location_id)
    scope_type = _infer_scope_type(organization_id, location_id)
    return await access_validator.has_permission(
        uuid.UUID(user.id),
        "voucher.manage",
        scope_type=scope_type,
        scope_context=context,
    )


def get_redemption_source(request: Request) -> str:
    """The presumed caller IP address for guest-facing redemption rate
    limiting -- see ``service.py``'s module docstring for why this, not the
    presented code, is the rate-limit key. Falls back to a fixed string
    (never ``None``) so a test client/proxy with no visible client host
    still gets a single, consistent bucket rather than bypassing the limiter
    entirely."""
    if request.client is not None and request.client.host:
        return request.client.host
    return "unknown"


__all__ = [
    "get_voucher_repository",
    "get_voucher_service",
    "get_voucher_manage_bypass",
    "get_redemption_source",
]
