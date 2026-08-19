"""FastAPI dependencies for the Captive Portal domain.

Wires the repository/service layer, composing with
``app.domains.organization``/``app.domains.location`` (for tenant/hierarchy
validation, via the narrow ``OrganizationLookupProtocol``/
``LocationLookupProtocol`` shapes ``service.py`` defines -- the real
``OrganizationService``/``LocationService`` already satisfy them
structurally, no adapter needed) and RBAC (for audit logging) rather than
duplicating either.
"""

from __future__ import annotations

from fastapi import Depends
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.redis import get_redis_client
from app.database.session import get_db_session
from app.domains.location.dependencies import get_location_service
from app.domains.location.service import LocationService
from app.domains.organization.dependencies import get_organization_service
from app.domains.organization.service import OrganizationService
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol

from .cache import CaptivePortalResolveCache
from .repository import CaptivePortalRepository, CaptivePortalRepositoryProtocol
from .service import CaptivePortalService


def get_captive_portal_repository(
    db: AsyncSession = Depends(get_db_session),
) -> CaptivePortalRepositoryProtocol:
    return CaptivePortalRepository(db)


def get_captive_portal_resolve_cache(
    redis: Redis = Depends(get_redis_client),
) -> CaptivePortalResolveCache:
    return CaptivePortalResolveCache(redis)


def get_captive_portal_service(
    repository: CaptivePortalRepositoryProtocol = Depends(
        get_captive_portal_repository
    ),
    organization_service: OrganizationService = Depends(get_organization_service),
    location_service: LocationService = Depends(get_location_service),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
    resolve_cache: CaptivePortalResolveCache = Depends(
        get_captive_portal_resolve_cache
    ),
) -> CaptivePortalService:
    return CaptivePortalService(
        repository,
        organization_service,
        location_service,
        audit_writer=audit_repository,
        resolve_cache=resolve_cache,
    )


__all__ = [
    "get_captive_portal_repository",
    "get_captive_portal_resolve_cache",
    "get_captive_portal_service",
]
