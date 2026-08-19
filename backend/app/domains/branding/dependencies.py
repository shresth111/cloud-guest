"""FastAPI dependencies for the Branding domain."""

from __future__ import annotations

from fastapi import Depends
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.storage import ObjectStorageProtocol, get_object_storage
from app.database.redis import get_redis_client
from app.database.session import get_db_session
from app.domains.captive_portal.cache import CaptivePortalResolveCache
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol

from .repository import BrandingRepository, BrandingRepositoryProtocol
from .service import BrandingService


def get_branding_repository(
    db: AsyncSession = Depends(get_db_session),
) -> BrandingRepositoryProtocol:
    return BrandingRepository(db)


def get_portal_resolve_cache(
    redis: Redis = Depends(get_redis_client),
) -> CaptivePortalResolveCache:
    """The captive-portal domain's own resolve cache, reused here rather
    than re-constructed -- design spec §5 S7 folds this organization's
    branding row into that cache, so this domain's writes are now what
    must invalidate it. Mirrors
    ``app.domains.captive_portal.dependencies.get_captive_portal_resolve_cache``
    exactly; the class reads its own TTL from Settings, so there is no
    second knob to keep in sync."""
    return CaptivePortalResolveCache(redis)


def get_branding_service(
    repository: BrandingRepositoryProtocol = Depends(get_branding_repository),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
    object_storage: ObjectStorageProtocol = Depends(get_object_storage),
    portal_resolve_cache: CaptivePortalResolveCache = Depends(
        get_portal_resolve_cache
    ),
) -> BrandingService:
    return BrandingService(
        repository,
        audit_writer=audit_repository,
        object_storage=object_storage,
        portal_resolve_cache=portal_resolve_cache,
    )
