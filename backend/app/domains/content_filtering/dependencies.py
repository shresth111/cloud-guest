"""FastAPI dependencies for the Content Filtering domain.

Composes ``app.domains.router`` entirely through its own existing,
already-wired FastAPI dependency function (``get_router_service``) --
mirrors ``app.domains.firewall.dependencies``'s identical shape.
"""

from __future__ import annotations

from fastapi import Depends
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.redis import get_redis_client
from app.database.session import get_db_session
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.location_scope import (
    CallerLocationScope,
    LocationScope,
)
from app.domains.rbac.repository import RBACRepositoryProtocol
from app.domains.router.dependencies import get_router_service
from app.domains.router.service import RouterService

from .repository import ContentFilterRepository, ContentFilterRepositoryProtocol
from .service import ContentFilterService


def get_content_filter_repository(
    db: AsyncSession = Depends(get_db_session),
) -> ContentFilterRepositoryProtocol:
    return ContentFilterRepository(db)


def get_content_filter_service(
    repository: ContentFilterRepositoryProtocol = Depends(
        get_content_filter_repository
    ),
    router_service: RouterService = Depends(get_router_service),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
    caller_location_scope: LocationScope = Depends(CallerLocationScope),
    # The per-router forward-chain lock shared with the firewall push -- see
    # app.common.router_firewall_lock.
    redis: Redis = Depends(get_redis_client),
) -> ContentFilterService:
    return ContentFilterService(
        repository,
        router_service,
        audit_writer=audit_repository,
        caller_location_scope=caller_location_scope,
        redis=redis,
    )


__all__ = ["get_content_filter_repository", "get_content_filter_service"]
