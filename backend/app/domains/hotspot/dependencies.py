"""FastAPI dependencies for the Hotspot Settings domain.

Composes ``app.domains.router`` entirely through its own existing,
already-wired FastAPI dependency function (``get_router_service``) --
exactly the same real service graph the live API already builds for that
domain, never a second, parallel construction path. Mirrors
``app.domains.dhcp.dependencies``'s identical shape.
"""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol
from app.domains.router.dependencies import get_router_service
from app.domains.router.service import RouterService

from .repository import HotspotRepository, HotspotRepositoryProtocol
from .service import HotspotService


def get_hotspot_repository(
    db: AsyncSession = Depends(get_db_session),
) -> HotspotRepositoryProtocol:
    return HotspotRepository(db)


def get_hotspot_service(
    repository: HotspotRepositoryProtocol = Depends(get_hotspot_repository),
    router_service: RouterService = Depends(get_router_service),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> HotspotService:
    return HotspotService(
        repository,
        router_service,
        audit_writer=audit_repository,
    )


__all__ = ["get_hotspot_repository", "get_hotspot_service"]
