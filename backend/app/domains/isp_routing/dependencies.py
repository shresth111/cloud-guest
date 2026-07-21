"""FastAPI dependencies for the ISP Routing domain.

Composes ``app.domains.router``/``app.domains.isp`` entirely through their
own existing, already-wired FastAPI dependency functions
(``get_router_service``/``get_isp_service``) -- exactly the same real
service graph the live API already builds for each of those domains, never
a second, parallel construction path. Mirrors
``app.domains.queue_management.dependencies``'s identical shape.
"""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.isp.dependencies import get_isp_service
from app.domains.isp.service import IspService
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol
from app.domains.router.dependencies import get_router_service
from app.domains.router.service import RouterService

from .repository import IspRoutingRepository, IspRoutingRepositoryProtocol
from .service import IspRoutingService


def get_isp_routing_repository(
    db: AsyncSession = Depends(get_db_session),
) -> IspRoutingRepositoryProtocol:
    return IspRoutingRepository(db)


def get_isp_routing_service(
    repository: IspRoutingRepositoryProtocol = Depends(get_isp_routing_repository),
    router_service: RouterService = Depends(get_router_service),
    isp_service: IspService = Depends(get_isp_service),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> IspRoutingService:
    return IspRoutingService(
        repository,
        router_service,
        isp_service,
        audit_writer=audit_repository,
    )


__all__ = [
    "get_isp_routing_repository",
    "get_isp_routing_service",
]
