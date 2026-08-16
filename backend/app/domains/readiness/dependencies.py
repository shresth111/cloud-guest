"""FastAPI dependencies for the Router Readiness Checklist domain.

Composes every cross-domain read through that sibling domain's own
existing, already-wired FastAPI dependency function
(``get_router_service``/``get_isp_service``/``get_wireguard_service``/
``get_router_agent_service``) -- never a second, parallel construction
path, mirroring ``app.domains.content_filtering.dependencies``'s identical
shape.
"""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.isp.dependencies import get_isp_service
from app.domains.isp.service import IspService
from app.domains.router.dependencies import get_router_service
from app.domains.router.service import RouterService
from app.domains.router_agent.dependencies import get_router_agent_service
from app.domains.router_agent.service import RouterAgentService
from app.domains.wireguard.dependencies import get_wireguard_service
from app.domains.wireguard.service import WireGuardService

from .repository import ReadinessRepository, ReadinessRepositoryProtocol
from .service import ReadinessService


def get_readiness_repository(
    db: AsyncSession = Depends(get_db_session),
) -> ReadinessRepositoryProtocol:
    return ReadinessRepository(db)


def get_readiness_service(
    repository: ReadinessRepositoryProtocol = Depends(get_readiness_repository),
    router_service: RouterService = Depends(get_router_service),
    isp_service: IspService = Depends(get_isp_service),
    wireguard_service: WireGuardService = Depends(get_wireguard_service),
    router_agent_service: RouterAgentService = Depends(get_router_agent_service),
) -> ReadinessService:
    return ReadinessService(
        repository,
        router_service,
        isp_service,
        wireguard_service,
        router_agent_service,
    )


__all__ = ["get_readiness_repository", "get_readiness_service"]
