"""FastAPI dependencies for the ISP Management domain.

Composes ``app.domains.router`` entirely through its own existing,
already-wired FastAPI dependency function (``get_router_service``) --
exactly the same real service graph the live API already builds for that
domain, never a second, parallel construction path. Mirrors
``app.domains.queue_management.dependencies``'s identical shape.

The per-router vendor adapter is *not* injected here -- ``IspService``
resolves it dynamically from each router's own ``vendor`` field (see
``service.py``'s own module docstring), so no adapter dependency exists in
this module at all.
"""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol
from app.domains.router.dependencies import get_router_service
from app.domains.router.service import RouterService

from .repository import IspRepository, IspRepositoryProtocol
from .service import IspService


def get_isp_repository(
    db: AsyncSession = Depends(get_db_session),
) -> IspRepositoryProtocol:
    return IspRepository(db)


def get_isp_service(
    repository: IspRepositoryProtocol = Depends(get_isp_repository),
    router_service: RouterService = Depends(get_router_service),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> IspService:
    return IspService(
        repository,
        router_service,
        audit_writer=audit_repository,
    )


__all__ = [
    "get_isp_repository",
    "get_isp_service",
]
