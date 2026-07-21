"""FastAPI dependencies for the QoS & VOIP Priority domain.

Composes ``app.domains.router`` entirely through its own existing,
already-wired FastAPI dependency function (``get_router_service``) --
exactly the same real service graph the live API already builds for that
domain, never a second, parallel construction path. Mirrors
``app.domains.hotspot.dependencies``'s identical shape.
"""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol
from app.domains.router.dependencies import get_router_service
from app.domains.router.service import RouterService

from .repository import QosRepository, QosRepositoryProtocol
from .service import QosService


def get_qos_repository(
    db: AsyncSession = Depends(get_db_session),
) -> QosRepositoryProtocol:
    return QosRepository(db)


def get_qos_service(
    repository: QosRepositoryProtocol = Depends(get_qos_repository),
    router_service: RouterService = Depends(get_router_service),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> QosService:
    return QosService(
        repository,
        router_service,
        audit_writer=audit_repository,
    )


__all__ = ["get_qos_repository", "get_qos_service"]
