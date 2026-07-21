"""FastAPI dependencies for the Firewall Rule Management domain.

Composes ``app.domains.router`` entirely through its own existing,
already-wired FastAPI dependency function (``get_router_service``) --
mirrors ``app.domains.dhcp.dependencies``'s identical shape.
"""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol
from app.domains.router.dependencies import get_router_service
from app.domains.router.service import RouterService

from .repository import FirewallRepository, FirewallRepositoryProtocol
from .service import FirewallService


def get_firewall_repository(
    db: AsyncSession = Depends(get_db_session),
) -> FirewallRepositoryProtocol:
    return FirewallRepository(db)


def get_firewall_service(
    repository: FirewallRepositoryProtocol = Depends(get_firewall_repository),
    router_service: RouterService = Depends(get_router_service),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> FirewallService:
    return FirewallService(
        repository,
        router_service,
        audit_writer=audit_repository,
    )


__all__ = ["get_firewall_repository", "get_firewall_service"]
