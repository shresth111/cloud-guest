"""FastAPI dependencies for the DNS Management domain.

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

from .repository import DnsRepository, DnsRepositoryProtocol
from .service import DnsService


def get_dns_repository(
    db: AsyncSession = Depends(get_db_session),
) -> DnsRepositoryProtocol:
    return DnsRepository(db)


def get_dns_service(
    repository: DnsRepositoryProtocol = Depends(get_dns_repository),
    router_service: RouterService = Depends(get_router_service),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> DnsService:
    return DnsService(
        repository,
        router_service,
        audit_writer=audit_repository,
    )


__all__ = ["get_dns_repository", "get_dns_service"]
