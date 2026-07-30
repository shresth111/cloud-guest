"""FastAPI dependencies for the MAC Authorization domain.

Composes ``app.domains.router``'s own already-wired ``RouterService`` --
this domain's rows are org/location-scoped, not router-scoped (see
``models.py``), so resolving "which entries apply to this router" needs
a real router lookup (``MacAuthorizationService
.list_active_entries_for_router``, the real device-config-generation
seam this domain previously had no way to reach)."""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol
from app.domains.router.dependencies import get_router_service
from app.domains.router.service import RouterService

from .repository import MacAuthorizationRepository, MacAuthorizationRepositoryProtocol
from .service import MacAuthorizationService


def get_mac_authorization_repository(
    db: AsyncSession = Depends(get_db_session),
) -> MacAuthorizationRepositoryProtocol:
    return MacAuthorizationRepository(db)


def get_mac_authorization_service(
    repository: MacAuthorizationRepositoryProtocol = Depends(
        get_mac_authorization_repository
    ),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
    router_service: RouterService = Depends(get_router_service),
) -> MacAuthorizationService:
    return MacAuthorizationService(
        repository, audit_writer=audit_repository, router_lookup=router_service
    )


__all__ = ["get_mac_authorization_repository", "get_mac_authorization_service"]
