"""FastAPI dependencies for the MAC Authorization domain.

No cross-domain composition needed at the dependency layer -- this
domain has no router/device concept to resolve (see ``service.py``'s own
module docstring).
"""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol

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
) -> MacAuthorizationService:
    return MacAuthorizationService(repository, audit_writer=audit_repository)


__all__ = ["get_mac_authorization_repository", "get_mac_authorization_service"]
