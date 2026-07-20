"""FastAPI dependencies for the Guest Access Control domain.

Wires the repository/service layer, composing with RBAC (for audit
logging) rather than duplicating it. Deliberately does **not** compose with
``app.domains.guest`` -- this module has no dependency on it at all (see
``service.py``'s module docstring for why); the dependency runs the other
direction, via ``app.domains.guest.dependencies.get_guest_service``
optionally wiring this module's ``GuestAccessService.check_access`` in as
``GuestService``'s own optional hook.
"""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol

from .repository import GuestAccessRepository, GuestAccessRepositoryProtocol
from .service import GuestAccessService


def get_guest_access_repository(
    db: AsyncSession = Depends(get_db_session),
) -> GuestAccessRepositoryProtocol:
    return GuestAccessRepository(db)


def get_guest_access_service(
    repository: GuestAccessRepositoryProtocol = Depends(get_guest_access_repository),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> GuestAccessService:
    return GuestAccessService(repository, audit_writer=audit_repository)


__all__ = ["get_guest_access_repository", "get_guest_access_service"]
