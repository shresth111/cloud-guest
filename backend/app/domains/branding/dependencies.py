"""FastAPI dependencies for the Branding domain."""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol

from .repository import BrandingRepository, BrandingRepositoryProtocol
from .service import BrandingService


def get_branding_repository(
    db: AsyncSession = Depends(get_db_session),
) -> BrandingRepositoryProtocol:
    return BrandingRepository(db)


def get_branding_service(
    repository: BrandingRepositoryProtocol = Depends(get_branding_repository),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> BrandingService:
    return BrandingService(repository, audit_writer=audit_repository)
