"""FastAPI dependencies for the Organization domain.

Authorization for organization endpoints is provided entirely by RBAC's
existing ``RequirePermission``/``RequireRole`` dependencies
(``app.domains.rbac.dependencies``) against the already-seeded
``organizations.*`` permission keys -- nothing here re-implements
authorization. This module only wires the repository/service layer.

See ``app.domains.rbac.dependencies.CurrentOrganization`` for the real
membership-validation check added alongside this module (documented there
and in ``docs/organization/ORGANIZATION_ARCHITECTURE.md``).
"""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol

from .repository import OrganizationRepository, OrganizationRepositoryProtocol
from .service import OrganizationService


def get_organization_repository(
    db: AsyncSession = Depends(get_db_session),
) -> OrganizationRepositoryProtocol:
    return OrganizationRepository(db)


def get_organization_service(
    repository: OrganizationRepositoryProtocol = Depends(get_organization_repository),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> OrganizationService:
    return OrganizationService(repository, audit_writer=audit_repository)
