"""FastAPI dependencies for the Policy domain.

Wires the repository/service layer, composing with
``app.domains.organization``/``app.domains.location`` (tenant/hierarchy
validation, via the narrow ``OrganizationLookupProtocol``/
``LocationLookupProtocol`` shapes ``service.py`` defines) and RBAC (for audit
logging) -- the exact same dependency shape ``app.domains.guest_teams
.dependencies`` already establishes, and nothing else: ``policy`` composes no
other feature domain (see ``service.py``'s module docstring).
"""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.location.dependencies import get_location_service
from app.domains.location.service import LocationService
from app.domains.organization.dependencies import get_organization_service
from app.domains.organization.service import OrganizationService
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol

from .repository import PolicyRepository, PolicyRepositoryProtocol
from .service import PolicyService


def get_policy_repository(
    db: AsyncSession = Depends(get_db_session),
) -> PolicyRepositoryProtocol:
    return PolicyRepository(db)


def get_policy_service(
    repository: PolicyRepositoryProtocol = Depends(get_policy_repository),
    organization_service: OrganizationService = Depends(get_organization_service),
    location_service: LocationService = Depends(get_location_service),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> PolicyService:
    return PolicyService(
        repository,
        organization_service,
        location_service,
        audit_writer=audit_repository,
    )


__all__ = ["get_policy_repository", "get_policy_service"]
