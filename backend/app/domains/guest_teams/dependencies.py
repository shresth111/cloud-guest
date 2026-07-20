"""FastAPI dependencies for the Guest Teams domain.

Wires the repository/service layer, composing with
``app.domains.organization``/``app.domains.location`` (for tenant/hierarchy
validation, via the narrow ``OrganizationLookupProtocol``/
``LocationLookupProtocol`` shapes ``service.py`` defines -- the real
``OrganizationService``/``LocationService`` already satisfy them
structurally, no adapter needed), ``app.domains.guest`` (the real
``GuestService``, composed directly -- see ``service.py``'s module
docstring for why this one composition depends on the concrete class rather
than a narrow Protocol), and RBAC (for audit logging) rather than
duplicating any of them.
"""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.guest.dependencies import get_guest_service
from app.domains.guest.service import GuestService
from app.domains.location.dependencies import get_location_service
from app.domains.location.service import LocationService
from app.domains.organization.dependencies import get_organization_service
from app.domains.organization.service import OrganizationService
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol

from .repository import GuestTeamRepository, GuestTeamRepositoryProtocol
from .service import GuestTeamService


def get_guest_team_repository(
    db: AsyncSession = Depends(get_db_session),
) -> GuestTeamRepositoryProtocol:
    return GuestTeamRepository(db)


def get_guest_team_service(
    repository: GuestTeamRepositoryProtocol = Depends(get_guest_team_repository),
    organization_service: OrganizationService = Depends(get_organization_service),
    location_service: LocationService = Depends(get_location_service),
    guest_service: GuestService = Depends(get_guest_service),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> GuestTeamService:
    return GuestTeamService(
        repository,
        organization_service,
        location_service,
        guest_service,
        audit_writer=audit_repository,
    )


__all__ = ["get_guest_team_repository", "get_guest_team_service"]
