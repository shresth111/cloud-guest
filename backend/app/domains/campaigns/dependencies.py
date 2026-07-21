"""FastAPI dependencies for the Campaigns domain.

Composes ``app.domains.organization``/``app.domains.location``/
``app.domains.router``/``app.domains.guest`` entirely through their own
existing, already-wired FastAPI dependency functions -- exactly the same
real service graph the live API already builds for those domains, never
a second, parallel construction path. Mirrors ``app.domains.qos
.dependencies``'s identical shape.
"""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.guest.dependencies import get_guest_repository
from app.domains.guest.repository import GuestRepositoryProtocol
from app.domains.location.dependencies import get_location_service
from app.domains.location.service import LocationService
from app.domains.organization.dependencies import get_organization_service
from app.domains.organization.service import OrganizationService
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol
from app.domains.router.dependencies import get_router_service
from app.domains.router.service import RouterService

from .repository import CampaignsRepository, CampaignsRepositoryProtocol
from .service import CampaignsService


def get_campaigns_repository(
    db: AsyncSession = Depends(get_db_session),
) -> CampaignsRepositoryProtocol:
    return CampaignsRepository(db)


def get_campaigns_service(
    repository: CampaignsRepositoryProtocol = Depends(get_campaigns_repository),
    organization_service: OrganizationService = Depends(get_organization_service),
    location_service: LocationService = Depends(get_location_service),
    router_service: RouterService = Depends(get_router_service),
    guest_repository: GuestRepositoryProtocol = Depends(get_guest_repository),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> CampaignsService:
    return CampaignsService(
        repository,
        organization_service,
        location_service,
        router_service,
        guest_repository,
        audit_writer=audit_repository,
    )


__all__ = ["get_campaigns_repository", "get_campaigns_service"]
