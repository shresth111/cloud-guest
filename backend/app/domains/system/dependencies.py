from __future__ import annotations

from fastapi import Depends

from app.domains.organization.dependencies import get_organization_service
from app.domains.organization.service import OrganizationService
from app.domains.location.dependencies import get_location_service
from app.domains.location.service import LocationService
from app.domains.router.dependencies import get_router_service
from app.domains.router.service import RouterService

from .service import SystemService


def get_system_service(
    organization_service: OrganizationService = Depends(get_organization_service),
    location_service: LocationService = Depends(get_location_service),
    router_service: RouterService = Depends(get_router_service),
) -> SystemService:
    return SystemService(
        organization_service=organization_service,
        location_service=location_service,
        router_service=router_service,
    )
