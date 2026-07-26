"""FastAPI dependencies for the Admin Logs domain.

Composes ``app.domains.organization``/``app.domains.auth``/
``app.domains.location``/``app.domains.router``/
``app.domains.router_provisioning`` entirely through their own existing,
already-wired FastAPI dependency functions -- exactly the same real
service graph the live API already builds for each of those domains,
never a second, parallel construction path (the identical posture
``app.domains.controller_logs.dependencies`` already establishes for its
own composition)."""

from __future__ import annotations

from fastapi import Depends

from app.domains.auth.dependencies import get_auth_service
from app.domains.auth.service import AuthService
from app.domains.location.dependencies import get_location_service
from app.domains.location.service import LocationService
from app.domains.organization.dependencies import get_organization_service
from app.domains.organization.service import OrganizationService
from app.domains.router.dependencies import get_router_service
from app.domains.router.service import RouterService
from app.domains.router_provisioning.dependencies import get_router_provisioning_service
from app.domains.router_provisioning.service import RouterProvisioningService

from .service import AdminLogsService


def get_admin_logs_service(
    organization_service: OrganizationService = Depends(get_organization_service),
    auth_service: AuthService = Depends(get_auth_service),
    location_service: LocationService = Depends(get_location_service),
    router_service: RouterService = Depends(get_router_service),
    router_provisioning_service: RouterProvisioningService = Depends(
        get_router_provisioning_service
    ),
) -> AdminLogsService:
    return AdminLogsService(
        organization_service,
        auth_service,
        location_service,
        router_service,
        router_provisioning_service,
    )


__all__ = ["get_admin_logs_service"]
