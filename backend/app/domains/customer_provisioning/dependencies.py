from __future__ import annotations

from fastapi import Depends

from app.domains.location.dependencies import get_location_service
from app.domains.location.service import LocationService
from app.domains.organization.dependencies import get_organization_service
from app.domains.organization.service import OrganizationService
from app.domains.rbac.dependencies import get_rbac_service
from app.domains.rbac.service import RBACService

from .service import CustomerProvisioningService


def get_customer_provisioning_service(
    organization_service: OrganizationService = Depends(get_organization_service),
    location_service: LocationService = Depends(get_location_service),
    rbac_service: RBACService = Depends(get_rbac_service),
) -> CustomerProvisioningService:
    return CustomerProvisioningService(
        organization_service=organization_service,
        location_service=location_service,
        rbac_service=rbac_service,
    )
