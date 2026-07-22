from __future__ import annotations

from fastapi import Depends

from app.domains.organization.dependencies import get_organization_service
from app.domains.organization.service import OrganizationService
from app.domains.location.dependencies import get_location_service
from app.domains.location.service import LocationService
from app.domains.router.dependencies import get_router_service
from app.domains.router.service import RouterService
from app.domains.router_provisioning.dependencies import get_router_provisioning_service
from app.domains.router_provisioning.service import RouterProvisioningService
from app.domains.wireguard.dependencies import get_wireguard_service
from app.domains.wireguard.service import WireGuardService
from app.domains.rbac.dependencies import get_rbac_service
from app.domains.rbac.service import RBACService

from .service import CustomerProvisioningService


def get_customer_provisioning_service(
    organization_service: OrganizationService = Depends(get_organization_service),
    location_service: LocationService = Depends(get_location_service),
    router_service: RouterService = Depends(get_router_service),
    provisioning_service: RouterProvisioningService = Depends(get_router_provisioning_service),
    wireguard_service: WireGuardService = Depends(get_wireguard_service),
    rbac_service: RBACService = Depends(get_rbac_service),
) -> CustomerProvisioningService:
    return CustomerProvisioningService(
        organization_service=organization_service,
        location_service=location_service,
        router_service=router_service,
        provisioning_service=provisioning_service,
        wireguard_service=wireguard_service,
        rbac_service=rbac_service,
    )
