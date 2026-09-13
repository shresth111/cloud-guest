"""Customer-facing (organization-scoped) reads for a venue's Omada controller.

Everything on ``router.py``'s ``router`` is ``ScopeType.GLOBAL`` -- the Master
console's operator surface, by deliberate design, so a venue owner is refused
there (see that module's docstring and
``test_every_route_on_router_requires_global_scope``). But a customer has one
legitimate, read-only need on their own controller: seeing the devices it
manages -- the controller and the APs adopted under it. That cannot ride the
GLOBAL routes, so it lives here, on its own router, gated at
``ScopeType.ORGANIZATION`` and resolved WITH the caller's organization and
location in the query (``get_omada_openapi_integration_for_location``), so a
location that is not theirs is indistinguishable from one with no controller.

Read-only, always: this router exposes no write, and never will. Writing
network config to a customer's live controller can drop guest internet, and
the whole Omada surface is deliberately observe-not-operate for a customer.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request

from app.common.responses import ApiResponse, build_response
from app.domains.rbac.dependencies import CurrentOrganization, RequirePermission
from app.domains.rbac.enums import ScopeType

from .dependencies import get_network_integration_service
from .schemas import ControllerDeviceView, ControllerInventoryResponse
from .service import NetworkIntegrationService

customer_router = APIRouter(
    prefix="/network-integrations", tags=["Network Integrations (customer)"]
)


@customer_router.get(
    "/locations/{location_id}/controller-devices",
    response_model=ApiResponse[ControllerInventoryResponse],
    dependencies=[
        Depends(RequirePermission("locations.read", scope=ScopeType.ORGANIZATION))
    ],
)
async def list_location_controller_devices(
    location_id: uuid.UUID,
    request: Request,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NetworkIntegrationService = Depends(get_network_integration_service),
) -> ApiResponse[ControllerInventoryResponse]:
    """The devices this location's Omada controller manages (read-only).

    Gated on ``locations.read`` at organization scope -- the same permission a
    venue owner already holds to read the location itself -- because the
    resource is scoped by ``location_id`` and belongs to the location, not to
    the Master-console ``network_integrations.*`` family.
    """
    result = await service.list_controller_devices_for_location(
        location_id=location_id, organization_id=requesting_organization_id
    )
    payload = ControllerInventoryResponse(
        status=result.status,
        devices=[
            ControllerDeviceView(
                mac=device.mac,
                name=device.name,
                device_type=device.device_type,
                model=device.model,
                status=device.status,
                ip_address=device.ip_address,
                firmware_version=device.firmware_version,
                uptime_seconds=device.uptime_seconds,
                client_count=device.client_count,
            )
            for device in result.devices
        ],
    )
    return build_response(
        success=True,
        message="Controller devices",
        data=payload.model_dump(),
        request_id=request.headers.get("X-Request-ID", ""),
    )
