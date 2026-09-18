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

## Where the line is drawn, now that this router does write

It used to say "read-only, always". That was the right line while the only
thing here was controller inventory, and it is the wrong line for the thing a
duty manager actually needs to do at 9pm: stop one device, slow one device,
disconnect one guest. So the line has moved, and it has moved to a specific
place rather than being erased.

**Controller *management* stays Master-only and is not on this router.**
Credentials, portal configuration, site selection, walled-garden entries,
integration CRUD, anything that changes how the venue's network is *set up* --
all of that remains on ``router.py`` at ``ScopeType.GLOBAL``, for the original
reason: writing network configuration to a live controller can drop guest
internet for the whole venue, and that is not a customer-facing risk.

**Per-*client* actions live here.** Blocking one device, clearing that block,
disconnecting one guest, setting and clearing one device's speed limit. Their
blast radius is one MAC address at one venue, they are the venue's own
decision to make about its own guests, and routing them through the Master
console would mean a venue owner filing a support ticket to throttle a
freeloader. Nothing here can touch a second device, let alone a second venue.

## Tenancy: the caller names a location, never a controller

Every route on this router is keyed on ``location_id`` plus, for the client
actions, a MAC. **No route takes an integration id, a site id or a controller
address**, and that is the tenancy design rather than a URL-style preference.
The integration is resolved by a query carrying the caller's own organization
*and* the location (``service._resolve_location_controller`` ->
``repository.get_omada_integration_for_location``), and the controller site
the action runs against comes from the row that query returned. So a location
id belonging to another tenant resolves to nothing, with the same 404 and the
same sentence as a location of the caller's own that has no controller -- and
a MAC belonging to another tenant's guest is simply a string this venue's
controller has never heard of.

There is no code path here in which a cross-tenant id is read and then
refused, which is the defect class this codebase has now found in fourteen
endpoints: the permission dependency reads the organization from the request
header while the handler reads the id from the path, and nothing compares
them.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request

from app.common.responses import ApiResponse, build_response
from app.domains.auth.models import AuthUser
from app.domains.queue_management.dependencies import get_queue_management_service
from app.domains.queue_management.service import QueueManagementService
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequirePermission,
)
from app.domains.rbac.enums import ScopeType

from .dependencies import get_network_integration_service
from .schemas import (
    ClientActionResponse,
    ClientCapabilitiesResponse,
    ClientCapabilityView,
    ClientMacRequest,
    ClientRateLimitView,
    ClientSpeedRequest,
    ControllerDeviceView,
    ControllerInventoryResponse,
)
from .service import ClientActionResult, NetworkIntegrationService

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


# ============================================================================
# Per-client actions
# ============================================================================


def _actor_id(actor: AuthUser | None) -> uuid.UUID | None:
    return uuid.UUID(actor.id) if actor is not None else None


def _capability_view(entry: dict[str, object]) -> ClientCapabilityView:
    return ClientCapabilityView(
        supported=bool(entry["supported"]),
        reason=entry["reason"],  # type: ignore[arg-type]
    )


def _client_action_response(
    result: ClientActionResult, request: Request, message: str
) -> ApiResponse[ClientActionResponse]:
    rate_limit = (
        None
        if result.rate_limit is None
        else ClientRateLimitView(
            enabled=result.rate_limit.enabled,
            applied_down_kbps=result.rate_limit.applied_down_kbps,
            applied_up_kbps=result.rate_limit.applied_up_kbps,
            requested_down_kbps=result.rate_limit.requested_down_kbps,
            requested_up_kbps=result.rate_limit.requested_up_kbps,
            clamped=result.rate_limit.clamped,
        )
    )
    payload = ClientActionResponse(
        action=result.action,
        performed=result.performed,
        client_mac=result.client_mac,
        rate_limit=rate_limit,
    )
    return build_response(
        success=True,
        message=message,
        data=payload.model_dump(),
        request_id=request.headers.get("X-Request-ID", ""),
    )


@customer_router.get(
    "/locations/{location_id}/clients/capabilities",
    response_model=ApiResponse[ClientCapabilitiesResponse],
    dependencies=[
        Depends(RequirePermission("locations.read", scope=ScopeType.ORGANIZATION))
    ],
)
async def get_location_client_capabilities(
    location_id: uuid.UUID,
    request: Request,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NetworkIntegrationService = Depends(get_network_integration_service),
) -> ApiResponse[ClientCapabilitiesResponse]:
    """What this venue's controller can do to one of its devices.

    Contacts nothing -- the answer comes from the integration's own auth
    mode -- so a console can call it while rendering and show an honestly
    disabled control with the reason beside it, instead of an enabled one
    that fails when somebody clicks it.

    ``locations.read`` because the question is about the location's own
    equipment and answers with no guest data; the actions themselves carry
    the heavier permissions.
    """
    capabilities = await service.get_client_capabilities(
        location_id=location_id, organization_id=requesting_organization_id
    )
    payload = ClientCapabilitiesResponse(
        set_rate_limit=_capability_view(capabilities["set_rate_limit"]),
        clear_rate_limit=_capability_view(capabilities["clear_rate_limit"]),
        block=_capability_view(capabilities["block"]),
        unblock=_capability_view(capabilities["unblock"]),
        list_blocked=_capability_view(capabilities["list_blocked"]),
        disconnect=_capability_view(capabilities["disconnect"]),
        client_stats=_capability_view(capabilities["client_stats"]),
    )
    return build_response(
        success=True,
        message="Client capabilities",
        data=payload.model_dump(),
        request_id=request.headers.get("X-Request-ID", ""),
    )


@customer_router.post(
    "/locations/{location_id}/clients/block",
    response_model=ApiResponse[ClientActionResponse],
    dependencies=[
        Depends(RequirePermission("guest_access.update", scope=ScopeType.ORGANIZATION))
    ],
)
async def block_location_client(
    location_id: uuid.UUID,
    payload: ClientMacRequest,
    request: Request,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NetworkIntegrationService = Depends(get_network_integration_service),
) -> ApiResponse[ClientActionResponse]:
    """Stop one device joining this venue's network.

    ``guest_access.update`` rather than a new permission key: this is the
    device-side half of the blocklist a venue admin already manages there,
    and minting a key would leave every existing role without it until the
    RBAC seed and its tests changed too.

    **What a caller may truthfully say about the result.** The device can no
    longer associate, and that survives a reconnect -- the flag lives on the
    controller's known-client record, not on a live association, which is why
    it can be set on a device that is currently offline. What it does to a
    guest who is *authorized right now* has not been measured, so nothing
    downstream may claim it cuts them off mid-session. And it is keyed on the
    MAC, so a phone that randomizes per SSID gets past it by forgetting the
    network: it is a nuisance control, not enforcement. The enforcement is the
    platform's own blocklist, which is vendor-neutral and is consulted at
    every sign-in.
    """
    result = await service.block_client(
        location_id=location_id,
        organization_id=requesting_organization_id,
        client_mac=payload.client_mac,
        actor_user_id=_actor_id(actor),
    )
    return _client_action_response(result, request, "Device blocked")


@customer_router.post(
    "/locations/{location_id}/clients/unblock",
    response_model=ApiResponse[ClientActionResponse],
    dependencies=[
        Depends(RequirePermission("guest_access.update", scope=ScopeType.ORGANIZATION))
    ],
)
async def unblock_location_client(
    location_id: uuid.UUID,
    payload: ClientMacRequest,
    request: Request,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NetworkIntegrationService = Depends(get_network_integration_service),
) -> ApiResponse[ClientActionResponse]:
    """Let a blocked device back onto this venue's network. Idempotent."""
    result = await service.unblock_client(
        location_id=location_id,
        organization_id=requesting_organization_id,
        client_mac=payload.client_mac,
        actor_user_id=_actor_id(actor),
    )
    return _client_action_response(result, request, "Device unblocked")


@customer_router.post(
    "/locations/{location_id}/clients/disconnect",
    response_model=ApiResponse[ClientActionResponse],
    dependencies=[
        Depends(RequirePermission("guest_access.update", scope=ScopeType.ORGANIZATION))
    ],
)
async def disconnect_location_client(
    location_id: uuid.UUID,
    payload: ClientMacRequest,
    request: Request,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NetworkIntegrationService = Depends(get_network_integration_service),
) -> ApiResponse[ClientActionResponse]:
    """End one guest's session at this venue, now.

    The venue-scoped door onto the disconnect the Master console already has
    -- the same controller call and the same session bookkeeping, resolved by
    location instead of by integration id.

    It is the only client action a venue on a hotspot-operator login keeps,
    because it rides that operator session rather than the site tree.

    **It does not stop them coming back.** The controller-side authorization
    ends and the platform session is ended so the next portal hit does not
    silently re-admit them, but a guest who signs in again with a fresh OTP is
    admitted again. Blocking is the separate action for that.
    """
    outcome = await service.disconnect_client_at_location(
        location_id=location_id,
        organization_id=requesting_organization_id,
        client_mac=payload.client_mac,
        actor_user_id=_actor_id(actor),
    )
    payload_out = ClientActionResponse(
        action="disconnect",
        performed=outcome.disconnected,
        client_mac=outcome.client_mac,
    )
    return build_response(
        success=True,
        message="Guest disconnected",
        data=payload_out.model_dump(),
        request_id=request.headers.get("X-Request-ID", ""),
    )


@customer_router.put(
    "/locations/{location_id}/clients/speed",
    response_model=ApiResponse[ClientActionResponse],
    dependencies=[
        Depends(RequirePermission("bandwidth.update", scope=ScopeType.ORGANIZATION))
    ],
)
async def set_location_client_speed(
    location_id: uuid.UUID,
    payload: ClientSpeedRequest,
    request: Request,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NetworkIntegrationService = Depends(get_network_integration_service),
    queue_service: QueueManagementService = Depends(get_queue_management_service),
) -> ApiResponse[ClientActionResponse]:
    """Set one device's speed limit at this venue.

    Takes either explicit kbps rates or a ``queue_profile_id``. A profile is
    read through ``QueueManagementService.get_profile``, which puts the
    caller's organization into its own scope check -- so a profile belonging
    to another tenant is refused there, by the domain that owns the model,
    rather than by a second copy of the rule written here. Speed profiles are
    the ones this platform already has; there is no parallel Omada-only model.

    **Two things this response must not be read as promising.** The rate does
    not travel in a RADIUS reply: this controller honours no bandwidth
    attribute from any vendor, so the ``Mikrotik-Rate-Limit`` that carries
    speed at a RouterOS venue is inert here and the limit is set by this
    separate call after the guest is already on. And what has been measured is
    that the controller accepts, stores and returns the limit -- not that an
    access point was observed to deliver it. ``applied_down_kbps`` is what the
    controller holds; show that number, not the one that was typed, because
    they differ whenever ``clamped`` is true.
    """
    down_kbps = payload.down_kbps
    up_kbps = payload.up_kbps
    if payload.queue_profile_id is not None:
        profile = await queue_service.get_profile(
            payload.queue_profile_id,
            requesting_organization_id=requesting_organization_id,
        )
        down_kbps = profile.download_rate_kbps
        up_kbps = profile.upload_rate_kbps
    result = await service.set_client_speed(
        location_id=location_id,
        organization_id=requesting_organization_id,
        client_mac=payload.client_mac,
        down_kbps=down_kbps,
        up_kbps=up_kbps,
        actor_user_id=_actor_id(actor),
    )
    return _client_action_response(result, request, "Speed limit applied")


@customer_router.post(
    "/locations/{location_id}/clients/speed/clear",
    response_model=ApiResponse[ClientActionResponse],
    dependencies=[
        Depends(RequirePermission("bandwidth.update", scope=ScopeType.ORGANIZATION))
    ],
)
async def clear_location_client_speed(
    location_id: uuid.UUID,
    payload: ClientMacRequest,
    request: Request,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NetworkIntegrationService = Depends(get_network_integration_service),
) -> ApiResponse[ClientActionResponse]:
    """Remove one device's speed limit. Idempotent on the controller.

    ``POST .../speed/clear`` rather than ``DELETE .../speed`` because the
    device is named in the body and a DELETE with a body is a shape many HTTP
    clients and proxies handle badly.
    """
    result = await service.clear_client_speed(
        location_id=location_id,
        organization_id=requesting_organization_id,
        client_mac=payload.client_mac,
        actor_user_id=_actor_id(actor),
    )
    return _client_action_response(result, request, "Speed limit removed")
