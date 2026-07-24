"""FastAPI routes for the Router domain: device CRUD, lifecycle management,
and zero-touch provisioning.

Responses use the project's standard envelope (``ApiResponse`` /
``build_response``), matching every other domain's router -- except the
device-presented check-in endpoint, which deliberately does not (see
``docs/router/ROUTER_ARCHITECTURE.md`` §5). Every mutating (and cross-
tenant-sensitive read) user-facing endpoint is gated by RBAC's existing
``RequirePermission`` dependency against the already-seeded ``routers.*``/
``router_provisioning.*`` permission keys -- this domain defines no
permission keys of its own.

``location_id`` appears in the path for the two collection endpoints (list/
create, nested under ``/locations/{location_id}/routers``) since a router is
always registered at a specific location; the remaining endpoints address a
router directly by its own id. Every user-facing endpoint additionally
resolves ``CurrentOrganization`` (``X-Organization-Id``) and passes it to
``RouterService`` as ``requesting_organization_id`` so tenant scoping is
enforced the same way ``OrganizationService``/``LocationService`` enforce it
-- not just left to the permission check, which only verifies *what* the
caller can do, not *which tenant's data* they are doing it to.

**Provisioning-token generation is approval-gated**: ``router_provisioning``
is the only permission module seeded with an ``approve`` action alongside
``create`` (``routers`` itself has no ``approve`` action) -- a strong signal
this action exists specifically to gate issuing a bearer credential that lets
a physical device join the network. ``POST /routers/{id}/provisioning-token``
therefore requires *both* ``router_provisioning.create`` and
``router_provisioning.approve``.

**The device check-in endpoint is not a normal authenticated-user
endpoint.** ``POST /routers/provisioning/check-in`` carries no
``RequirePermission``/``CurrentUser`` dependency at all -- the physical
device has no platform user identity or JWT; its only credential is the
provisioning token itself, presented in the request body and validated by
``RouterService.check_in`` (hash-compare against ``token_hash``, expiry,
single-use). See ``docs/router/ROUTER_ARCHITECTURE.md`` §5 for the full
reasoning, including why this was chosen over a bespoke bearer-header auth
scheme.

**Additive dependency on Module 009 Part 2
(``app.domains.router_agent``).** ``provisioning_check_in`` composes with
``RouterAgentService.issue_credential_for_router`` to additionally issue
that module's persistent, device-facing bearer credential in the same
response -- see ``ProvisioningCheckInResponse``'s own docstring and
``app.domains.router_agent.service``'s module docstring for why this was
chosen over a separate, later "activate" endpoint. Nothing else in this
file changed for that module's sake.

**Additive dependency on Module 009 Part 3
(``app.domains.wireguard``).** ``provisioning_check_in`` also, optionally,
composes with ``WireGuardService.create_tunnel`` (its additive
``external_public_key`` parameter) when the device-presented request
carries ``wireguard_public_key`` -- the zero-touch bootstrap-script path
described in ``app.domains.network_config.renderers.render_bootstrap_script``'s
own docstring. This reuses ``WireGuardService``'s real tunnel-IP allocator
rather than a second, parallel one; see that method's own docstring for
why the device's public key is accepted as-is instead of a platform-
generated one.
"""

from __future__ import annotations

import ipaddress
import uuid

from fastapi import APIRouter, Depends, Query, Request, status

from app.common.responses import ApiResponse, build_response
from app.domains.auth.models import AuthUser
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequirePermission,
)
from app.domains.router_agent.dependencies import get_router_agent_service
from app.domains.router_agent.service import RouterAgentService
from app.domains.wireguard.dependencies import get_wireguard_service
from app.domains.wireguard.service import WireGuardService

from .dependencies import get_router_service
from .enums import RouterStatus
from .models import Router
from .schemas import (
    HeartbeatRequest,
    MessageResponse,
    ProvisioningCheckInRequest,
    ProvisioningCheckInResponse,
    ProvisioningTokenResponse,
    RouterCreateRequest,
    RouterListResponse,
    RouterResponse,
    RouterUpdateRequest,
)
from .service import RouterService

router = APIRouter(tags=["Routers"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _router_response(router_device: Router) -> RouterResponse:
    return RouterResponse(
        id=str(router_device.id),
        location_id=str(router_device.location_id),
        organization_id=str(router_device.organization_id),
        name=router_device.name,
        serial_number=router_device.serial_number,
        mac_address=router_device.mac_address,
        model=router_device.model,
        vendor=router_device.vendor,
        routeros_version=router_device.routeros_version,
        management_ip_address=router_device.management_ip_address,
        public_ip_address=router_device.public_ip_address,
        status=RouterStatus(router_device.status),
        last_seen_at=router_device.last_seen_at,
        last_health_check_at=router_device.last_health_check_at,
        health_status=router_device.health_status,
        has_api_credentials=router_device.api_credentials_encrypted is not None,
        settings=router_device.settings,
        created_at=router_device.created_at,
        updated_at=router_device.updated_at,
    )


# ============================================================================
# Collection endpoints (nested under a location)
# ============================================================================


@router.get(
    "/locations/{location_id}/routers",
    response_model=ApiResponse[RouterListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("routers.read"))],
)
async def list_routers(
    request: Request,
    location_id: uuid.UUID,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    search: str | None = Query(default=None, max_length=200),
    router_status: RouterStatus | None = Query(default=None),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    router_service: RouterService = Depends(get_router_service),
):
    routers, meta = await router_service.list_routers(
        location_id=location_id,
        requesting_organization_id=requesting_organization_id,
        page=page,
        page_size=page_size,
        search=search,
        status=router_status,
    )
    payload = RouterListResponse(
        items=[_router_response(item) for item in routers],
        page=meta.page,
        page_size=meta.page_size,
        total_items=meta.total_items,
        total_pages=meta.total_pages,
        has_next=meta.has_next,
        has_previous=meta.has_previous,
    )
    return build_response(
        success=True,
        message="Routers retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/locations/{location_id}/routers",
    response_model=ApiResponse[RouterResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("routers.create"))],
)
async def create_router(
    request: Request,
    location_id: uuid.UUID,
    payload: RouterCreateRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    router_service: RouterService = Depends(get_router_service),
):
    created = await router_service.create_router(
        actor_user_id=uuid.UUID(user.id),
        location_id=location_id,
        requesting_organization_id=requesting_organization_id,
        name=payload.name,
        serial_number=payload.serial_number,
        mac_address=payload.mac_address,
        model=payload.model,
        vendor=payload.vendor,
        management_ip_address=payload.management_ip_address,
        public_ip_address=payload.public_ip_address,
        api_username=payload.api_username,
        api_secret=payload.api_secret,
        settings=payload.settings,
    )
    return build_response(
        success=True,
        message="Router registered",
        data=_router_response(created).model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Direct router endpoints
# ============================================================================


@router.get(
    "/routers/{router_id}",
    response_model=ApiResponse[RouterResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("routers.read"))],
)
async def get_router(
    request: Request,
    router_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    router_service: RouterService = Depends(get_router_service),
):
    router_device = await router_service.get_router(
        router_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Router retrieved",
        data=_router_response(router_device).model_dump(),
        request_id=_request_id(request),
    )


@router.put(
    "/routers/{router_id}",
    response_model=ApiResponse[RouterResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("routers.update"))],
)
async def update_router(
    request: Request,
    router_id: uuid.UUID,
    payload: RouterUpdateRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    router_service: RouterService = Depends(get_router_service),
):
    data = payload.model_dump(exclude_unset=True)
    updated = await router_service.update_router(
        actor_user_id=uuid.UUID(user.id),
        router_id=router_id,
        requesting_organization_id=requesting_organization_id,
        data=data,
    )
    return build_response(
        success=True,
        message="Router updated",
        data=_router_response(updated).model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/routers/{router_id}",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("routers.delete"))],
)
async def decommission_router(
    request: Request,
    router_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    router_service: RouterService = Depends(get_router_service),
):
    await router_service.decommission_router(
        actor_user_id=uuid.UUID(user.id),
        router_id=router_id,
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Router decommissioned",
        data=MessageResponse(message="Router decommissioned").model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/routers/{router_id}/suspend",
    response_model=ApiResponse[RouterResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("routers.manage"))],
)
async def suspend_router(
    request: Request,
    router_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    router_service: RouterService = Depends(get_router_service),
):
    updated = await router_service.suspend_router(
        actor_user_id=uuid.UUID(user.id),
        router_id=router_id,
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Router suspended",
        data=_router_response(updated).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/routers/{router_id}/reinstate",
    response_model=ApiResponse[RouterResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("routers.manage"))],
)
async def reinstate_router(
    request: Request,
    router_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    router_service: RouterService = Depends(get_router_service),
):
    updated = await router_service.reinstate_router(
        actor_user_id=uuid.UUID(user.id),
        router_id=router_id,
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Router reinstated",
        data=_router_response(updated).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/routers/{router_id}/heartbeat",
    response_model=ApiResponse[RouterResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("routers.manage"))],
)
async def router_heartbeat(
    request: Request,
    router_id: uuid.UUID,
    payload: HeartbeatRequest,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    router_service: RouterService = Depends(get_router_service),
):
    updated = await router_service.heartbeat(
        router_id=router_id,
        requesting_organization_id=requesting_organization_id,
        routeros_version=payload.routeros_version,
        management_ip_address=payload.management_ip_address,
    )
    return build_response(
        success=True,
        message="Heartbeat recorded",
        data=_router_response(updated).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/routers/{router_id}/provisioning-token",
    response_model=ApiResponse[ProvisioningTokenResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(RequirePermission("router_provisioning.create")),
        Depends(RequirePermission("router_provisioning.approve")),
    ],
)
async def generate_provisioning_token(
    request: Request,
    router_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    router_service: RouterService = Depends(get_router_service),
):
    token, plaintext = await router_service.generate_provisioning_token(
        actor_user_id=uuid.UUID(user.id),
        router_id=router_id,
        requesting_organization_id=requesting_organization_id,
    )
    payload = ProvisioningTokenResponse(
        router_id=str(token.router_id), token=plaintext, expires_at=token.expires_at
    )
    return build_response(
        success=True,
        message=(
            "Provisioning token generated -- store it now, it will not be "
            "shown again"
        ),
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Device-facing zero-touch provisioning endpoint
# ============================================================================


@router.post(
    "/routers/provisioning/check-in",
    status_code=status.HTTP_200_OK,
)
async def provisioning_check_in(
    payload: ProvisioningCheckInRequest,
    router_service: RouterService = Depends(get_router_service),
    agent_service: RouterAgentService = Depends(get_router_agent_service),
    wireguard_service: WireGuardService = Depends(get_wireguard_service),
) -> ProvisioningCheckInResponse:
    """Presented by the physical device, not an authenticated platform user
    -- see module docstring and ``docs/router/ROUTER_ARCHITECTURE.md`` §5.

    Additively issues the device's persistent ``app.domains.router_agent``
    credential in the same response (see
    ``ProvisioningCheckInResponse``'s own docstring and
    ``app.domains.router_agent.service``'s module docstring for why here,
    not a separate later endpoint): this call is the device's last chance to
    authenticate itself with a credential (the one-time provisioning token)
    this platform already trusts before that token is consumed.

    **Module 009 Part 3 (zero-touch enrollment) additive extension:** when
    ``payload.wireguard_public_key`` is present, this call also composes
    with ``WireGuardService.create_tunnel`` (via its additive
    ``external_public_key`` parameter -- see that method's own docstring)
    to allocate this router's tunnel IP and create its ``WireGuardPeer``
    row right here, using the *same* allocation logic every other tunnel
    on this platform goes through -- not a second, parallel allocator. This
    is deliberately optional: a device presenting only ``token`` (no public
    key yet, or a non-WireGuard enrollment path) gets exactly today's
    behavior, unchanged. When absent, no ``WireGuardPeer`` is created and
    the four WireGuard-shaped response fields stay ``None`` -- a device can
    always create its tunnel later through the ordinary, authenticated
    ``app.domains.wireguard`` admin surface instead."""
    updated = await router_service.check_in(plaintext_token=payload.token)
    credential, agent_credential = await agent_service.issue_credential_for_router(
        updated
    )

    tunnel_ip_address: str | None = None
    wireguard_server_public_key: str | None = None
    wireguard_endpoint_host: str | None = None
    wireguard_endpoint_port: int | None = None
    wireguard_hub_tunnel_address: str | None = None
    if payload.wireguard_public_key:
        delivery = await wireguard_service.create_tunnel(
            actor_user_id=None,
            router_id=updated.id,
            requesting_organization_id=None,
            external_public_key=payload.wireguard_public_key,
        )
        tunnel_ip_address = delivery.peer.tunnel_ip_address
        wireguard_server_public_key = delivery.server.public_key
        wireguard_endpoint_host = delivery.server.endpoint_host
        wireguard_endpoint_port = delivery.server.endpoint_port
        # The hub's own conventional tunnel address (first usable host of
        # its tunnel_network_cidr) -- mirrors
        # app.domains.network_config.renderers._hub_tunnel_address's
        # identical derivation exactly, computed here rather than imported
        # since that helper is that module's own private implementation
        # detail, not a shared cross-domain surface. See
        # ProvisioningCheckInResponse.wireguard_hub_tunnel_address's own
        # docstring for why the device needs this real value, not a
        # fabricated one, for its own allowed-address=.
        hub_network = ipaddress.ip_network(
            delivery.server.tunnel_network_cidr, strict=False
        )
        wireguard_hub_tunnel_address = str(next(hub_network.hosts()))

    return ProvisioningCheckInResponse(
        router_id=str(updated.id),
        status=RouterStatus(updated.status),
        agent_credential=agent_credential,
        agent_credential_expires_at=credential.expires_at,
        tunnel_ip_address=tunnel_ip_address,
        wireguard_server_public_key=wireguard_server_public_key,
        wireguard_endpoint_host=wireguard_endpoint_host,
        wireguard_endpoint_port=wireguard_endpoint_port,
        wireguard_hub_tunnel_address=wireguard_hub_tunnel_address,
    )


__all__ = ["router"]
