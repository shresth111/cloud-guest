"""FastAPI routes for the WireGuard domain: admin-facing tunnel/peer
lifecycle management, plus device-facing tunnel-configuration delivery and
handshake reporting.

**Admin-facing endpoints** (``GET``/``POST``/``DELETE .../wireguard-peer``,
``POST .../wireguard-peer/rotate``) use the project's standard envelope
(``ApiResponse``/``build_response``) and are gated by RBAC's existing
``RequirePermission`` dependency against the already-seeded ``wireguard.*``
permission keys, exactly mirroring ``app.domains.router.router``'s own
convention. ``rotate`` is gated by ``wireguard.execute`` (not ``update``) --
consistent with how ``PermissionModule.WIREGUARD``'s own ``execute`` action
is used elsewhere in this codebase's seed data (``ROUTERS``/``HOTSPOT``/
``FIREWALL`` also carry a distinct ``execute`` action alongside
``create``/``update``) for "trigger an operational action against the live
device," as opposed to editing a stored record.

**Device-facing endpoints** (``GET /agent/wireguard-config``,
``POST /agent/wireguard-config/handshake``) are a **new cross-domain
composition, not a new device-credential scheme.** Both depend on
``app.domains.router_agent.dependencies.CurrentAgent`` -- imported and
reused exactly as-is, never reimplemented -- the same persistent,
hashed-bearer-credential dependency (presented via
``X-Agent-Credential``) every other device-facing endpoint in
``app.domains.router_agent.router`` already depends on. This is precisely
the seam the module brief calls for: "the device (via its existing agent
credential) can pull its assigned WireGuard peer config through a new
device-facing endpoint in *this* module that itself depends on
router_agent's existing CurrentAgent-style dependency." Responses mirror
``app.domains.router_agent.schemas``'s own minimal, non-``ApiResponse``
shape -- the calling device is not expected to parse a rich, user-facing
API contract.

``POST /agent/wireguard-config/handshake`` is an **additive endpoint beyond
the module brief's literal five** -- the brief explicitly leaves "how
``last_handshake_at`` gets updated" to this module's judgment ("via the
device-facing status/heartbeat composition, or via a dedicated endpoint the
device calls -- your call"). Composing through ``app.domains.router_agent
.router.agent_report_status`` was considered and rejected: that endpoint's
request schema lives in a module this task's scope explicitly forbids
modifying, and stretching "the device just pulled its config" into "a
handshake was observed" would conflate two genuinely different WireGuard
concepts (config delivery vs. a live tunnel handshake). A small, dedicated,
equally ``CurrentAgent``-gated endpoint keeps the two signals honest and
independently testable without touching any file outside this module's own
directory.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request, status

from app.common.responses import ApiResponse, build_response
from app.domains.auth.models import AuthUser
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequirePermission,
)
from app.domains.router_agent.dependencies import AgentIdentity, CurrentAgent

from .dependencies import get_wireguard_service
from .models import WireGuardPeer
from .schemas import (
    AgentWireGuardConfigResponse,
    AgentWireGuardHandshakeResponse,
    MessageResponse,
    WireGuardPeerResponse,
    WireGuardTunnelCreateResponse,
    WireGuardTunnelRotateResponse,
)
from .service import TunnelDeliveryInfo, WireGuardService

router = APIRouter(tags=["WireGuard"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _peer_response(
    peer: WireGuardPeer, *, service: WireGuardService
) -> WireGuardPeerResponse:
    return WireGuardPeerResponse(
        id=str(peer.id),
        router_id=str(peer.router_id),
        server_id=str(peer.server_id),
        tunnel_ip_address=peer.tunnel_ip_address,
        public_key=peer.public_key,
        status=peer.status,
        rotation_count=peer.rotation_count,
        last_handshake_at=peer.last_handshake_at,
        health_status=service.compute_health_status(peer),
        created_at=peer.created_at,
        updated_at=peer.updated_at,
    )


def _tunnel_delivery_response(
    info: TunnelDeliveryInfo,
    *,
    service: WireGuardService,
    schema: type[WireGuardTunnelCreateResponse],
) -> WireGuardTunnelCreateResponse:
    base = _peer_response(info.peer, service=service)
    return schema(
        **base.model_dump(),
        peer_private_key=info.peer_private_key,
        hub_public_key=info.server.public_key,
        hub_endpoint_host=info.server.endpoint_host,
        hub_endpoint_port=info.server.endpoint_port,
        tunnel_network_cidr=info.server.tunnel_network_cidr,
    )


# ============================================================================
# Admin-facing peer endpoints
# ============================================================================


@router.get(
    "/routers/{router_id}/wireguard-peer",
    response_model=ApiResponse[WireGuardPeerResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("wireguard.read"))],
)
async def get_wireguard_peer(
    request: Request,
    router_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: WireGuardService = Depends(get_wireguard_service),
):
    peer = await service.get_peer(
        router_id=router_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="WireGuard tunnel retrieved",
        data=_peer_response(peer, service=service).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/routers/{router_id}/wireguard-peer",
    response_model=ApiResponse[WireGuardTunnelCreateResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("wireguard.create"))],
)
async def create_wireguard_peer(
    request: Request,
    router_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: WireGuardService = Depends(get_wireguard_service),
):
    info = await service.create_tunnel(
        actor_user_id=uuid.UUID(user.id),
        router_id=router_id,
        requesting_organization_id=requesting_organization_id,
    )
    payload = _tunnel_delivery_response(
        info, service=service, schema=WireGuardTunnelCreateResponse
    )
    return build_response(
        success=True,
        message=(
            "WireGuard tunnel created -- the peer private key is shown here "
            "for manual configuration, and remains retrievable by the "
            "device itself via GET /agent/wireguard-config"
        ),
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/routers/{router_id}/wireguard-peer",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("wireguard.delete"))],
)
async def revoke_wireguard_peer(
    request: Request,
    router_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: WireGuardService = Depends(get_wireguard_service),
):
    await service.revoke_tunnel(
        actor_user_id=uuid.UUID(user.id),
        router_id=router_id,
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="WireGuard tunnel revoked",
        data=MessageResponse(message="WireGuard tunnel revoked").model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/routers/{router_id}/wireguard-peer/rotate",
    response_model=ApiResponse[WireGuardTunnelRotateResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("wireguard.execute"))],
)
async def rotate_wireguard_peer(
    request: Request,
    router_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: WireGuardService = Depends(get_wireguard_service),
):
    info = await service.rotate_tunnel(
        actor_user_id=uuid.UUID(user.id),
        router_id=router_id,
        requesting_organization_id=requesting_organization_id,
    )
    payload = _tunnel_delivery_response(
        info, service=service, schema=WireGuardTunnelRotateResponse
    )
    return build_response(
        success=True,
        message="WireGuard tunnel keys rotated -- the tunnel IP is unchanged",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Device-facing endpoints -- composes with app.domains.router_agent's
# CurrentAgent, see module docstring.
# ============================================================================


@router.get(
    "/agent/wireguard-config",
    response_model=AgentWireGuardConfigResponse,
    status_code=status.HTTP_200_OK,
)
async def agent_pull_wireguard_config(
    identity: AgentIdentity = Depends(CurrentAgent),
    service: WireGuardService = Depends(get_wireguard_service),
) -> AgentWireGuardConfigResponse:
    """Repeatable, not "shown once" -- see ``service.py``'s module docstring
    for why the device may re-pull its own private key anytime, unlike a
    one-time provisioning token/agent credential."""
    info = await service.get_config_for_agent(router=identity.router)
    return AgentWireGuardConfigResponse(
        router_id=str(identity.router.id),
        peer_public_key=info.peer.public_key,
        peer_private_key=info.peer_private_key,
        tunnel_ip_address=info.peer.tunnel_ip_address,
        tunnel_network_cidr=info.server.tunnel_network_cidr,
        hub_public_key=info.server.public_key,
        hub_endpoint_host=info.server.endpoint_host,
        hub_endpoint_port=info.server.endpoint_port,
    )


@router.post(
    "/agent/wireguard-config/handshake",
    response_model=AgentWireGuardHandshakeResponse,
    status_code=status.HTTP_200_OK,
)
async def agent_report_wireguard_handshake(
    identity: AgentIdentity = Depends(CurrentAgent),
    service: WireGuardService = Depends(get_wireguard_service),
) -> AgentWireGuardHandshakeResponse:
    """See module docstring for why this is a small, additive endpoint
    rather than composing through ``app.domains.router_agent``'s own
    ``POST /agent/status``."""
    peer = await service.record_handshake(router=identity.router)
    assert peer.last_handshake_at is not None  # set unconditionally above
    return AgentWireGuardHandshakeResponse(
        router_id=str(identity.router.id),
        last_handshake_at=peer.last_handshake_at,
    )


__all__ = ["router"]
