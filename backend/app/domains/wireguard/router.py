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

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.common.responses import ApiResponse, build_response
from app.core.config import get_settings
from app.domains.auth.models import AuthUser
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequirePermission,
)
from app.domains.rbac.enums import ScopeType
from app.domains.router_agent.dependencies import AgentIdentity, CurrentAgent

from .dependencies import get_wireguard_service
from .models import WireGuardPeer
from .schemas import (
    AgentWireGuardConfigResponse,
    AgentWireGuardHandshakeResponse,
    MessageResponse,
    RegisterExternalWireGuardPeerRequest,
    WireGuardPeerResponse,
    WireGuardTunnelCreateResponse,
    WireGuardTunnelRotateResponse,
)
from .service import TunnelDeliveryInfo, WireGuardService
from .validators import hub_reserved_ip

router = APIRouter(tags=["WireGuard"])

# The single-tenant hub bridge (ops/hub-agents/wg_agent.py, port 9091).
# These WERE module constants hardcoded to the old hub's public IP with the
# shared secret in cleartext in this file. Both are now Settings fields
# (CLOUDGUEST_HUB_WG_AGENT_URL / _SECRET), read per call rather than at
# import time so a value can be changed without a code change OR an image
# rebuild -- the old constants were baked into the running image, so moving
# the hub cost a full rebuild and every venue provisioning hung to timeout
# in the meantime. Default target is the hub's VNet-private address: the
# transport is plain HTTP and the secret must not cross the internet.


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
        hub_tunnel_ip_address=hub_reserved_ip(info.server.tunnel_network_cidr),
    )


# ============================================================================
# Admin-facing peer endpoints
# ============================================================================


@router.get(
    "/routers/{router_id}/wireguard-peer",
    response_model=ApiResponse[WireGuardPeerResponse],
    status_code=status.HTTP_200_OK,
    # GLOBAL, not header-inferred -- WireGuard/tunnel internals must never
    # be reachable by an org-scoped role, even the router's own owning
    # organization (confirmed live: sending this org's own X-Organization-Id
    # let an Organization Owner token read full tunnel metadata, violating
    # the standing "no WireGuard on customer dashboard" product rule).
    dependencies=[Depends(RequirePermission("wireguard.read", scope=ScopeType.GLOBAL))],
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
    # See get_wireguard_peer's own comment -- GLOBAL scope only.
    dependencies=[
        Depends(RequirePermission("wireguard.create", scope=ScopeType.GLOBAL))
    ],
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


@router.post(
    "/routers/{router_id}/wireguard-peer/register-external",
    response_model=ApiResponse[WireGuardPeerResponse],
    status_code=status.HTTP_201_CREATED,
    # See get_wireguard_peer's own comment -- GLOBAL scope only.
    dependencies=[
        Depends(RequirePermission("wireguard.create", scope=ScopeType.GLOBAL))
    ],
)
async def register_external_wireguard_peer(
    request: Request,
    router_id: uuid.UUID,
    payload: RegisterExternalWireGuardPeerRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: WireGuardService = Depends(get_wireguard_service),
):
    """Records a peer the Master console's Setup Script panel already had
    allocated and configured directly against the real hub through its
    own out-of-band agent bridge (not this domain) -- see
    ``WireGuardService.register_agent_allocated_peer``'s own docstring
    for the full "why this exists" write-up. Never allocates a new IP or
    generates a keypair; both are already decided by the caller."""
    peer = await service.register_agent_allocated_peer(
        actor_user_id=uuid.UUID(user.id),
        router_id=router_id,
        requesting_organization_id=requesting_organization_id,
        tunnel_ip_address=payload.tunnel_ip_address,
        public_key=payload.public_key,
    )
    return build_response(
        success=True,
        message="WireGuard tunnel registered",
        data=_peer_response(peer, service=service).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/routers/{router_id}/wireguard-peer/allocate-external",
    response_model=ApiResponse[WireGuardTunnelCreateResponse],
    status_code=status.HTTP_201_CREATED,
    # See get_wireguard_peer's own comment -- GLOBAL scope only.
    dependencies=[
        Depends(RequirePermission("wireguard.create", scope=ScopeType.GLOBAL))
    ],
)
async def allocate_external_wireguard_peer(
    request: Request,
    router_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: WireGuardService = Depends(get_wireguard_service),
):
    """Server-side equivalent of the Master console calling the hub's agent
    bridge directly from the browser -- that bridge is a bare
    ``http.server.BaseHTTPRequestHandler`` with no CORS/OPTIONS support at
    all, so a browser ``fetch()`` to it always fails once a custom auth
    header is involved (confirmed live: the bridge 501s any OPTIONS
    preflight). CORS is a browser-enforced restriction on cross-origin
    requests -- it never applies to this server calling that bridge itself,
    so doing the exact same call from here sidesteps the problem entirely.
    Combines what the frontend previously did in two steps (call the
    bridge, then ``register-external``) into one, returning the same
    "everything needed to configure the device" bundle
    ``POST .../wireguard-peer`` does."""
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            _settings = get_settings()
            resp = await client.post(
                _settings.hub_wg_agent_url,
                headers={"X-Agent-Secret": _settings.hub_wg_agent_secret},
            )
            resp.raise_for_status()
            wg = resp.json()
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=502, detail="Could not reach the WireGuard hub bridge"
        ) from exc

    peer = await service.register_agent_allocated_peer(
        actor_user_id=uuid.UUID(user.id),
        router_id=router_id,
        requesting_organization_id=requesting_organization_id,
        tunnel_ip_address=wg["router_tunnel_ip"],
        public_key=wg["router_public_key"],
    )
    base = _peer_response(peer, service=service)
    payload = WireGuardTunnelCreateResponse(
        **base.model_dump(),
        peer_private_key=wg["router_private_key"],
        hub_public_key=wg["server_public_key"],
        hub_endpoint_host=wg["server_endpoint_host"],
        hub_endpoint_port=int(wg["server_endpoint_port"]),
        tunnel_network_cidr=wg["tunnel_subnet"],
        hub_tunnel_ip_address=hub_reserved_ip(wg["tunnel_subnet"]),
    )
    return build_response(
        success=True,
        message="WireGuard tunnel allocated",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/routers/{router_id}/wireguard-peer",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    # See get_wireguard_peer's own comment -- GLOBAL scope only.
    dependencies=[
        Depends(RequirePermission("wireguard.delete", scope=ScopeType.GLOBAL))
    ],
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
    # See get_wireguard_peer's own comment -- GLOBAL scope only.
    dependencies=[
        Depends(RequirePermission("wireguard.execute", scope=ScopeType.GLOBAL))
    ],
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
