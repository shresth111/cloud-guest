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
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

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
    FleetPeerStatusResponse,
    FleetStatusResponse,
    MessageResponse,
    RegisterExternalWireGuardPeerRequest,
    WireGuardPeerResponse,
    WireGuardTunnelCreateResponse,
    WireGuardTunnelRotateResponse,
)
from .service import FleetStatus, TunnelDeliveryInfo, WireGuardService
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


def _fleet_status_response(status_: FleetStatus) -> FleetStatusResponse:
    return FleetStatusResponse(
        summary={s.value: count for s, count in status_.summary.items()},
        peers=[
            FleetPeerStatusResponse(
                status=entry.status,
                public_key=entry.public_key,
                router_id=str(entry.router_id) if entry.router_id else None,
                router_name=entry.router_name,
                tunnel_ip_address=entry.tunnel_ip_address,
                last_handshake_at=entry.last_handshake_at,
            )
            for entry in status_.peers
        ],
    )


@router.get(
    "/wireguard/fleet-status",
    response_model=ApiResponse[FleetStatusResponse],
    status_code=status.HTTP_200_OK,
    # GLOBAL, same reasoning as GET /routers/{id}/wireguard-peer just below:
    # this reads across the ENTIRE fleet, not one router, so it must never
    # be reachable via an org-scoped role at all -- there is no
    # organization an unscoped "how many of the fleet are connected"
    # question could sensibly be answered for.
    dependencies=[Depends(RequirePermission("wireguard.read", scope=ScopeType.GLOBAL))],
)
async def get_wireguard_fleet_status(
    request: Request,
    service: WireGuardService = Depends(get_wireguard_service),
):
    """Compares this platform's own ``wireguard_peers`` table against the
    hub's own live ``wg show`` state and returns the merged, classified
    result -- see ``WireGuardService.get_fleet_status`` for the full
    per-peer classification. Built after a live incident where the two
    had drifted sharply (72 peers on the hub, 1 in the database)."""
    fleet_status = await service.get_fleet_status()
    return build_response(
        success=True,
        message="Fleet status retrieved",
        data=_fleet_status_response(fleet_status).model_dump(),
        request_id=_request_id(request),
    )


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


def _bridge_error_detail(resp: httpx.Response) -> str:
    """The hub agent's own explanation of a >=400. See the identically
    named helper in ``app.domains.guest.router`` -- both hub agents share
    the ``{"error": "<str(exception)>"}`` shape and the same silent-logging
    behaviour, so both need the body carried through to the caller."""
    try:
        body = resp.json()
    except ValueError:
        return (resp.text or "<empty response body>")[:600]
    if isinstance(body, dict) and "error" in body:
        return str(body["error"])[:600]
    return str(body)[:600]


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
    rotate: bool = Query(
        default=False,
        description=(
            "Allocate a BRAND NEW keypair and tunnel IP even if this router "
            "already has a usable peer. Default false -- see the endpoint's "
            "docstring: the hub agent has no delete or update verb, so every "
            "allocation is permanent and unreclaimable. Tick this only when "
            "the device has genuinely lost its WireGuard config (a reflash, "
            "or straight after Guided Setup's recovery phase), because it is "
            "the one case reuse cannot serve."
        ),
    ),
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
    # REUSE BEFORE ALLOCATING. Added 2026-08-27.
    #
    # `ops/hub-agents/wg_agent.py` exposes exactly two verbs: `POST
    # /wg/peer`, which ALWAYS calls `allocate_peer()` with no reuse branch
    # and no idempotency key, and `GET /wg/peers`. There is no `do_DELETE`
    # and no `do_PUT` -- an attempted DELETE returns `501 Unsupported
    # method`. So on that hub, every allocation is PERMANENT AND
    # UNRECLAIMABLE by construction.
    #
    # This endpoint called it unconditionally, on every click of Generate.
    # The consequences compounded:
    #   - the hub accumulated a peer per click and could never shed one;
    #     router 01c9171e's tunnel IP reached 10.20.0.5 while the device was
    #     still using .3, and orphans survive even the router row's deletion
    #   - `next_free_ip()` scans live kernel state, so the orphans
    #     permanently consume a /24
    #   - `register_external_radius_nas` binds the FreeRADIUS `client{}`
    #     stanza to the tunnel IP THIS TABLE holds, so the device -- still
    #     on the previous address -- became an unknown client whose RADIUS
    #     packets are dropped with no reply and nothing logged
    #
    # Reuse is the only half of this we can fix from here: a client-side
    # "update the peer" script cannot repair a divergence whose server side
    # has no update verb, and shipping one to the hub needs shell access
    # this platform does not currently have.
    #
    # Correctness of returning no private key: an agent-allocated peer's
    # key was generated ON THE HUB and stored here as
    # EXTERNALLY_MANAGED_KEY_SENTINEL -- this platform has never held it.
    # That is exactly why reuse is safe: the device already has the
    # matching key. The response carries `reused=True` and a null
    # `peer_private_key`, and the setup-script generator omits the
    # `private-key=` line rather than writing a sentinel over a working
    # interface.
    #
    # `rotate=true` is the escape hatch for the one case reuse cannot
    # serve -- a device that has genuinely lost its config -- mirroring the
    # explicit-opt-in shape the API-password path already uses.
    if not rotate:
        existing = await service.get_peer_if_usable(
            router_id=router_id,
            requesting_organization_id=requesting_organization_id,
        )
        if existing is not None:
            base = _peer_response(existing, service=service)
            server = await service.get_server(existing.server_id)
            payload = WireGuardTunnelCreateResponse(
                **base.model_dump(),
                peer_private_key=None,
                reused=True,
                hub_public_key=server.public_key,
                hub_endpoint_host=server.endpoint_host,
                hub_endpoint_port=server.endpoint_port,
                tunnel_network_cidr=server.tunnel_network_cidr,
                hub_tunnel_ip_address=hub_reserved_ip(server.tunnel_network_cidr),
            )
            return build_response(
                success=True,
                message=(
                    "Existing WireGuard tunnel reused -- no new peer was "
                    "allocated on the hub"
                ),
                data=payload.model_dump(),
                request_id=_request_id(request),
            )

    # Same reporting fix as `register_external_radius_nas` -- see the long
    # note there. A bridge that answers with a real HTTP status is NOT
    # "could not be reached", and its response body is the only description
    # of the failure that exists anywhere (the agents' `log_message` is a
    # deliberate no-op, so nothing reaches the hub's journal either).
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            _settings = get_settings()
            resp = await client.post(
                _settings.hub_wg_agent_url,
                headers={"X-Agent-Secret": _settings.hub_wg_agent_secret},
            )
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Could not reach the WireGuard hub bridge: {exc!s}",
        ) from exc

    if resp.status_code >= 400:
        raise HTTPException(
            status_code=502,
            detail=(
                f"The WireGuard hub bridge refused this allocation "
                f"(HTTP {resp.status_code}): {_bridge_error_detail(resp)}"
            ),
        )
    wg = resp.json()

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
