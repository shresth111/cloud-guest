"""Pydantic request/response schemas for the WireGuard API.

Admin-facing schemas follow the same pydantic v2 conventions as
``app.domains.router.schemas`` (``ConfigDict``, ``from_attributes``,
explicit ``Field`` descriptions) and are wrapped in the project's standard
``ApiResponse``/``build_response`` envelope by ``router.py``.

Device-facing schemas (``AgentWireGuardConfigResponse``,
``AgentWireGuardHandshakeResponse``) deliberately do **not** use that
envelope, mirroring ``app.domains.router_agent.schemas``'s own "the calling
device is not expected to parse a rich, user-facing API contract" reasoning
-- see that module's schemas.py docstring and this domain's ``router.py``
module docstring for the exact cross-domain composition.

``WireGuardPeerResponse`` never includes raw key material -- only
``WireGuardTunnelCreateResponse``/``WireGuardTunnelRotateResponse`` (peer
creation/rotation) include the peer's private key, mirroring
``ProvisioningTokenResponse``/``ProvisioningCheckInResponse``'s "shown once,
at the moment it is generated" convention for admin-facing secrets --
though see ``service.py``'s module docstring for why this secret is, unlike
those, also always re-deliverable to the legitimate device afterward.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.domains.auth.schemas import MessageResponse

from .constants import (
    DEFAULT_PERSISTENT_KEEPALIVE_SECONDS,
    FleetPeerStatus,
    HealthStatus,
    PeerStatus,
)

__all__ = [
    "MessageResponse",
    "WireGuardPeerResponse",
    "WireGuardTunnelCreateResponse",
    "WireGuardTunnelRotateResponse",
    "AgentWireGuardConfigResponse",
    "AgentWireGuardHandshakeResponse",
]


# ============================================================================
# Admin-facing response schemas
# ============================================================================


class RegisterExternalWireGuardPeerRequest(BaseModel):
    """Body for ``POST .../wireguard-peer/register-external`` -- both
    values are already-decided facts about a tunnel an out-of-band agent
    bridge already configured directly on the real hub, not a request for
    this domain to allocate or generate anything (see
    ``WireGuardService.register_agent_allocated_peer``'s own docstring)."""

    tunnel_ip_address: str = Field(..., min_length=1, max_length=45)
    public_key: str = Field(..., min_length=1, max_length=64)


class WireGuardPeerResponse(BaseModel):
    """The read-only admin view of a router's current tunnel/peer -- never
    includes key material (see module docstring)."""

    id: str
    router_id: str
    server_id: str
    tunnel_ip_address: str
    public_key: str
    status: PeerStatus
    rotation_count: int
    last_handshake_at: datetime | None = None
    health_status: HealthStatus
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FleetPeerStatusResponse(BaseModel):
    """One peer's row in ``GET /wireguard/fleet-status`` -- a merge of this
    table's own record (if any) and the hub's live ``wg show`` state (if
    any) for one public key. See ``service.FleetPeerEntry``."""

    status: FleetPeerStatus
    public_key: str
    router_id: str | None = None
    router_name: str | None = None
    tunnel_ip_address: str | None = None
    # The address the HUB has in allowed-ips for this key. Reported next to
    # `tunnel_ip_address` (this platform's belief), not instead of it: the
    # two disagreeing IS the finding, and it is the specific disagreement
    # that silently drops every guest login, because the RADIUS client
    # stanza is keyed on the address.
    hub_tunnel_ip_address: str | None = None
    last_handshake_at: datetime | None = None
    # Why this row is classified the way it is, in plain English. Written
    # for whoever is looking at seven peers on a hub trying to work out
    # which ones matter -- an orphan that says why it is an orphan is not
    # drift.
    explanation: str | None = None


class FleetStatusResponse(BaseModel):
    """Returned by ``GET /wireguard/fleet-status`` -- a summary count per
    ``FleetPeerStatus`` plus the full per-peer detail list. See
    ``service.WireGuardService.get_fleet_status``'s own docstring for why
    this reads the hub live rather than trusting this table alone."""

    summary: dict[FleetPeerStatus, int]
    peers: list[FleetPeerStatusResponse]


class WireGuardTunnelCreateResponse(WireGuardPeerResponse):
    """Returned by ``POST /routers/{id}/wireguard-peer`` -- additionally
    carries everything needed to manually configure the device's local
    WireGuard interface, for the (hopefully rare) case zero-touch delivery
    via ``GET /agent/wireguard-config`` cannot reach the device."""

    peer_private_key: str | None = Field(
        default=None,
        description=(
            "The peer's own private key, decrypted -- see service.py "
            "docstring for why this remains retrievable, unlike a one-time "
            "token. NULL when `reused` is true: an agent-allocated peer's "
            "private key was generated on the hub and never held by this "
            "platform (stored as EXTERNALLY_MANAGED_KEY_SENTINEL), so there "
            "is nothing to hand back. That is not a degraded response -- the "
            "device already holds the matching key, which is precisely why "
            "the peer was reused rather than replaced."
        ),
    )
    reused: bool = Field(
        default=False,
        description=(
            "True when this router already had a usable peer and it was "
            "returned as-is rather than a new one being allocated. Callers "
            "rendering a setup script MUST NOT emit a `private-key=` line "
            "when this is true -- there is no key to emit, and the device's "
            "existing one is already correct."
        ),
    )
    hub_public_key: str
    hub_endpoint_host: str
    hub_endpoint_port: int
    tunnel_network_cidr: str
    # The hub's own address *inside* the tunnel (e.g. "10.20.0.1"), derived
    # from `tunnel_network_cidr` via validators.hub_reserved_ip -- distinct
    # from hub_endpoint_host, which is the hub's *public* address a router
    # dials to establish the tunnel in the first place. Callers that need
    # to reach the hub's own services (e.g. RADIUS) *through* the tunnel,
    # rather than dial the tunnel itself, need this address instead --
    # some sites' ISPs block RADIUS's own UDP ports (1812/1813) outbound
    # but never touch WireGuard's single UDP port, so pointing a router's
    # `/radius add address=...` at this address instead of the hub's
    # public IP is what actually gets RADIUS traffic through in that case.
    hub_tunnel_ip_address: str
    persistent_keepalive_seconds: int = DEFAULT_PERSISTENT_KEEPALIVE_SECONDS


class WireGuardTunnelRotateResponse(WireGuardTunnelCreateResponse):
    """Identical shape to ``WireGuardTunnelCreateResponse`` -- rotation
    returns exactly the same "everything needed to reconfigure the
    interface" bundle, just against the peer's new keypair."""


# ============================================================================
# Device-facing schemas (no ApiResponse envelope -- see module docstring)
# ============================================================================


class AgentWireGuardConfigResponse(BaseModel):
    """``GET /agent/wireguard-config`` -- the device's own private key plus
    everything needed to build a local WireGuard interface/peer block. See
    ``app.domains.router_agent.dependencies.CurrentAgent`` for the
    credential this endpoint is authenticated by (composed, not
    reimplemented -- see ``router.py``'s module docstring)."""

    router_id: str
    peer_public_key: str
    peer_private_key: str
    tunnel_ip_address: str
    tunnel_network_cidr: str
    hub_public_key: str
    hub_endpoint_host: str
    hub_endpoint_port: int
    persistent_keepalive_seconds: int = DEFAULT_PERSISTENT_KEEPALIVE_SECONDS


class AgentWireGuardHandshakeResponse(BaseModel):
    """``POST /agent/wireguard-config/handshake`` -- device-reported
    liveness signal (see ``service.py``'s ``record_handshake``)."""

    router_id: str
    last_handshake_at: datetime
