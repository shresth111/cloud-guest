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

from .constants import DEFAULT_PERSISTENT_KEEPALIVE_SECONDS, HealthStatus, PeerStatus

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


class WireGuardTunnelCreateResponse(WireGuardPeerResponse):
    """Returned by ``POST /routers/{id}/wireguard-peer`` -- additionally
    carries everything needed to manually configure the device's local
    WireGuard interface, for the (hopefully rare) case zero-touch delivery
    via ``GET /agent/wireguard-config`` cannot reach the device."""

    peer_private_key: str = Field(
        description="The peer's own private key, decrypted -- see service.py "
        "docstring for why this remains retrievable, unlike a one-time token."
    )
    hub_public_key: str
    hub_endpoint_host: str
    hub_endpoint_port: int
    tunnel_network_cidr: str
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
