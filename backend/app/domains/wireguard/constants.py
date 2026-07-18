"""Enumerations and small constants for the WireGuard domain.

Stored as plain ``String`` columns on the ORM models (``WireGuardPeer.status``),
never a native PostgreSQL enum type -- the same reason every other domain in
this codebase documents (``app.domains.router.enums``, ``app.domains
.router_agent.constants``): adding a new value never requires an
``ALTER TYPE`` migration.
"""

from __future__ import annotations

from enum import StrEnum

# ============================================================================
# WireGuard key material
# ============================================================================

# WireGuard keys are Curve25519 (X25519) keys: 32 raw bytes, presented
# base64-encoded (44 characters with the trailing '=' padding) -- exactly
# what ``wg genkey``/``wg pubkey`` produce. See ``service.py``'s module
# docstring for why ``cryptography``'s ``X25519PrivateKey``/``X25519PublicKey``
# (already a transitive capability of the ``cryptography`` package this
# codebase depends on for Fernet, see ``app.domains.router.crypto``) are
# reused here rather than adding a new dependency.
WIREGUARD_KEY_RAW_BYTES = 32

# ============================================================================
# Tunnel IP allocation
# ============================================================================

# How many of a hub's leading usable host addresses (per
# ``WireGuardServer.tunnel_network_cidr``) are reserved and never handed out
# to a peer. The hub itself is conventionally assigned the network's first
# usable host address (e.g. ``10.100.0.1`` for ``10.100.0.0/16``) for its own
# WireGuard interface -- this constant keeps the allocator
# (``validators.allocate_tunnel_ip``) from ever double-assigning that address
# to a router peer. A single reserved slot is enough for the single-hub
# design this module ships with (see ``models.WireGuardServer``'s module
# docstring); a future multi-hub-per-CIDR design is not something this
# constant needs to anticipate.
HUB_RESERVED_HOST_COUNT = 1

# Default WireGuard UDP listen port for a newly-created hub, matching the
# upstream project's own conventional default -- purely a sensible starting
# value for ``WireGuardServer.endpoint_port``, not enforced anywhere.
DEFAULT_WIREGUARD_PORT = 51820

# The ``PersistentKeepalive`` value (seconds) this module recommends every
# device-facing config pull embed in the peer's local WireGuard interface
# config. Non-zero and fairly short (WireGuard's own docs suggest 25s for
# peers behind NAT) because the entire reason this module exists is routers
# sitting behind carrier-grade NAT with no public IP -- without a
# persistent keepalive, the NAT mapping the hub is relying on to reach the
# router back would silently expire between handshakes.
DEFAULT_PERSISTENT_KEEPALIVE_SECONDS = 25


class PeerStatus(StrEnum):
    """Lifecycle status of a :class:`~.models.WireGuardPeer`.

    * ``PENDING`` -- the platform has generated a keypair, allocated a
      tunnel IP, and created the peer row, but the device has not yet
      fetched its configuration (``GET /agent/wireguard-config``) even
      once. This is the only status a freshly-created or freshly-rotated
      peer starts in.
    * ``ACTIVE`` -- the device has successfully pulled its configuration at
      least once (or reported a handshake directly), meaning it has (or
      very recently had) everything it needs to bring its local WireGuard
      interface up. This is a "delivered/in-use" signal, distinct from
      *currently connected* -- see ``last_handshake_at``/health-status
      derivation in ``service.py`` for the separate, time-based
      connectivity signal.
    * ``REVOKED`` -- administratively torn down. Terminal: the tunnel IP is
      considered free for reuse (excluded from
      ``validators.allocate_tunnel_ip``'s occupancy check) and the device's
      credential-bound identity can no longer pull a config for it. Not
      transitioned out of directly -- see ``PEER_STATUS_TRANSITIONS`` and
      ``WireGuardService.create_tunnel`` for how a revoked router gets a
      fresh peer again (the same row is reused, reset back to ``PENDING``).
    """

    PENDING = "pending"
    ACTIVE = "active"
    REVOKED = "revoked"


# The explicit, exhaustive legal-transition graph -- mirrors
# ``app.domains.router.enums.ROUTER_STATUS_TRANSITIONS``'s own convention:
# any status change not listed here is rejected by ``WireGuardService`` with
# ``InvalidPeerStatusTransitionError``.
#
# ``ACTIVE -> PENDING`` is an intentional, additive edge for key rotation
# (``WireGuardService.rotate_tunnel``): rotating a peer's keypair genuinely
# invalidates whatever connectivity evidence justified ``ACTIVE`` (the
# device's old private key no longer matches what the hub expects), so the
# peer goes back to "delivered a config, not yet confirmed" until the device
# re-pulls and re-handshakes. See ``service.py``'s module docstring for why
# tunnel rotation and key rotation are the same operation in this design.
PEER_STATUS_TRANSITIONS: dict[PeerStatus, frozenset[PeerStatus]] = {
    PeerStatus.PENDING: frozenset({PeerStatus.ACTIVE, PeerStatus.REVOKED}),
    PeerStatus.ACTIVE: frozenset({PeerStatus.PENDING, PeerStatus.REVOKED}),
    PeerStatus.REVOKED: frozenset(),
}


class HealthStatus(StrEnum):
    """A read-time-computed (never persisted) connectivity signal for a
    peer, derived from ``WireGuardPeer.last_handshake_at`` against
    ``Settings.wireguard_handshake_stale_after_minutes`` -- see
    ``service.py``'s ``WireGuardService.compute_health_status``.

    Deliberately not persisted as a column (unlike ``Router.health_status``,
    which BE-008 does persist) -- a peer's health is a pure function of
    "how long ago was the last handshake" plus the current time, so storing
    it would only ever risk drifting stale between reads; computing it at
    response-build time is strictly simpler and always correct. This is a
    DB-tracked, device-*reported* signal, not a live ``wg show`` integration
    -- see the module-level docs (``docs/wireguard/README.md``) for the
    same honest "interim design" posture BE-008/BE-009 already establish for
    their own simulated health/provisioning.
    """

    HEALTHY = "healthy"
    STALE = "stale"
    UNKNOWN = "unknown"
    REVOKED = "revoked"


__all__ = [
    "WIREGUARD_KEY_RAW_BYTES",
    "HUB_RESERVED_HOST_COUNT",
    "DEFAULT_WIREGUARD_PORT",
    "DEFAULT_PERSISTENT_KEEPALIVE_SECONDS",
    "PeerStatus",
    "PEER_STATUS_TRANSITIONS",
    "HealthStatus",
]
