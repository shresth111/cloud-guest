"""WireGuard domain exceptions.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide exception handler / ``ApiResponse`` envelope exactly like every
other domain's exception hierarchy does -- no route needs its own
try/except translation.
"""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError

__all__ = [
    "WireGuardError",
    "WireGuardServerNotFoundError",
    "NoActiveWireGuardServerError",
    "WireGuardPeerNotFoundError",
    "WireGuardPeerAlreadyExistsError",
    "WireGuardPeerRevokedError",
    "WireGuardPrivateKeyUnavailableError",
    "InvalidPeerStatusTransitionError",
    "WireGuardRouterNotEligibleError",
    "TunnelIPPoolExhaustedError",
    "TunnelIPAllocationConflictError",
    "InvalidWireGuardCidrError",
]


class WireGuardError(CloudGuestError):
    """Base exception for WireGuard domain errors."""

    def __init__(self, message: str, *, status_code: int) -> None:
        super().__init__(message, status_code=status_code)


class WireGuardServerNotFoundError(WireGuardError):
    def __init__(self, identifier: object) -> None:
        super().__init__(
            f"WireGuard server not found: {identifier}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class NoActiveWireGuardServerError(WireGuardError):
    """Raised when a tunnel operation needs an active hub
    (``WireGuardServer.is_active``) but none is configured -- an
    operational/bootstrap gap (the platform has not provisioned its hub
    yet), not a per-router error."""

    def __init__(self) -> None:
        super().__init__(
            "No active WireGuard server (hub) is configured",
            status_code=status.HTTP_409_CONFLICT,
        )


class HubPeerListerNotConfiguredError(WireGuardError):
    """``get_fleet_status`` has no ``hub_peer_lister`` injected.

    Unlike ``hub_peer_deregistrar`` (which `revoke_tunnel` silently skips
    when absent -- the database-side revoke is still meaningful on its
    own), a fleet-status read with no way to reach the hub has nothing
    real to return: the entire point of this call is comparing this
    table against the hub's own state, so a silent DB-only fallback would
    quietly reintroduce the exact "trusted the database alone" blind spot
    this feature exists to close."""

    def __init__(self) -> None:
        super().__init__(
            "The WireGuard hub bridge is not configured -- cannot read live fleet status",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )


class WireGuardPeerNotFoundError(WireGuardError):
    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Router {router_id} has no WireGuard tunnel/peer",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class WireGuardPeerAlreadyExistsError(WireGuardError):
    """A router already has an active (``pending``/``active``) peer -- this
    module rejects creating a second one rather than silently
    revoke-then-recreate, so an admin's explicit ``DELETE`` (revoke) is
    always the one place a tunnel teardown is decided. See
    ``service.py``'s module docstring for the full reasoning."""

    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Router {router_id} already has an active WireGuard tunnel -- "
            "revoke it first before creating a new one",
            status_code=status.HTTP_409_CONFLICT,
        )


class WireGuardPeerRevokedError(WireGuardError):
    """The peer exists but is ``revoked`` -- raised by operations
    (rotation, config pull, handshake reporting) that are only meaningful
    against a live tunnel."""

    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Router {router_id}'s WireGuard tunnel has been revoked",
            status_code=status.HTTP_409_CONFLICT,
        )


class WireGuardPrivateKeyUnavailableError(WireGuardError):
    """The peer's keypair is device-managed (its stored "private key" is
    ``service.EXTERNALLY_MANAGED_KEY_SENTINEL``, from the legacy
    device-generated-keypair enrollment) -- the platform never held a real
    private key for it, so the device-facing config pull has nothing
    genuine to deliver. Without this guard, ``GET /agent/wireguard-config``
    would serve the literal sentinel string as though it were a key and the
    device would install it as an invalid ``private-key=``. Re-running the
    current bootstrap script clears the condition: its check-in rotates the
    peer to a platform-generated pair first (see
    ``WireGuardService.ensure_tunnel_for_check_in``)."""

    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Router {router_id}'s WireGuard keypair is device-managed -- "
            "the platform holds no private key to deliver; re-run the "
            "bootstrap script to rotate to a platform-generated pair",
            status_code=status.HTTP_409_CONFLICT,
        )


class InvalidPeerStatusTransitionError(WireGuardError):
    """Raised when a requested status change is not a legal edge in
    ``app.domains.wireguard.constants.PEER_STATUS_TRANSITIONS``."""

    def __init__(self, current_status: str, requested_status: str) -> None:
        super().__init__(
            f"Cannot transition WireGuard peer from '{current_status}' to "
            f"'{requested_status}'",
            status_code=status.HTTP_409_CONFLICT,
        )


class WireGuardRouterNotEligibleError(WireGuardError):
    """The router itself is ``decommissioned``/``suspended`` -- composes
    with BE-008's own ``RouterStatus``, not a new lifecycle of its own
    (mirrors ``app.domains.router_agent.exceptions
    .AgentRouterNotEligibleError``'s identical reasoning)."""

    def __init__(self, router_id: uuid.UUID, current_status: str) -> None:
        super().__init__(
            f"Router {router_id} in status '{current_status}' cannot have a "
            "WireGuard tunnel",
            status_code=status.HTTP_409_CONFLICT,
        )


class TunnelIPPoolExhaustedError(WireGuardError):
    """Every usable host address in the hub's ``tunnel_network_cidr`` is
    already allocated to a non-revoked peer."""

    def __init__(self, cidr: str) -> None:
        super().__init__(
            f"No free tunnel IP addresses remain in {cidr}",
            status_code=status.HTTP_409_CONFLICT,
        )


class TunnelIPAllocationConflictError(WireGuardError):
    """Two concurrent allocation attempts raced for the same address and
    this one lost (the database's own unique constraint on
    ``(server_id, tunnel_ip_address)`` is the actual race-safety net -- see
    ``service.py``'s module docstring). The caller should simply retry the
    request."""

    def __init__(self) -> None:
        super().__init__(
            "Tunnel IP allocation conflict -- please retry",
            status_code=status.HTTP_409_CONFLICT,
        )


class InvalidWireGuardCidrError(WireGuardError):
    def __init__(self, cidr: str) -> None:
        super().__init__(
            f"'{cidr}' is not a valid IPv4/IPv6 network CIDR",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
