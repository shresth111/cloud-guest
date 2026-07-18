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
