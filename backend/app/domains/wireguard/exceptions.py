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
    "HubPeerListerNotConfiguredError",
    "HubCannotLearnPlatformKeyError",
    "HubPeerRemovalUnsupportedError",
    "HubPeerNotOnHubError",
    "HubPeerClaimedByAnotherRouterError",
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
            "The WireGuard hub bridge is not configured -- cannot read live "
            "fleet status",
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


class HubCannotLearnPlatformKeyError(WireGuardError):
    """The operation would write a platform-generated public key that this
    hub has no verb to be told about, so the tunnel it describes could
    never come up.

    This is the honest name for a gap that has been silently producing
    broken tunnels. ``ops/hub-agents/wg_agent.py`` exposes ``POST
    /wg/peer``, which *generates its own keypair* and returns it, and
    ``GET /wg/peers``. There is no endpoint that accepts a public key the
    caller already has. So ``create_tunnel``/``rotate_tunnel``'s
    ``generate_wireguard_keypair()`` path writes a key that exists in
    exactly one place -- this database -- and the hub goes on expecting the
    old one.

    Confirmed live 2026-08-27 on router 21e13913: three console
    "Generate" clicks each ran ``POST /routers/provisioning/check-in``,
    which rotated the peer to a fresh platform keypair
    (``XdLGb1sx...``, ``rP4Bjge...``, ``Tytu4dAc...``), none of which ever
    appeared in ``GET /wg/peers``. Each was then immediately superseded by
    a hub-allocated peer, so the damage was masked -- but for the seconds
    between them the platform's record of that router's identity was a key
    no WireGuard implementation anywhere held.

    Raised rather than logged because there is a real, correct action the
    caller can take instead (allocate through the hub bridge, which is the
    only path that produces a key both sides know), and silently writing
    the unusable key is what hid this for months. Lifts automatically the
    moment the hub gains a registration verb -- see
    ``service.HubCapabilities``."""

    def __init__(self, operation: str) -> None:
        super().__init__(
            f"{operation} would generate a WireGuard keypair on the platform "
            "side, but the hub agent has no verb to be told a public key it "
            "did not generate itself -- the resulting tunnel could never "
            "establish. Allocate through the hub bridge instead "
            "(POST /routers/{router_id}/wireguard-peer/allocate-external).",
            status_code=status.HTTP_409_CONFLICT,
        )


class HubPeerRemovalUnsupportedError(WireGuardError):
    """The hub cannot be told to drop a peer, and the caller needed it to.

    Distinct from ``dependencies.HubBridgeUnavailableError`` on purpose,
    and the distinction is the whole point: "the bridge could not be
    reached" is transient and worth retrying, while "the bridge does not
    implement this verb" is a permanent property of the deployed agent
    that no retry will change. Collapsing the two is what let a ``501
    Unsupported method ('DELETE')`` be logged, once per orphaned peer, as
    though it were a blip.

    Everything that can degrade honestly around this does so instead of
    raising -- see ``WireGuardService.revoke_tunnel``, which now quarantines
    the address rather than refusing to revoke at all. This exists for the
    paths where continuing really would be a lie."""

    def __init__(self, public_key: str) -> None:
        super().__init__(
            "The WireGuard hub agent has no peer-removal verb deployed, so "
            f"peer {public_key[:16]}... cannot be removed from it. This is a "
            "capability gap on the hub, not a transient failure -- see "
            "ops/hub-agents/wg_agent.py's do_DELETE, which is written and "
            "waiting on shell access to that host.",
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
        )


class HubPeerNotOnHubError(WireGuardError):
    """Adoption was asked to record an identity the hub does not actually
    have. Refused, because adoption's entire justification is that it
    writes down something demonstrably true -- adopting a key ``GET
    /wg/peers`` has never heard of would just be a differently-wrong row."""

    def __init__(self, public_key: str) -> None:
        super().__init__(
            f"The hub has no peer with public key {public_key[:16]}... -- "
            "there is nothing to adopt. Check GET /wireguard/fleet-status "
            "for what the hub actually holds.",
            status_code=status.HTTP_409_CONFLICT,
        )


class HubPeerClaimedByAnotherRouterError(WireGuardError):
    """The key being adopted is already this platform's record of a
    *different* router's peer. Two routers sharing one WireGuard identity
    is not a state worth reaching by accident: the hub routes by
    ``allowed-ips``, so the second one silently steals the first one's
    traffic."""

    def __init__(self, public_key: str, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Public key {public_key[:16]}... is already recorded as router "
            f"{router_id}'s peer -- adopting it here would give two routers "
            "one tunnel identity. Revoke the other router's peer first if "
            "this device has genuinely taken over its identity.",
            status_code=status.HTTP_409_CONFLICT,
        )
