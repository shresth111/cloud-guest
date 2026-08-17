"""A small, reusable WireGuard-tunnel-state diagnostic for any domain that
attempts a *live* device connection over a router's WireGuard tunnel and
wants to tell an operator *why* a generic connection failure happened,
rather than surfacing a bare timeout with no actionable next step.

## Why this exists (confirmed production incident, 2026-08-14)

Router "R3" had a WireGuard peer stuck in ``status='pending'`` with
``last_handshake_at=NULL`` -- the tunnel had never handshaked. Every
domain that tries to reach that router over its tunnel IP failed with a
generic connect-timeout error (Master Console's Device Console surfaced
"Could not connect to device at '10.20.0.45': " -- see
``mikrotik_adapter._describe_exception`` for the separate, related
empty-detail bug this incident also exposed). An operator staring at that
message has no way to know WireGuard is even involved without manually
cross-referencing the ``routers`` and ``wireguard_peers`` tables -- exactly
what this module exists to make automatic.

## Composition, not duplication, with ``readiness``

``app.domains.readiness.service.ReadinessService._check_wireguard`` (built
the same day as this incident) already contains the exact state
classification this module needs: no peer configured / never handshaked /
stale / revoked / healthy, derived from ``WireGuardService.get_peer`` +
``.compute_health_status``. This module extracts that classification into
one small, standalone function so a connection-failure handler can reuse
it without depending on the readiness domain (whose own job -- persisting
checklist rows -- has nothing to do with error messages) and without
reimplementing peer-lookup/health logic a third time. Composes against
``app.domains.wireguard`` through the same narrow, duck-typed
``WireGuardTunnelLookupProtocol`` convention every other domain in this
codebase uses for cross-domain reads.

## Why ``attempted_host`` matters

A router's ``management_ip_address`` is an operator-set field, not
something the platform enforces to equal its WireGuard peer's
``tunnel_ip_address`` -- some routers are managed over a public IP or LAN
address with no WireGuard tunnel involved at all. Blaming WireGuard for a
connection failure that was never attempted over the tunnel would be a
real, separate misdiagnosis bug of its own kind, so this module only
returns a WireGuard explanation when the failed connection's own
``host`` matches the router's actual tunnel IP -- otherwise it returns
``None`` (do not mention WireGuard) and the caller's original error
message is left untouched.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Protocol

from .constants import HealthStatus
from .exceptions import WireGuardPeerNotFoundError

__all__ = ["WireGuardTunnelLookupProtocol", "TunnelState", "diagnose_connection_failure"]


class WireGuardTunnelLookupProtocol(Protocol):
    """The subset of ``WireGuardService``'s own surface this module needs
    -- identical to ``app.domains.readiness.service.WireGuardLookupProtocol``,
    duplicated rather than imported cross-domain (readiness composes
    *its* dependencies the same narrow way; this module is the sibling
    doing the same thing for a different caller)."""

    async def get_peer(
        self, *, router_id: uuid.UUID, requesting_organization_id: uuid.UUID | None
    ) -> object: ...

    def compute_health_status(self, peer: object, *, now: datetime | None = None) -> object: ...


class TunnelState:
    """Every value ``diagnose_connection_failure`` can classify a tunnel
    into, plus the healthy/never-handshaked/stale/revoked shorthand a
    caller may want for logging or metrics without string-matching the
    message text."""

    NOT_APPLICABLE = "not_applicable"  # no tunnel configured, or this
    # connection wasn't attempted over the tunnel's own IP -- WireGuard is
    # not implicated, caller's original message should stand unchanged.
    NEVER_HANDSHAKED = "never_handshaked"
    STALE = "stale"
    REVOKED = "revoked"
    HEALTHY = "healthy"


def diagnose_connection_failure(
    *, health_status: object, tunnel_matches_attempted_host: bool
) -> tuple[str, str | None]:
    """Pure classification step, given an already-computed
    ``HealthStatus`` and whether the failed connection's host matches the
    peer's tunnel IP. Returns ``(TunnelState.*, message_or_none)`` --
    ``message`` is ``None`` exactly when ``state == NOT_APPLICABLE``.

    Split out from ``diagnose_router_connection_failure`` (the real,
    I/O-performing entry point below) purely so the state-to-message
    mapping is trivially unit-testable without a fake repository/service
    -- the same "pure core, thin I/O shell" split ``validators.py`` uses
    elsewhere in this domain."""
    if not tunnel_matches_attempted_host:
        return TunnelState.NOT_APPLICABLE, None

    value = getattr(health_status, "value", str(health_status))
    if value == HealthStatus.HEALTHY.value:
        return (
            TunnelState.HEALTHY,
            "Its WireGuard tunnel is healthy and recently handshaked, so "
            "this looks like a different problem -- not a tunnel issue. "
            "Check the device's own credentials, load, or service status "
            "instead.",
        )
    if value == HealthStatus.UNKNOWN.value:
        return (
            TunnelState.NEVER_HANDSHAKED,
            "Can't reach this router: its WireGuard tunnel has never "
            "completed a handshake. Check the router's WAN is up and UDP "
            "isn't blocked before troubleshooting anything else.",
        )
    if value == HealthStatus.STALE.value:
        return (
            TunnelState.STALE,
            "Can't reach this router: its WireGuard tunnel handshaked "
            "before but hasn't recently, so it looks disconnected right "
            "now. Check the router's WAN is up and UDP isn't blocked "
            "before troubleshooting anything else.",
        )
    if value == HealthStatus.REVOKED.value:
        return (
            TunnelState.REVOKED,
            "Can't reach this router: its WireGuard tunnel was revoked, "
            "so the device currently has no way to reach the platform. "
            "Issue it a fresh tunnel before troubleshooting anything "
            "else.",
        )
    # Unrecognized future HealthStatus value -- fail open to "not
    # applicable" rather than fabricate a message for a state this
    # module doesn't know about yet.
    return TunnelState.NOT_APPLICABLE, None


async def diagnose_router_connection_failure(
    wireguard_lookup: WireGuardTunnelLookupProtocol,
    *,
    router_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None,
    attempted_host: str | None,
) -> tuple[str, str | None]:
    """The real, I/O-performing entry point: looks up ``router_id``'s
    WireGuard peer (if any) and classifies it via
    ``diagnose_connection_failure`` above. Returns
    ``(TunnelState.*, message_or_none)`` -- callers append/prepend
    ``message`` to their own generic connection-failure text when it is
    not ``None``; when it is ``None`` (``TunnelState.NOT_APPLICABLE``),
    WireGuard is not implicated and the caller's original message should
    be left exactly as it was.
    """
    try:
        peer = await wireguard_lookup.get_peer(
            router_id=router_id, requesting_organization_id=requesting_organization_id
        )
    except WireGuardPeerNotFoundError:
        return TunnelState.NOT_APPLICABLE, None

    tunnel_matches = bool(attempted_host) and attempted_host == peer.tunnel_ip_address
    health_status = wireguard_lookup.compute_health_status(peer)
    return diagnose_connection_failure(
        health_status=health_status, tunnel_matches_attempted_host=tunnel_matches
    )
