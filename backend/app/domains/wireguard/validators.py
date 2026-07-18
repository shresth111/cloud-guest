"""Pure, side-effect-free business-rule checks for the WireGuard domain.

Every function here takes an already-fetched model instance (or plain
value) and either returns a value or raises one of this module's own
``exceptions`` -- none of these functions perform I/O, mirroring
``app.domains.router_provisioning.validators``/``app.domains.router_agent
.validators``'s identical discipline of keeping "what is a legal state (or
address)" centralized and directly unit-testable in isolation from any
database or event loop.
"""

from __future__ import annotations

import ipaddress

from app.domains.router.enums import RouterStatus
from app.domains.router.models import Router

from .constants import HUB_RESERVED_HOST_COUNT, PEER_STATUS_TRANSITIONS, PeerStatus
from .exceptions import (
    InvalidPeerStatusTransitionError,
    InvalidWireGuardCidrError,
    TunnelIPPoolExhaustedError,
    WireGuardRouterNotEligibleError,
)

# A router in either of these BE-008 lifecycle statuses has no business
# holding a WireGuard tunnel: a decommissioned router is permanently
# retired, and a suspended router is administratively frozen pending human
# action -- identical reasoning to ``app.domains.router_agent.validators
# ._ROUTER_STATUSES_INELIGIBLE_FOR_AGENT``.
_ROUTER_STATUSES_INELIGIBLE_FOR_WIREGUARD = frozenset(
    {RouterStatus.DECOMMISSIONED.value, RouterStatus.SUSPENDED.value}
)


def validate_router_eligible_for_wireguard(router: Router) -> None:
    if router.status in _ROUTER_STATUSES_INELIGIBLE_FOR_WIREGUARD:
        raise WireGuardRouterNotEligibleError(router.id, router.status)


def validate_peer_transition(current_status: str, new_status: PeerStatus) -> None:
    """Consults the exhaustive ``PEER_STATUS_TRANSITIONS`` graph -- mirrors
    ``RouterService._validate_transition``'s identical discipline (no
    "same status is a no-op" shortcut: revoking an already-revoked peer
    must raise, since ``REVOKED`` has no outgoing edges at all)."""
    current = PeerStatus(current_status)
    legal_targets = PEER_STATUS_TRANSITIONS.get(current, frozenset())
    if new_status not in legal_targets:
        raise InvalidPeerStatusTransitionError(current.value, new_status.value)


def validate_cidr(cidr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Parses ``cidr`` into an :mod:`ipaddress` network object, raising
    ``InvalidWireGuardCidrError`` if it is malformed. ``strict=True`` (the
    default) rejects a CIDR whose host bits are set (e.g. ``10.0.0.5/16``
    instead of ``10.0.0.0/16``) -- a hub's tunnel network should always be
    given as a clean network address, catching a copy-paste mistake at hub
    -creation time rather than silently truncating it."""
    try:
        return ipaddress.ip_network(cidr, strict=True)
    except (ValueError, TypeError) as exc:
        raise InvalidWireGuardCidrError(cidr) from exc


def allocate_tunnel_ip(cidr: str, occupied: set[str]) -> str:
    """Returns the next free host address in ``cidr`` not present in
    ``occupied``, skipping the hub's own reserved address(es) (see
    ``constants.HUB_RESERVED_HOST_COUNT``). Raises
    ``TunnelIPPoolExhaustedError`` if every remaining candidate is taken.

    **Algorithm and complexity.** Uses stdlib :mod:`ipaddress` (no new
    dependency): ``ip_network(cidr).hosts()`` already excludes the network
    and broadcast addresses for a normal-sized subnet, so the only extra
    exclusion this function applies is the hub's own reserved leading
    address(es). It walks candidates in address order and returns the first
    free one, so the common case (a mostly-empty pool) is fast; the
    worst case (a nearly-exhausted pool) is O(pool size) -- acceptable for
    this platform's expected per-hub peer counts (thousands, not millions of
    routers) and this sandbox's synchronous test usage. A production
    deployment with a very large CIDR and heavy churn would want a
    dedicated free-list/bitmap rather than a linear scan; that optimization
    is not implemented here.

    **Concurrency.** This function itself has no notion of "in progress"
    allocations -- it is a pure function of "what does the caller currently
    consider occupied". Real race-safety comes from the database: the
    ``(server_id, tunnel_ip_address)`` unique constraint on
    ``WireGuardPeer`` guarantees two concurrent requests can never both
    successfully commit the same address, even if both independently
    computed it as "next free" from a stale read. ``WireGuardService``
    catches that resulting integrity conflict and retries allocation a
    bounded number of times before surfacing
    ``TunnelIPAllocationConflictError`` -- see its module docstring for the
    full reasoning. No explicit row lock (``SELECT ... FOR UPDATE`` on the
    hub) is taken; that would be the natural next step for a
    higher-contention production deployment.
    """
    network = validate_cidr(cidr)
    hosts = network.hosts()
    for _ in range(HUB_RESERVED_HOST_COUNT):
        next(hosts, None)
    for candidate in hosts:
        candidate_str = str(candidate)
        if candidate_str not in occupied:
            return candidate_str
    raise TunnelIPPoolExhaustedError(cidr)


__all__ = [
    "validate_router_eligible_for_wireguard",
    "validate_peer_transition",
    "validate_cidr",
    "allocate_tunnel_ip",
]
