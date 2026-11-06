"""Pure, side-effect-free validation logic for the Queue Management Engine
domain -- mirrors ``app.domains.policy.validators``/
``app.domains.router_provisioning.validators``'s own identical "no I/O, no
repository access, just shape/transition checks" convention.
"""

from __future__ import annotations

import ipaddress
import uuid

from .constants import (
    DEVICE_BOUND_TARGET_TYPES,
    QUEUE_STATUS_TRANSITIONS,
    QueueStatus,
    QueueTargetType,
)
from .exceptions import (
    InvalidQueueStatusTransitionError,
    QueueTargetIdNotAllowedError,
    QueueTargetIdRequiredError,
    QueueTargetRouterRequiredError,
)


def validate_target(
    *,
    target_type: QueueTargetType,
    target_id: uuid.UUID | None,
    router_id: uuid.UUID | None,
) -> None:
    """Enforces ``constants.QueueTargetType``'s own polymorphic shape rule
    (mirrors ``app.domains.policy.validators``'s identical
    ``PolicyAssignment.scope_id`` nullability check): ``target_id`` is
    required for every target type except ``ORGANIZATION``, and forbidden
    for ``ORGANIZATION`` itself; ``router_id`` is required for every
    device-bound target type (see
    ``constants.DEVICE_BOUND_TARGET_TYPES``)."""
    if target_type == QueueTargetType.ORGANIZATION:
        if target_id is not None:
            raise QueueTargetIdNotAllowedError()
    elif target_id is None:
        raise QueueTargetIdRequiredError(target_type.value)

    if target_type in DEVICE_BOUND_TARGET_TYPES and router_id is None:
        raise QueueTargetRouterRequiredError(target_type.value)


def validate_status_transition(*, current: QueueStatus, target: QueueStatus) -> None:
    """Consults the exhaustive ``QUEUE_STATUS_TRANSITIONS`` graph.
    Deliberately has no "same status is a no-op" shortcut -- mirrors every
    other domain's identical status-machine discipline in this codebase."""
    legal_targets = QUEUE_STATUS_TRANSITIONS.get(current, frozenset())
    if target not in legal_targets:
        raise InvalidQueueStatusTransitionError(current.value, target.value)


#: The only ranges a guest's own address on a venue LAN can come from.
#:
#: RFC 1918 and nothing else, deliberately. A RouterOS ``/queue simple``
#: matches traffic to and from one LAN-side address, so a target outside
#: these ranges cannot be a guest: it is the address the *internet* saw (the
#: venue's WAN address, or a phone on mobile data), and a queue written
#: against it sits on the router matching nothing. Loopback, link-local and
#: carrier-grade NAT space are excluded on purpose -- ``ip_address.is_private``
#: would have let the first two through.
_GUEST_LAN_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def routeros_guest_queue_target(
    address: str | None, *, router_addresses: tuple[str | None, ...] = ()
) -> str | None:
    """``address`` if a RouterOS ``/queue simple`` for one guest may target
    it, else ``None``.

    A session's recorded address has two possible sources: the LAN address
    the hotspot redirect handed the portal, or -- when the guest opened the
    portal without being redirected -- the source address of the HTTP
    request, which at any venue is the venue's public WAN address. Both
    land in the same column, and only the first is something a queue can
    match. This is the one place that tells them apart, and it answers
    ``None`` rather than guessing: no queue is better than a queue that
    reads as an applied speed limit and limits nobody.

    ``router_addresses`` are addresses known to belong to the router itself
    (its public and management addresses); a queue for a guest never
    targets those either.

    Pure: no I/O, never raises."""
    if not address:
        return None
    candidate = address.strip()
    # ``10.5.50.7/32`` is the same single host RouterOS itself prints, and
    # what the admin API has always accepted. Any other prefix is a subnet.
    host = candidate.removesuffix("/32")
    try:
        parsed = ipaddress.ip_address(host)
    except ValueError:
        return None
    if parsed.version != 4:
        return None
    if not any(parsed in network for network in _GUEST_LAN_NETWORKS):
        return None
    for own in router_addresses:
        if not own:
            continue
        try:
            if ipaddress.ip_address(own.strip()) == parsed:
                return None
        except ValueError:
            continue
    return candidate


__all__ = [
    "validate_target",
    "validate_status_transition",
    "routeros_guest_queue_target",
]
