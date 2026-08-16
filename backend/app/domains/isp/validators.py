"""Pure, side-effect-free validation/classification for the ISP Management
domain.

Mirrors ``app.domains.guest.validators``/``app.domains.voucher
.validators``'s identical discipline: no I/O, just "is this a legal input"
or "what does this measurement mean" checks the service layer calls before
touching the database or acting on a health-check result.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence

from .constants import (
    DEFAULT_LATENCY_DEGRADED_THRESHOLD_MS,
    DEFAULT_LATENCY_UNHEALTHY_THRESHOLD_MS,
    DEFAULT_PACKET_LOSS_DEGRADED_THRESHOLD_PERCENT,
    DEFAULT_PACKET_LOSS_UNHEALTHY_THRESHOLD_PERCENT,
    HealthStatus,
    WanRoutingMode,
)
from .exceptions import MixedWanRoutingWeightsError


def classify_health_status(
    *,
    latency_ms: float | None,
    packet_loss_percentage: float | None,
    latency_degraded_threshold_ms: float = DEFAULT_LATENCY_DEGRADED_THRESHOLD_MS,
    latency_unhealthy_threshold_ms: float = DEFAULT_LATENCY_UNHEALTHY_THRESHOLD_MS,
    packet_loss_degraded_threshold_percent: float = (
        DEFAULT_PACKET_LOSS_DEGRADED_THRESHOLD_PERCENT
    ),
    packet_loss_unhealthy_threshold_percent: float = (
        DEFAULT_PACKET_LOSS_UNHEALTHY_THRESHOLD_PERCENT
    ),
) -> HealthStatus:
    """Classifies one health-check reading -- ``UNHEALTHY`` wins over
    ``DEGRADED`` wins over ``HEALTHY`` whenever *either* latency or packet
    loss crosses its own threshold (a link with great latency but 100%
    packet loss, or vice versa, is still genuinely unhealthy). ``None``
    values (the ping itself failed outright, e.g. no route to host) are
    treated as the worst case, ``UNHEALTHY`` -- a missing reading is never
    silently treated as "fine"."""
    if latency_ms is None or packet_loss_percentage is None:
        return HealthStatus.UNHEALTHY
    if (
        packet_loss_percentage >= packet_loss_unhealthy_threshold_percent
        or latency_ms >= latency_unhealthy_threshold_ms
    ):
        return HealthStatus.UNHEALTHY
    if (
        packet_loss_percentage >= packet_loss_degraded_threshold_percent
        or latency_ms >= latency_degraded_threshold_ms
    ):
        return HealthStatus.DEGRADED
    return HealthStatus.HEALTHY


def validate_wan_routing_weights(
    *,
    router_id: uuid.UUID,
    mode: WanRoutingMode,
    enabled_link_weights: Sequence[int | None],
) -> None:
    """Enforces "weight every enabled link or none of them" for a router
    in ``WanRoutingMode.LOAD_BALANCE`` -- called by the service layer
    before persisting a link's ``load_balance_weight`` or a router's
    ``wan_routing_mode``, with the *other* enabled links' current weights
    passed alongside the one being changed.

    A no-op for ``FAILOVER_ONLY`` (weights are simply unused in that mode,
    still storable so switching back to ``LOAD_BALANCE`` later doesn't
    lose prior tuning -- see ``WanRoutingMode``'s own docstring) and for
    fewer than two enabled links (a ratio is meaningless with one WAN).

    Rejects a *partial* weighting outright rather than silently treating
    the unweighted links as an even split among themselves -- that would
    make the actual on-device ratio depend on which links happen to have
    an explicit number today, a surprising, hard-to-audit outcome for
    something that directly controls how a customer's paid bandwidth is
    split. An admin must weight every enabled link at once (the UI's own
    ratio slider naturally does this) or leave all of them at ``None``
    for the existing, unweighted even-split behavior."""
    if mode is not WanRoutingMode.LOAD_BALANCE or len(enabled_link_weights) < 2:
        return
    has_any_weight = any(w is not None for w in enabled_link_weights)
    if not has_any_weight:
        return
    if not all(w is not None for w in enabled_link_weights):
        raise MixedWanRoutingWeightsError(router_id)
    if any(w <= 0 for w in enabled_link_weights if w is not None):
        raise ValueError("load_balance_weight must be a positive integer")


def is_failover_threshold_reached(
    *, consecutive_unhealthy_count: int, threshold: int
) -> bool:
    """Guest Session Engine's ``is_concurrent_session_limit_reached``/
    ``is_device_limit_reached`` establish the identical ``>=`` (not ``>``)
    convention this mirrors: a link that has *just reached* the configured
    consecutive-failure threshold has reached it, not merely "one more
    check away" from reaching it."""
    return consecutive_unhealthy_count >= threshold


__all__ = [
    "classify_health_status",
    "is_failover_threshold_reached",
    "validate_wan_routing_weights",
]
