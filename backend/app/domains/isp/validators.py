"""Pure, side-effect-free validation/classification for the ISP Management
domain.

Mirrors ``app.domains.guest.validators``/``app.domains.voucher
.validators``'s identical discipline: no I/O, just "is this a legal input"
or "what does this measurement mean" checks the service layer calls before
touching the database or acting on a health-check result.
"""

from __future__ import annotations

from .constants import (
    DEFAULT_LATENCY_DEGRADED_THRESHOLD_MS,
    DEFAULT_LATENCY_UNHEALTHY_THRESHOLD_MS,
    DEFAULT_PACKET_LOSS_DEGRADED_THRESHOLD_PERCENT,
    DEFAULT_PACKET_LOSS_UNHEALTHY_THRESHOLD_PERCENT,
    HealthStatus,
)


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


def is_failover_threshold_reached(
    *, consecutive_unhealthy_count: int, threshold: int
) -> bool:
    """Guest Session Engine's ``is_concurrent_session_limit_reached``/
    ``is_device_limit_reached`` establish the identical ``>=`` (not ``>``)
    convention this mirrors: a link that has *just reached* the configured
    consecutive-failure threshold has reached it, not merely "one more
    check away" from reaching it."""
    return consecutive_unhealthy_count >= threshold


__all__ = ["classify_health_status", "is_failover_threshold_reached"]
