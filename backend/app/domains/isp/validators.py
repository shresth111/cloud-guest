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
    IspConnectionMode,
    WanRoutingMode,
)
from .exceptions import IspLinkInterfaceInvariantError, MixedWanRoutingWeightsError


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


def derive_pppoe_routing_interface(*, wan_slot: int) -> str:
    """Return the canonical PPPoE virtual interface name for a WAN slot.

    ``wan_slot`` is 1-based (WAN1 → ``pppoe-wan1``).
    """
    if wan_slot < 1:
        raise ValueError("wan_slot must be >= 1")
    return f"pppoe-wan{wan_slot}"


def normalize_isp_link_interfaces(
    *,
    connection_mode: str,
    interface: str | None = None,
    physical_interface: str | None = None,
    routing_interface: str | None = None,
    pppoe_username: str | None = None,
    has_pppoe_password: bool = False,
    wan_slot: int = 1,
    is_create: bool = False,
) -> tuple[str | None, str | None, str | None]:
    """Resolve physical/routing/legacy ``interface`` fields for persistence.

    Returns ``(physical_interface, routing_interface, legacy_interface)``
    where ``legacy_interface`` is kept equal to ``routing_interface`` so
    existing health-check and netwatch code that reads ``interface`` keeps
    working without modification in this step.

  Invariants (enforced here, not DB CHECK constraints):
    * static/dhcp: ``routing_interface == physical_interface`` (both required).
    * pppoe: physical required; routing defaults to ``pppoe-wan{wan_slot}``
      unless explicitly provided; username + password required on create.
    """
    mode = IspConnectionMode(connection_mode)
    physical = (physical_interface or "").strip() or None
    legacy_interface = (interface or "").strip() or None
    routing = (routing_interface or "").strip() or None

    if not physical and not routing and not legacy_interface:
        if (
            mode is IspConnectionMode.PPPOE
            and is_create
            and (pppoe_username or has_pppoe_password)
        ):
            raise IspLinkInterfaceInvariantError(
                "PPPoE links require physical_interface (or interface) "
                "when credentials are supplied"
            )
        return None, None, None
    if mode in (IspConnectionMode.STATIC, IspConnectionMode.DHCP):
        resolved_physical = physical or legacy_interface
        if not resolved_physical:
            return None, None, None
        if routing and routing != resolved_physical:
            raise IspLinkInterfaceInvariantError(
                f"{mode.value} links must have routing_interface equal to "
                "physical_interface"
            )
        return resolved_physical, resolved_physical, resolved_physical

    if mode is IspConnectionMode.PPPOE:
        if physical:
            if not routing:
                routing = derive_pppoe_routing_interface(wan_slot=wan_slot)
            legacy = routing
        elif legacy_interface:
            # Legacy callers stored the virtual PPPoE client name in
            # ``interface`` (e.g. ``pppoe-out1``) with no physical split.
            routing = routing or legacy_interface
            legacy = legacy_interface
        else:
            raise IspLinkInterfaceInvariantError(
                "PPPoE links require physical_interface (or interface)"
            )
        if is_create and (pppoe_username or has_pppoe_password):
            if not pppoe_username:
                raise IspLinkInterfaceInvariantError(
                    "PPPoE links require pppoe_username when a password is supplied"
                )
            if not has_pppoe_password:
                raise IspLinkInterfaceInvariantError(
                    "PPPoE links require pppoe_password when a username is supplied"
                )
        return physical, routing, legacy

    raise IspLinkInterfaceInvariantError(
        f"Unsupported connection_mode: {connection_mode}"
    )


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
    "derive_pppoe_routing_interface",
    "is_failover_threshold_reached",
    "normalize_isp_link_interfaces",
    "validate_wan_routing_weights",
]
