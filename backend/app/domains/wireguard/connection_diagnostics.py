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

## Why a hint may now say nothing, or say "I don't know" (2026-09-06)

This module shipped confidently wrong hints twice in five minutes, on the
same router, for the same command, while that router was demonstrably
fine. Both failures are fixed here, and both were failures of *honesty*,
not of plumbing:

1. **A healthy tunnel used to produce a hint at all.** The
   ``HealthStatus.HEALTHY`` branch appended "this looks like a different
   problem -- not a tunnel issue. Check the device's own credentials,
   load, or service status instead." That sentence names three subsystems
   this module has not looked at and cannot see. It sent an operator to
   audit credentials and device load during a live-venue debug session
   when the real cause was the console dialling a filtered port. A
   healthy tunnel is evidence that WireGuard is *not* implicated -- it is
   not evidence about what is -- so the honest output is no hint at all,
   exactly as ``ProvisioningEngineService._enrich_connection_error``'s own
   docstring already promised ("the tunnel turns out to be healthy -- ...
   blaming WireGuard would be a misdiagnosis").

2. **The healthy/stale verdict oscillated on a healthy tunnel.**
   ``last_handshake_at`` is not a live reading. It is refreshed by the
   hub-reconciliation sweep, which runs every
   ``HUB_RECONCILIATION_SWEEP_INTERVAL_SECONDS`` = 300s, and the
   staleness window it is compared against
   (``Settings.wireguard_handshake_stale_after_minutes``) defaults to
   exactly 5 minutes as well. A window equal to the refresh interval
   classifies nothing: on a perfectly healthy tunnel the recorded age
   sawtooths from ~0s up past 300s and back on every sweep, so the verdict
   depends on where in the sweep cycle the operator happened to click, not
   on the tunnel. That is precisely how the same router read "stale, check
   your WAN and UDP" and then "healthy" five minutes later.

   The fix is not to widen the window -- ``HealthStatus`` has other
   consumers (readiness, fleet status, monitoring, analytics) whose own
   reasoning about 5 minutes is deliberate. It is for *this* module, the
   one that speaks to a human, to refuse to assert what its input cannot
   support: an age within one refresh interval of the threshold is
   reported as :attr:`TunnelState.UNCERTAIN`, in a message that states the
   measured age and the lag rather than prescribing a fix. Only an age
   beyond that band is called stale.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Protocol

from .constants import HealthStatus
from .exceptions import WireGuardPeerNotFoundError

__all__ = [
    "WireGuardTunnelLookupProtocol",
    "TunnelState",
    "HANDSHAKE_OBSERVATION_LAG",
    "diagnose_connection_failure",
]

# How far behind the truth ``WireGuardPeer.last_handshake_at`` can be while
# everything is working correctly -- i.e. the cadence of the slowest thing
# that refreshes it.
#
# Mirrors ``app.domains.hub_reconciliation.constants
# .HUB_RECONCILIATION_SWEEP_INTERVAL_SECONDS`` (300.0), the sweep that
# writes the hub's real ``wg show`` handshake times onto peer rows. Mirrored
# rather than imported, following the same cross-domain convention
# ``app.domains.monitoring.constants`` uses for
# ``Settings.wireguard_handshake_stale_after_minutes``;
# ``tests/unit/test_wireguard_connection_diagnostics.py`` asserts the two
# stay equal so the mirror cannot drift silently.
HANDSHAKE_OBSERVATION_LAG = timedelta(seconds=300)


class WireGuardTunnelLookupProtocol(Protocol):
    """The subset of ``WireGuardService``'s own surface this module needs
    -- identical to ``app.domains.readiness.service.WireGuardLookupProtocol``,
    duplicated rather than imported cross-domain (readiness composes
    *its* dependencies the same narrow way; this module is the sibling
    doing the same thing for a different caller)."""

    async def get_peer(
        self, *, router_id: uuid.UUID, requesting_organization_id: uuid.UUID | None
    ) -> object: ...

    def compute_health_status(
        self, peer: object, *, now: datetime | None = None
    ) -> object: ...

    # The window ``compute_health_status`` itself compares against
    # (``WireGuardService.handshake_stale_after``). Needed here so the
    # stale/uncertain boundary is drawn against the *same* threshold the
    # status was derived from rather than a second, independently-chosen
    # copy of it -- read defensively via ``getattr`` at the call site, so a
    # lookup that predates this attribute still works and simply never
    # reaches the confident-stale verdict.
    handshake_stale_after: timedelta


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
    HEALTHY = "healthy"  # carries no message: see the module docstring's
    # point 1. WireGuard is not implicated, and this module knows nothing
    # about what is.
    UNCERTAIN = "uncertain"  # the recorded handshake is old enough to be
    # called stale, but not by more than one refresh interval -- so "the
    # tunnel went quiet" and "the sweep hasn't run yet" are indistinguishable
    # from here. Says so, rather than picking one. See the module docstring's
    # point 2.


def _describe_duration(delta: timedelta) -> str:
    """A short, honest rendering of ``delta`` for an operator-facing
    sentence -- whole minutes once past a minute, whole seconds below."""
    seconds = int(max(delta.total_seconds(), 0))
    if seconds < 60:
        return f"{seconds} second{'' if seconds == 1 else 's'}"
    minutes = seconds // 60
    return f"{minutes} minute{'' if minutes == 1 else 's'}"


def diagnose_connection_failure(
    *,
    health_status: object,
    tunnel_matches_attempted_host: bool,
    handshake_age: timedelta | None = None,
    stale_after: timedelta | None = None,
) -> tuple[str, str | None]:
    """Pure classification step, given an already-computed
    ``HealthStatus``, whether the failed connection's host matches the
    peer's tunnel IP, and (optionally) how old the recorded handshake
    actually is together with the window it was judged against. Returns
    ``(TunnelState.*, message_or_none)``.

    ``message`` is ``None`` for ``NOT_APPLICABLE`` **and for ``HEALTHY``**:
    a healthy tunnel means WireGuard is not implicated, which is not the
    same as knowing what is, and the previous wording ("check the device's
    own credentials, load, or service status instead") asserted the latter.
    See the module docstring's point 1.

    ``handshake_age``/``stale_after`` are what separate a *confidently*
    stale tunnel from one whose record is merely due a refresh. Omit them
    and this function will never return ``STALE`` -- it degrades to
    ``UNCERTAIN``, because without the age it genuinely cannot tell the two
    apart, and guessing is the bug this module is fixing. See the module
    docstring's point 2.

    Split out from ``diagnose_router_connection_failure`` (the real,
    I/O-performing entry point below) purely so the state-to-message
    mapping is trivially unit-testable without a fake repository/service
    -- the same "pure core, thin I/O shell" split ``validators.py`` uses
    elsewhere in this domain."""
    if not tunnel_matches_attempted_host:
        return TunnelState.NOT_APPLICABLE, None

    value = getattr(health_status, "value", str(health_status))
    if value == HealthStatus.HEALTHY.value:
        return TunnelState.HEALTHY, None
    if value == HealthStatus.UNKNOWN.value:
        return (
            TunnelState.NEVER_HANDSHAKED,
            "Can't reach this router: this platform has never recorded a "
            "WireGuard handshake for its tunnel. Check the router's WAN is "
            "up and UDP isn't blocked before troubleshooting anything else.",
        )
    if value == HealthStatus.STALE.value:
        return _diagnose_stale(handshake_age=handshake_age, stale_after=stale_after)
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


def _diagnose_stale(
    *, handshake_age: timedelta | None, stale_after: timedelta | None
) -> tuple[str, str | None]:
    """Splits ``HealthStatus.STALE`` into the part this module can actually
    stand behind and the part it cannot -- see the module docstring's
    point 2 for the sampling problem that makes the split necessary."""
    lag = _describe_duration(HANDSHAKE_OBSERVATION_LAG)
    if handshake_age is None or stale_after is None:
        return (
            TunnelState.UNCERTAIN,
            "Its WireGuard tunnel's last recorded handshake is older than "
            "the healthy window, but this platform records handshakes from "
            f"a sweep that only runs every {lag}, so that on its own does "
            "not establish the tunnel is down. Treat the tunnel state as "
            "unknown here rather than as a diagnosis.",
        )
    age = _describe_duration(handshake_age)
    if handshake_age <= stale_after + HANDSHAKE_OBSERVATION_LAG:
        return (
            TunnelState.UNCERTAIN,
            f"Its WireGuard tunnel's last recorded handshake was {age} ago, "
            f"just past the healthy window of "
            f"{_describe_duration(stale_after)}. This platform learns "
            f"handshakes from a sweep that runs "
            f"every {lag}, so at this age a tunnel that has genuinely gone "
            "quiet and one whose latest handshake simply hasn't been swept "
            "in yet look identical. Treat the tunnel state as unknown here "
            "rather than as a diagnosis.",
        )
    return (
        TunnelState.STALE,
        f"Can't reach this router: its WireGuard tunnel last handshaked "
        f"{age} ago -- far enough past the healthy window of "
        f"{_describe_duration(stale_after)} that a pending "
        f"sweep (every {lag}) can't account for it, so it looks "
        "disconnected right now. Check the router's WAN is up and UDP isn't "
        "blocked before troubleshooting anything else.",
    )


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
    not ``None``; when it is ``None`` (``TunnelState.NOT_APPLICABLE`` or
    ``TunnelState.HEALTHY``), this module has nothing it can honestly add
    and the caller's original message should be left exactly as it was.
    """
    try:
        peer = await wireguard_lookup.get_peer(
            router_id=router_id, requesting_organization_id=requesting_organization_id
        )
    except WireGuardPeerNotFoundError:
        return TunnelState.NOT_APPLICABLE, None

    tunnel_matches = bool(attempted_host) and attempted_host == peer.tunnel_ip_address
    now = datetime.now(UTC)
    health_status = wireguard_lookup.compute_health_status(peer, now=now)
    return diagnose_connection_failure(
        health_status=health_status,
        tunnel_matches_attempted_host=tunnel_matches,
        handshake_age=_handshake_age(peer, now=now),
        # Read defensively: a lookup implementation predating this
        # attribute simply never reaches the confident-stale verdict, which
        # is the safe direction to fail in.
        stale_after=getattr(wireguard_lookup, "handshake_stale_after", None),
    )


def _handshake_age(peer: object, *, now: datetime) -> timedelta | None:
    """``now`` minus the peer's recorded handshake, or ``None`` when there
    is no usable timestamp.

    This function never raises: a missing attribute, a non-datetime, or a
    naive datetime all yield ``None``, costing one confident verdict rather
    than a ``TypeError`` the caller's own blanket ``except`` would swallow
    into a silently hintless error.

    Note what it does *not* fix. ``WireGuardService.compute_health_status``
    does the same subtraction one line earlier and has no such guard, so a
    naive ``last_handshake_at`` still raises there first -- that is a real
    fragility, in another domain's method with other callers, and widening
    this fix to reach it is a separate change. The guard here is honest
    about its own scope: it keeps *this* module from being the one that
    raises."""
    handshake = getattr(peer, "last_handshake_at", None)
    if not isinstance(handshake, datetime) or handshake.tzinfo is None:
        return None
    return now - handshake
