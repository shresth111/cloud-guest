"""Guided Setup verification: what the platform can *observe* about a
router after provisioning, separated into the three claims this product
has historically conflated.

1. **"The router is configured."** Rows exist -- a RADIUS NAS client, a
   WireGuard peer. Says nothing about whether the device agrees.
2. **"The router is reachable."** The device has actually talked to us --
   a recent WireGuard handshake, a recent agent heartbeat.
3. **"A guest can get online."** Real guest traffic has completed the
   whole loop -- a session exists and RADIUS accounting has reported bytes
   against it.

A router can satisfy (1) completely and fail (2) and (3) silently, which
is precisely the failure mode this module exists to make visible: every
"generate the setup script" click used to rotate credentials the device
was still using, and the device-side chunks are add-if-missing, so the
platform's rows looked perfect while the router held stale values.

Everything here is a **pure function of already-fetched facts** -- no I/O,
no device calls, no persistence. Gathering is the caller's job; judgement
is this module's. That split is what makes the judgement unit-testable
without a database, and it is why this reports observations rather than
running probes: there is no synthetic-auth harness anywhere in this
codebase (see ``app.domains.readiness.constants``' own note), so an
honest "no Access-Request has been observed" is the strongest true claim
available, and this module says exactly that rather than implying a live
test it did not perform.

Reuses ``app.domains.provisioning_engine.planner.schemas.VerificationCheck``
(``name``/``status``/``observed``/``expected``/``detail``/``duration_ms``)
and its ``VerificationCheckStatus`` rather than inventing a parallel
result shape -- the fleet wizard's own Step 5/Step 11 already speak it, so
the Guided Setup module renders both with one component.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from app.domains.provisioning_engine.planner.constants import VerificationCheckStatus
from app.domains.provisioning_engine.planner.schemas import VerificationCheck

# How fresh an agent heartbeat has to be before it counts as "the device is
# talking to us right now". The bootstrap script installs a 5-minute
# scheduler (``render_agent_heartbeat_scheduler``'s own default interval),
# so three missed beats is the smallest window that cannot be tripped by a
# single lost run.
HEARTBEAT_FRESH_WITHIN_MINUTES = 15

# How many of a router's most recent sessions the caller samples when
# looking for evidence that RADIUS accounting has ever reported traffic.
GUIDED_SETUP_SESSION_SAMPLE = 50

CHECK_RADIUS_NAS = "radius_nas_client"
CHECK_WIREGUARD = "wireguard_tunnel"
CHECK_HEARTBEAT = "agent_heartbeat"
CHECK_RADIUS_TRAFFIC = "radius_traffic_observed"
CHECK_GUEST_SESSION = "guest_session"


@dataclass(frozen=True, slots=True)
class GuidedSetupFacts:
    """Everything :func:`build_guided_setup_checks` needs, already read.

    Deliberately plain values rather than ORM rows wherever a plain value
    will do, so the judgement below cannot accidentally trigger lazy I/O.
    """

    nas_identifier: str | None = None
    nas_status: str | None = None
    nas_tunnel_ip: str | None = None
    peer_present: bool = False
    peer_revoked: bool = False
    peer_tunnel_ip: str | None = None
    last_handshake_at: datetime | None = None
    router_last_seen_at: datetime | None = None
    total_session_count: int = 0
    active_session_count: int = 0
    accounted_session_count: int = 0


def _age(then: datetime | None, now: datetime) -> timedelta | None:
    if then is None:
        return None
    if then.tzinfo is None:
        then = then.replace(tzinfo=UTC)
    return now - then


def _ago(then: datetime | None, now: datetime) -> str:
    delta = _age(then, now)
    if delta is None:
        return "never"
    seconds = int(delta.total_seconds())
    if seconds < 90:
        return f"{max(seconds, 0)}s ago"
    minutes = seconds // 60
    if minutes < 90:
        return f"{minutes}m ago"
    return f"{minutes // 60}h ago"


def _check(
    name: str,
    status: VerificationCheckStatus,
    *,
    observed: str,
    expected: str,
    detail: str,
) -> VerificationCheck:
    return VerificationCheck(
        name=name,
        status=status,
        observed=observed,
        expected=expected,
        detail=detail,
    )


def build_guided_setup_checks(
    facts: GuidedSetupFacts, *, now: datetime | None = None
) -> list[VerificationCheck]:
    """The five observable facts, in the order an operator should read
    them: configuration first, then reachability, then real guest traffic.
    """
    now = now or datetime.now(UTC)
    checks: list[VerificationCheck] = []

    # -- 1. Configured: RADIUS NAS row -------------------------------------
    if facts.nas_identifier is None:
        checks.append(
            _check(
                CHECK_RADIUS_NAS,
                VerificationCheckStatus.ERROR,
                observed="no NAS client registered",
                expected="an active RADIUS NAS client",
                detail=(
                    "This router has no RADIUS identity, so no guest can "
                    "ever authenticate on it. Register one from the setup "
                    "panel, then apply the /radius lines to the device."
                ),
            )
        )
    elif facts.nas_status != "active":
        checks.append(
            _check(
                CHECK_RADIUS_NAS,
                VerificationCheckStatus.ERROR,
                observed=f"{facts.nas_identifier} is {facts.nas_status}",
                expected="an active RADIUS NAS client",
                detail=(
                    "The NAS client exists but is not active, so the "
                    "backend rejects its authorize calls. Activate it."
                ),
            )
        )
    elif facts.nas_tunnel_ip is None:
        checks.append(
            _check(
                CHECK_RADIUS_NAS,
                VerificationCheckStatus.WARNING,
                observed=f"{facts.nas_identifier}, no tunnel IP known",
                expected="an active NAS scoped to a tunnel IP",
                detail=(
                    "FreeRADIUS matches clients by source address. Without "
                    "a WireGuard tunnel IP this NAS falls back to a "
                    "catch-all entry, which collides with every other "
                    "such NAS and only one of them will load."
                ),
            )
        )
    else:
        checks.append(
            _check(
                CHECK_RADIUS_NAS,
                VerificationCheckStatus.PASS,
                observed=f"{facts.nas_identifier} active on {facts.nas_tunnel_ip}",
                expected="an active RADIUS NAS client",
                detail=(
                    "A NAS identity exists. This does not prove the device "
                    "holds the matching shared secret -- see "
                    f"'{CHECK_RADIUS_TRAFFIC}' below for that."
                ),
            )
        )

    # -- 2. Configured + reachable: WireGuard ------------------------------
    if not facts.peer_present or facts.peer_revoked:
        checks.append(
            _check(
                CHECK_WIREGUARD,
                VerificationCheckStatus.ERROR,
                observed="revoked" if facts.peer_revoked else "no peer",
                expected="a live WireGuard peer with a recent handshake",
                detail=(
                    "Without a tunnel the platform cannot reach this "
                    "router and its RADIUS traffic cannot reach the hub."
                ),
            )
        )
    elif facts.last_handshake_at is None:
        checks.append(
            _check(
                CHECK_WIREGUARD,
                VerificationCheckStatus.ERROR,
                observed=f"peer {facts.peer_tunnel_ip}, never handshaked",
                expected="a live WireGuard peer with a recent handshake",
                detail=(
                    "The peer row exists but the device has never "
                    "completed a handshake -- the usual cause is that the "
                    "router's WireGuard config was never applied, or was "
                    "applied with a key the platform has since replaced."
                ),
            )
        )
    else:
        delta = _age(facts.last_handshake_at, now)
        stale = delta is not None and delta > timedelta(
            minutes=HEARTBEAT_FRESH_WITHIN_MINUTES
        )
        checks.append(
            _check(
                CHECK_WIREGUARD,
                (
                    VerificationCheckStatus.WARNING
                    if stale
                    else VerificationCheckStatus.PASS
                ),
                observed=(
                    f"peer {facts.peer_tunnel_ip}, last handshake "
                    f"{_ago(facts.last_handshake_at, now)}"
                ),
                expected="a live WireGuard peer with a recent handshake",
                detail=(
                    "Handshake is stale. The tunnel may have dropped; "
                    "persistent-keepalive is 25s, so a healthy peer "
                    "refreshes well inside this window."
                    if stale
                    else "The device is on the tunnel."
                ),
            )
        )

    # -- 3. Reachable: agent heartbeat -------------------------------------
    delta = _age(facts.router_last_seen_at, now)
    if delta is None:
        checks.append(
            _check(
                CHECK_HEARTBEAT,
                VerificationCheckStatus.WARNING,
                observed="never",
                expected=f"a heartbeat within {HEARTBEAT_FRESH_WITHIN_MINUTES}m",
                detail=(
                    "No agent heartbeat has ever been recorded. Guests can "
                    "still get online without it, but the platform is blind "
                    "to this router's health and cannot push day-2 config."
                ),
            )
        )
    else:
        stale = delta > timedelta(minutes=HEARTBEAT_FRESH_WITHIN_MINUTES)
        checks.append(
            _check(
                CHECK_HEARTBEAT,
                (
                    VerificationCheckStatus.WARNING
                    if stale
                    else VerificationCheckStatus.PASS
                ),
                observed=_ago(facts.router_last_seen_at, now),
                expected=f"a heartbeat within {HEARTBEAT_FRESH_WITHIN_MINUTES}m",
                detail=(
                    "The scheduler that posts heartbeats may not have been "
                    "installed, or the device lost its route to the API."
                    if stale
                    else "The device is checking in."
                ),
            )
        )

    # -- 4. Real traffic: has RADIUS ever completed a cycle? ---------------
    if facts.accounted_session_count > 0:
        checks.append(
            _check(
                CHECK_RADIUS_TRAFFIC,
                VerificationCheckStatus.PASS,
                observed=(
                    f"{facts.accounted_session_count} session(s) with RADIUS accounting"
                ),
                expected="at least one session with RADIUS accounting",
                detail=(
                    "Accounting only follows a successful Access-Accept, so "
                    "this is real proof that a guest authenticated through "
                    "FreeRADIUS on this router and the shared secret matches."
                ),
            )
        )
    else:
        checks.append(
            _check(
                CHECK_RADIUS_TRAFFIC,
                VerificationCheckStatus.WARNING,
                observed="none observed",
                expected="at least one session with RADIUS accounting",
                detail=(
                    "No RADIUS accounting has been observed for this router "
                    f"across its {GUIDED_SETUP_SESSION_SAMPLE} most recent "
                    "sessions. This is expected on a router no guest has "
                    "used yet. If guests have tried and failed, the likely "
                    "causes are a shared secret the device no longer "
                    "matches, or a /radius entry missing src-address. Note "
                    "this is an observation, not a live authentication test "
                    "-- the platform has no synthetic-auth capability."
                ),
            )
        )

    # -- 5. Real traffic: guest sessions -----------------------------------
    if facts.total_session_count == 0:
        checks.append(
            _check(
                CHECK_GUEST_SESSION,
                VerificationCheckStatus.WARNING,
                observed="no sessions",
                expected="at least one guest session",
                detail=(
                    "No guest has completed the captive portal on this "
                    "router yet. Connect a phone and sign in to confirm "
                    "the whole path end to end."
                ),
            )
        )
    else:
        checks.append(
            _check(
                CHECK_GUEST_SESSION,
                VerificationCheckStatus.PASS,
                observed=(
                    f"{facts.total_session_count} session(s), "
                    f"{facts.active_session_count} active"
                ),
                expected="at least one guest session",
                detail=(
                    "A guest has completed the portal. Note this proves the "
                    "portal and OTP worked, not that the guest got real "
                    f"internet -- '{CHECK_RADIUS_TRAFFIC}' is that claim."
                ),
            )
        )

    return checks


def overall_status(checks: list[VerificationCheck]) -> VerificationCheckStatus:
    """Worst status wins. ERROR means a guest provably cannot get online;
    WARNING means the platform cannot yet prove that one can."""
    statuses = {check.status for check in checks}
    for worst in (
        VerificationCheckStatus.BLOCKED,
        VerificationCheckStatus.ERROR,
        VerificationCheckStatus.WARNING,
    ):
        if worst in statuses:
            return worst
    return VerificationCheckStatus.PASS


__all__ = [
    "GUIDED_SETUP_SESSION_SAMPLE",
    "HEARTBEAT_FRESH_WITHIN_MINUTES",
    "GuidedSetupFacts",
    "build_guided_setup_checks",
    "overall_status",
]
