"""``app.domains.wireguard.connection_diagnostics`` -- the operator-facing
tunnel-state hint appended to a device connection failure.

This module had no tests, and shipped two confidently wrong hints for the
same router, five minutes apart, while that router was demonstrably
reachable. Both are pinned here:

* A **healthy** tunnel used to emit "this looks like a different problem --
  not a tunnel issue. Check the device's own credentials, load, or service
  status instead." That contradicted its own caller's documented contract
  (``ProvisioningEngineService._enrich_connection_error``: "the tunnel turns
  out to be healthy -- ... blaming WireGuard would be a misdiagnosis ... the
  original message is left exactly as the adapter produced it") and named
  three subsystems this module cannot see.

* The healthy/stale boundary was drawn against a field refreshed on exactly
  the same 5-minute cadence as the window it was compared to, so the verdict
  oscillated once per sweep on a perfectly healthy tunnel.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.core.config import Settings
from app.domains.hub_reconciliation.constants import (
    HUB_RECONCILIATION_SWEEP_INTERVAL_SECONDS,
)
from app.domains.wireguard.connection_diagnostics import (
    HANDSHAKE_OBSERVATION_LAG,
    TunnelState,
    diagnose_connection_failure,
    diagnose_router_connection_failure,
)
from app.domains.wireguard.constants import HealthStatus
from app.domains.wireguard.exceptions import WireGuardPeerNotFoundError

TUNNEL_IP = "10.20.0.19"
STALE_AFTER = timedelta(minutes=5)


# ============================================================================
# The premise: why UNCERTAIN has to exist at all
# ============================================================================


def test_observation_lag_matches_the_sweep_that_refreshes_the_field() -> None:
    """``HANDSHAKE_OBSERVATION_LAG`` mirrors the hub-reconciliation sweep
    interval rather than importing it (cross-domain convention). This is the
    guard that stops the mirror drifting: if the sweep is ever re-tuned, the
    honesty band here must move with it."""
    assert (
        HANDSHAKE_OBSERVATION_LAG.total_seconds()
        == HUB_RECONCILIATION_SWEEP_INTERVAL_SECONDS
    )


def test_default_stale_window_is_not_wider_than_the_refresh_interval() -> None:
    """The defect itself, stated as an assertion.

    ``last_handshake_at`` is refreshed at most once per sweep, and the
    default staleness window is no wider than that sweep -- so on a healthy
    tunnel the recorded age sawtooths across the threshold every cycle and a
    bare healthy/stale verdict is a coin flip on sweep timing. This test does
    not assert the configuration is *wrong*; it documents that the window
    cannot on its own distinguish a quiet tunnel from an unswept record,
    which is exactly why ``TunnelState.UNCERTAIN`` exists.

    If someone later widens the default past the sweep interval, this test
    fails and should be reconsidered together with the UNCERTAIN band."""
    window = timedelta(minutes=Settings().wireguard_handshake_stale_after_minutes)
    assert window <= HANDSHAKE_OBSERVATION_LAG


# ============================================================================
# The pure classifier
# ============================================================================


def test_healthy_tunnel_produces_no_hint() -> None:
    """The regression. A healthy tunnel means WireGuard is not implicated;
    it is not evidence about what is."""
    state, message = diagnose_connection_failure(
        health_status=HealthStatus.HEALTHY,
        tunnel_matches_attempted_host=True,
        handshake_age=timedelta(seconds=30),
        stale_after=STALE_AFTER,
    )

    assert state == TunnelState.HEALTHY
    assert message is None


def test_healthy_hint_never_prescribes_another_subsystem() -> None:
    """Belt and braces on the exact wording that misdirected a live debug
    session -- an operator was sent to audit credentials and device load
    while the real cause was elsewhere entirely."""
    _state, message = diagnose_connection_failure(
        health_status=HealthStatus.HEALTHY, tunnel_matches_attempted_host=True
    )
    assert message is None


@pytest.mark.parametrize("age_minutes", [5, 6, 9, 10])
def test_barely_stale_is_reported_as_uncertain(age_minutes: int) -> None:
    """Anywhere inside one refresh interval past the window, "the tunnel
    went quiet" and "the sweep hasn't run yet" are indistinguishable."""
    state, message = diagnose_connection_failure(
        health_status=HealthStatus.STALE,
        tunnel_matches_attempted_host=True,
        handshake_age=timedelta(minutes=age_minutes),
        stale_after=STALE_AFTER,
    )

    assert state == TunnelState.UNCERTAIN
    assert message is not None
    # Says what it measured and why it cannot conclude -- and does NOT send
    # the operator to the WAN/UDP checks the confident verdict prescribes.
    assert "unknown" in message
    assert "UDP" not in message


def test_clearly_stale_is_still_reported_confidently() -> None:
    """The fix must not make the module useless: an age a pending sweep
    cannot account for is still a real diagnosis, with its real next step."""
    state, message = diagnose_connection_failure(
        health_status=HealthStatus.STALE,
        tunnel_matches_attempted_host=True,
        handshake_age=timedelta(hours=3),
        stale_after=STALE_AFTER,
    )

    assert state == TunnelState.STALE
    assert message is not None
    assert "180 minutes ago" in message
    assert "UDP isn't blocked" in message


def test_stale_without_an_age_degrades_to_uncertain() -> None:
    """Given no age, the module cannot tell the two apart -- so it says so
    rather than defaulting to the confident verdict."""
    state, message = diagnose_connection_failure(
        health_status=HealthStatus.STALE, tunnel_matches_attempted_host=True
    )

    assert state == TunnelState.UNCERTAIN
    assert message is not None
    assert "UDP" not in message


def test_never_handshaked_is_unambiguous_and_keeps_its_verdict() -> None:
    """No sampling problem here: a NULL handshake is not a stale reading,
    it is the absence of any reading at all."""
    state, message = diagnose_connection_failure(
        health_status=HealthStatus.UNKNOWN, tunnel_matches_attempted_host=True
    )

    assert state == TunnelState.NEVER_HANDSHAKED
    assert message is not None
    assert "never recorded" in message


def test_revoked_keeps_its_verdict() -> None:
    state, message = diagnose_connection_failure(
        health_status=HealthStatus.REVOKED, tunnel_matches_attempted_host=True
    )

    assert state == TunnelState.REVOKED
    assert message is not None
    assert "revoked" in message


@pytest.mark.parametrize(
    "status",
    [
        HealthStatus.HEALTHY,
        HealthStatus.STALE,
        HealthStatus.UNKNOWN,
        HealthStatus.REVOKED,
    ],
)
def test_non_tunnel_host_never_mentions_wireguard(status: HealthStatus) -> None:
    """Unchanged behavior, restated: a connection that was never attempted
    over the tunnel IP cannot be explained by the tunnel's state."""
    state, message = diagnose_connection_failure(
        health_status=status,
        tunnel_matches_attempted_host=False,
        handshake_age=timedelta(days=1),
        stale_after=STALE_AFTER,
    )

    assert state == TunnelState.NOT_APPLICABLE
    assert message is None


def test_unrecognized_status_fails_open() -> None:
    state, message = diagnose_connection_failure(
        health_status="some_future_status", tunnel_matches_attempted_host=True
    )

    assert state == TunnelState.NOT_APPLICABLE
    assert message is None


# ============================================================================
# The I/O entry point
# ============================================================================


class _FakePeer:
    def __init__(self, *, last_handshake_at: datetime | None) -> None:
        self.tunnel_ip_address = TUNNEL_IP
        self.last_handshake_at = last_handshake_at


class _FakeLookup:
    """Duck-types the narrow ``WireGuardTunnelLookupProtocol`` surface, with
    the same ``compute_health_status`` rule ``WireGuardService`` uses."""

    def __init__(
        self,
        peer: _FakePeer | None,
        *,
        stale_after: timedelta | None = STALE_AFTER,
        forced_status: HealthStatus | None = None,
    ) -> None:
        self._peer = peer
        self._forced_status = forced_status
        if stale_after is not None:
            self.handshake_stale_after = stale_after

    async def get_peer(
        self, *, router_id: uuid.UUID, requesting_organization_id: uuid.UUID | None
    ) -> _FakePeer:
        if self._peer is None:
            raise WireGuardPeerNotFoundError(router_id)
        return self._peer

    def compute_health_status(
        self, peer: _FakePeer, *, now: datetime | None = None
    ) -> HealthStatus:
        if self._forced_status is not None:
            return self._forced_status
        if peer.last_handshake_at is None:
            return HealthStatus.UNKNOWN
        moment = now or datetime.now(UTC)
        window = getattr(self, "handshake_stale_after", STALE_AFTER)
        if moment - peer.last_handshake_at <= window:
            return HealthStatus.HEALTHY
        return HealthStatus.STALE


async def _diagnose(lookup: _FakeLookup, *, host: str | None = TUNNEL_IP):
    return await diagnose_router_connection_failure(
        lookup,
        router_id=uuid.uuid4(),
        requesting_organization_id=None,
        attempted_host=host,
    )


class TestDiagnoseRouterConnectionFailure:
    async def test_the_incident_a_recently_handshaked_router_gets_no_hint(
        self,
    ) -> None:
        """The founder's exact situation: tunnel handshaked about a minute
        before the failure, connection attempted over the tunnel IP. The
        console error must be left alone -- the cause was not the tunnel,
        and this module has nothing to add."""
        lookup = _FakeLookup(
            _FakePeer(last_handshake_at=datetime.now(UTC) - timedelta(seconds=60))
        )

        state, message = await _diagnose(lookup)

        assert state == TunnelState.HEALTHY
        assert message is None

    async def test_a_handshake_one_sweep_overdue_reads_uncertain_not_stale(
        self,
    ) -> None:
        """The oscillation, reproduced: the same healthy router, sampled
        just before the next sweep lands, used to read STALE and send the
        operator to check WAN and UDP."""
        lookup = _FakeLookup(
            _FakePeer(
                last_handshake_at=datetime.now(UTC) - timedelta(minutes=5, seconds=30)
            )
        )

        state, message = await _diagnose(lookup)

        assert state == TunnelState.UNCERTAIN
        assert message is not None
        assert "UDP" not in message

    async def test_a_long_dead_tunnel_still_reads_stale(self) -> None:
        lookup = _FakeLookup(
            _FakePeer(last_handshake_at=datetime.now(UTC) - timedelta(days=2))
        )

        state, message = await _diagnose(lookup)

        assert state == TunnelState.STALE
        assert message is not None
        assert "UDP isn't blocked" in message

    async def test_lookup_without_the_window_attribute_degrades_to_uncertain(
        self,
    ) -> None:
        """``handshake_stale_after`` is read defensively. A lookup that
        predates it loses the confident verdict, never raises."""
        lookup = _FakeLookup(
            _FakePeer(last_handshake_at=datetime.now(UTC) - timedelta(days=2)),
            stale_after=None,
        )

        state, message = await _diagnose(lookup)

        assert state == TunnelState.UNCERTAIN
        assert message is not None

    async def test_naive_handshake_timestamp_does_not_raise_here(self) -> None:
        """A timestamp that lost its timezone makes ``now - handshake`` a
        ``TypeError``, which the caller's blanket ``except`` swallows into a
        silently hintless error. This module's own age computation degrades
        to UNCERTAIN instead of being that raise.

        The lookup is forced to answer STALE without doing arithmetic of its
        own, because the real ``WireGuardService.compute_health_status``
        would raise on the same value one line earlier -- a separate,
        pre-existing fragility in another domain that this change
        deliberately does not reach into (see ``_handshake_age``)."""
        lookup = _FakeLookup(
            _FakePeer(last_handshake_at=datetime(2020, 1, 1)),
            forced_status=HealthStatus.STALE,
        )

        state, message = await _diagnose(lookup)

        assert state == TunnelState.UNCERTAIN
        assert message is not None

    async def test_no_peer_means_no_hint(self) -> None:
        state, message = await _diagnose(_FakeLookup(None))

        assert state == TunnelState.NOT_APPLICABLE
        assert message is None

    async def test_connection_to_a_non_tunnel_host_means_no_hint(self) -> None:
        lookup = _FakeLookup(
            _FakePeer(last_handshake_at=datetime.now(UTC) - timedelta(days=2))
        )

        state, message = await _diagnose(lookup, host="192.168.1.110")

        assert state == TunnelState.NOT_APPLICABLE
        assert message is None
