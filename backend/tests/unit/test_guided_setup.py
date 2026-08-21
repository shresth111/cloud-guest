"""Unit tests for the Guided Setup verification judgement.

Pure functions over already-fetched facts -- no DB, no device, no clock
dependence beyond the ``now`` that is passed in explicitly.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.domains.provisioning_engine.planner.constants import VerificationCheckStatus
from app.domains.router.guided_setup import (
    CHECK_GUEST_SESSION,
    CHECK_HEARTBEAT,
    CHECK_RADIUS_NAS,
    CHECK_RADIUS_TRAFFIC,
    CHECK_WIREGUARD,
    GuidedSetupFacts,
    build_guided_setup_checks,
    overall_status,
)

NOW = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)


def _by_name(facts: GuidedSetupFacts) -> dict[str, VerificationCheckStatus]:
    return {c.name: c.status for c in build_guided_setup_checks(facts, now=NOW)}


def _healthy() -> GuidedSetupFacts:
    return GuidedSetupFacts(
        nas_identifier="cg-04f81868",
        nas_status="active",
        nas_tunnel_ip="10.100.0.7",
        peer_present=True,
        peer_revoked=False,
        peer_tunnel_ip="10.100.0.7",
        last_handshake_at=NOW - timedelta(seconds=30),
        router_last_seen_at=NOW - timedelta(minutes=2),
        total_session_count=4,
        active_session_count=1,
        accounted_session_count=3,
    )


class TestHealthyRouter:
    def test_everything_passes(self) -> None:
        assert set(_by_name(_healthy()).values()) == {VerificationCheckStatus.PASS}

    def test_overall_is_pass(self) -> None:
        checks = build_guided_setup_checks(_healthy(), now=NOW)
        assert overall_status(checks) is VerificationCheckStatus.PASS

    def test_always_five_checks_in_a_stable_order(self) -> None:
        checks = build_guided_setup_checks(_healthy(), now=NOW)
        assert [c.name for c in checks] == [
            CHECK_RADIUS_NAS,
            CHECK_WIREGUARD,
            CHECK_HEARTBEAT,
            CHECK_RADIUS_TRAFFIC,
            CHECK_GUEST_SESSION,
        ]


class TestConfiguredButNotWorking:
    """The failure this endpoint exists for: every row is present and
    perfect, and no guest can actually get online."""

    def test_rows_present_but_no_radius_traffic_is_not_a_pass(self) -> None:
        facts = GuidedSetupFacts(
            nas_identifier="cg-04f81868",
            nas_status="active",
            nas_tunnel_ip="10.100.0.7",
            peer_present=True,
            peer_tunnel_ip="10.100.0.7",
            last_handshake_at=NOW - timedelta(seconds=30),
            router_last_seen_at=NOW - timedelta(minutes=1),
            total_session_count=6,
            active_session_count=2,
            accounted_session_count=0,
        )
        statuses = _by_name(facts)
        assert statuses[CHECK_RADIUS_NAS] is VerificationCheckStatus.PASS
        assert statuses[CHECK_WIREGUARD] is VerificationCheckStatus.PASS
        assert statuses[CHECK_GUEST_SESSION] is VerificationCheckStatus.PASS
        # ...but the one check that proves real internet does not pass.
        assert statuses[CHECK_RADIUS_TRAFFIC] is VerificationCheckStatus.WARNING
        assert (
            overall_status(build_guided_setup_checks(facts, now=NOW))
            is VerificationCheckStatus.WARNING
        )

    def test_guest_session_check_does_not_claim_internet(self) -> None:
        checks = build_guided_setup_checks(_healthy(), now=NOW)
        session_check = next(c for c in checks if c.name == CHECK_GUEST_SESSION)
        assert "not that the guest got real" in (session_check.detail or "")


class TestMissingPieces:
    def test_no_nas_is_an_error(self) -> None:
        facts = GuidedSetupFacts(nas_identifier=None)
        assert _by_name(facts)[CHECK_RADIUS_NAS] is VerificationCheckStatus.ERROR

    def test_inactive_nas_is_an_error(self) -> None:
        facts = GuidedSetupFacts(nas_identifier="cg-1", nas_status="disabled")
        assert _by_name(facts)[CHECK_RADIUS_NAS] is VerificationCheckStatus.ERROR

    def test_nas_without_tunnel_ip_warns_about_catch_all_collision(self) -> None:
        facts = GuidedSetupFacts(
            nas_identifier="cg-1", nas_status="active", nas_tunnel_ip=None
        )
        checks = build_guided_setup_checks(facts, now=NOW)
        nas = next(c for c in checks if c.name == CHECK_RADIUS_NAS)
        assert nas.status is VerificationCheckStatus.WARNING
        assert "source address" in (nas.detail or "")

    def test_no_peer_is_an_error(self) -> None:
        assert (
            _by_name(GuidedSetupFacts(peer_present=False))[CHECK_WIREGUARD]
            is VerificationCheckStatus.ERROR
        )

    def test_revoked_peer_is_an_error(self) -> None:
        facts = GuidedSetupFacts(peer_present=True, peer_revoked=True)
        assert _by_name(facts)[CHECK_WIREGUARD] is VerificationCheckStatus.ERROR

    def test_peer_that_never_handshaked_is_an_error(self) -> None:
        facts = GuidedSetupFacts(
            peer_present=True, peer_tunnel_ip="10.100.0.7", last_handshake_at=None
        )
        assert _by_name(facts)[CHECK_WIREGUARD] is VerificationCheckStatus.ERROR

    def test_stale_handshake_warns_but_does_not_error(self) -> None:
        facts = GuidedSetupFacts(
            peer_present=True,
            peer_tunnel_ip="10.100.0.7",
            last_handshake_at=NOW - timedelta(hours=3),
        )
        assert _by_name(facts)[CHECK_WIREGUARD] is VerificationCheckStatus.WARNING

    def test_stale_heartbeat_warns(self) -> None:
        facts = GuidedSetupFacts(router_last_seen_at=NOW - timedelta(hours=2))
        assert _by_name(facts)[CHECK_HEARTBEAT] is VerificationCheckStatus.WARNING

    def test_never_seen_heartbeat_warns_not_errors(self) -> None:
        """A router can serve guests without ever posting a heartbeat."""
        facts = GuidedSetupFacts(router_last_seen_at=None)
        assert _by_name(facts)[CHECK_HEARTBEAT] is VerificationCheckStatus.WARNING


class TestOverallStatus:
    def test_worst_wins(self) -> None:
        facts = GuidedSetupFacts()  # nothing configured at all
        assert (
            overall_status(build_guided_setup_checks(facts, now=NOW))
            is VerificationCheckStatus.ERROR
        )

    def test_naive_datetimes_are_treated_as_utc(self) -> None:
        facts = GuidedSetupFacts(
            peer_present=True,
            peer_tunnel_ip="10.100.0.7",
            last_handshake_at=NOW.replace(tzinfo=None) - timedelta(seconds=10),
        )
        assert _by_name(facts)[CHECK_WIREGUARD] is VerificationCheckStatus.PASS


class TestHonesty:
    def test_radius_check_does_not_claim_to_have_run_a_live_test(self) -> None:
        facts = GuidedSetupFacts()
        check = next(
            c
            for c in build_guided_setup_checks(facts, now=NOW)
            if c.name == CHECK_RADIUS_TRAFFIC
        )
        assert "not a live authentication test" in (check.detail or "")
