"""Unit tests for Discovery's precondition pre-flight.

Motivating incident (2026-08-22): the fleet wizard offered a Discover
button for a router whose preconditions could not possibly be met, waited
out a connect timeout, and returned ``Could not connect to device at
'10.20.0.64' for discovery: timed out`` -- a message that names an IP
address and a symptom but none of the four independent things that must
be true first.

Every test here pins one specific guard. Each is written so that breaking
that single guard in ``planner/preflight.py`` or ``planner/service.py``
fails *this* test by name -- see the mutation log in the accompanying
report.

Follows this project's plain-``assert`` / native-``async def`` style; no
live device or network I/O anywhere in this file.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from wyfy_device_gateway.mikrotik_adapter import MikroTikConnectionError
from wyfy_device_gateway.read_only_reader import ReadOnlyStateCapture

from app.domains.provisioning_engine.planner.exceptions import (
    DiscoveryDeviceConnectionError,
    DiscoveryPreconditionsUnmetError,
)
from app.domains.provisioning_engine.planner.preflight import (
    DiscoveryPreflightReport,
    PreconditionKey,
    PreconditionStatus,
    SecretResolution,
    build_discovery_preflight,
    evaluate_preconditions,
)
from app.domains.provisioning_engine.planner.service import DiscoveryService
from app.domains.router.models import Router
from app.domains.wireguard.constants import HealthStatus
from app.domains.wireguard.exceptions import WireGuardPeerNotFoundError

TUNNEL_IP = "10.20.0.64"


# ============================================================================
# Helpers
# ============================================================================


def _now() -> datetime:
    return datetime.now(UTC)


def _base_fields(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": uuid.uuid4(),
        "created_at": _now(),
        "updated_at": _now(),
        "deleted_at": None,
        "is_deleted": False,
        "created_by": None,
        "updated_by": None,
        "version": 1,
    }
    base.update(overrides)
    return base


def _make_router(**overrides: object) -> Router:
    fields: dict[str, object] = {
        "organization_id": uuid.uuid4(),
        "location_id": uuid.uuid4(),
        "name": "Founder Router",
        "serial_number": f"SN-{uuid.uuid4().hex[:8]}",
        "mac_address": "AA:BB:CC:DD:EE:FF",
        "model": "RB4011",
        "vendor": "mikrotik",
        "routeros_version": "7.15.3",
        "management_ip_address": TUNNEL_IP,
        "public_ip_address": "192.168.2.200",
        "status": "online",
        "last_seen_at": _now(),
        "last_health_check_at": None,
        "health_status": None,
        "api_username": "cloudguest-api",
        "api_credentials_encrypted": "encrypted-placeholder",
        "settings": {},
    }
    fields.update(overrides)
    return Router(**_base_fields(**fields))


def _ok_secret() -> SecretResolution:
    return SecretResolution(secret="s3cret")


def _evaluate(**overrides: Any) -> DiscoveryPreflightReport:
    """All preconditions satisfied unless a test overrides one."""
    kwargs: dict[str, Any] = {
        "host": TUNNEL_IP,
        "api_username": "cloudguest-api",
        "secret": _ok_secret(),
        "peer_tunnel_ip": TUNNEL_IP,
        "peer_health": HealthStatus.HEALTHY,
    }
    kwargs.update(overrides)
    return evaluate_preconditions(**kwargs)


def _check(report: DiscoveryPreflightReport, key: PreconditionKey) -> Any:
    matches = [c for c in report.checks if c.key == key]
    assert matches, f"no check emitted for {key}"
    return matches[0]


class FakePeer:
    def __init__(self, tunnel_ip: str = TUNNEL_IP) -> None:
        self.tunnel_ip_address = tunnel_ip


class FakeWireGuardLookup:
    """Duck-typed stand-in for ``WireGuardService``'s two-method surface."""

    def __init__(
        self,
        *,
        peer: object | None = None,
        health: object = HealthStatus.HEALTHY,
        raises: Exception | None = None,
        health_raises: Exception | None = None,
    ) -> None:
        self._peer = peer
        self._health = health
        self._raises = raises
        self._health_raises = health_raises

    async def get_peer(
        self, *, router_id: uuid.UUID, requesting_organization_id: uuid.UUID | None
    ) -> object:
        if self._raises is not None:
            raise self._raises
        return self._peer

    def compute_health_status(
        self, peer: object, *, now: object | None = None
    ) -> object:
        if self._health_raises is not None:
            raise self._health_raises
        return self._health


class FakeSnapshotRepository:
    def __init__(self) -> None:
        self.rows: list[Any] = []

    async def create(self, data: dict[str, Any]) -> Any:
        from app.domains.provisioning_engine.planner.models import RouterSnapshot

        row = RouterSnapshot(**_base_fields(**data))
        self.rows.append(row)
        return row


class FakeRouterLookup:
    def __init__(self, router: Router, secret: str | None = "s3cret") -> None:
        self.router = router
        self.secret = secret
        self.secret_error: Exception | None = None

    async def get_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> Router:
        return self.router

    def get_decrypted_api_secret(self, router: Router) -> str | None:
        if self.secret_error is not None:
            raise self.secret_error
        return self.secret


# ============================================================================
# Pure core -- one test per precondition guard
# ============================================================================


def test_all_preconditions_met_allows_attempt() -> None:
    report = _evaluate()
    assert report.can_attempt is True
    assert report.blocking == ()
    assert report.summary is None


def test_missing_management_address_blocks_and_names_itself() -> None:
    report = _evaluate(host=None, peer_tunnel_ip=None, peer_health=None)
    check = _check(report, PreconditionKey.MANAGEMENT_ADDRESS)
    assert check.status is PreconditionStatus.FAIL
    assert report.can_attempt is False
    assert "no management or public IP" in check.detail
    assert check.next_step and "heartbeat" in check.next_step


def test_missing_api_username_blocks_and_points_at_the_manual_step() -> None:
    """Nothing in the platform creates the RouterOS API user -- the next
    step must say so rather than implying it appears on its own."""
    report = _evaluate(api_username=None)
    check = _check(report, PreconditionKey.API_USERNAME)
    assert check.status is PreconditionStatus.FAIL
    assert report.can_attempt is False
    assert check.next_step and "API Access" in check.next_step
    assert "automatically" in check.next_step


def test_missing_api_secret_blocks() -> None:
    report = _evaluate(secret=SecretResolution())
    check = _check(report, PreconditionKey.API_SECRET)
    assert check.status is PreconditionStatus.FAIL
    assert report.can_attempt is False


def test_undecryptable_secret_is_distinct_from_absent_secret() -> None:
    """A rotated encryption key must not tell the operator to re-run the
    setup script -- the password is there, it just cannot be read."""
    report = _evaluate(
        secret=SecretResolution(undecryptable_reason="RouterCredentialDecryptionError")
    )
    check = _check(report, PreconditionKey.API_SECRET)
    assert check.status is PreconditionStatus.FAIL
    assert "could not be decrypted" in check.detail
    assert check.next_step and "encryption key" in check.next_step


def test_never_handshaked_tunnel_blocks_with_paste_the_chunk_next_step() -> None:
    """The founder's reported case: the exact sentence the product owes him."""
    report = _evaluate(peer_health=HealthStatus.UNKNOWN)
    check = _check(report, PreconditionKey.WIREGUARD_HANDSHAKE)
    assert check.status is PreconditionStatus.FAIL
    assert report.can_attempt is False
    assert "never recorded a handshake" in check.detail
    assert check.next_step and "WireGuard chunk" in check.next_step
    assert report.summary and "WireGuard chunk" in report.summary


def test_stale_tunnel_blocks_with_its_own_message() -> None:
    report = _evaluate(peer_health=HealthStatus.STALE)
    check = _check(report, PreconditionKey.WIREGUARD_HANDSHAKE)
    assert check.status is PreconditionStatus.FAIL
    assert "handshaked before but not" in check.detail
    assert check.next_step and "UDP" in check.next_step


def test_revoked_tunnel_blocks_with_its_own_message() -> None:
    report = _evaluate(peer_health=HealthStatus.REVOKED)
    check = _check(report, PreconditionKey.WIREGUARD_HANDSHAKE)
    assert check.status is PreconditionStatus.FAIL
    assert "revoked" in check.detail
    assert check.next_step and "fresh tunnel" in check.next_step


def test_unrecognized_tunnel_state_is_unknown_not_pass() -> None:
    """A future HealthStatus must never be silently treated as healthy."""
    report = _evaluate(peer_health="some-future-state")
    check = _check(report, PreconditionKey.WIREGUARD_HANDSHAKE)
    assert check.status is PreconditionStatus.UNKNOWN
    assert check in report.unverified


def test_non_tunnel_host_never_blames_wireguard() -> None:
    """A router managed over a LAN address must not be told its tunnel is
    broken -- the tunnel is not on the path at all."""
    report = _evaluate(
        host="192.168.88.1", peer_tunnel_ip=TUNNEL_IP, peer_health=HealthStatus.UNKNOWN
    )
    peer = _check(report, PreconditionKey.WIREGUARD_PEER)
    handshake = _check(report, PreconditionKey.WIREGUARD_HANDSHAKE)
    assert peer.status is PreconditionStatus.PASS
    assert handshake.status is PreconditionStatus.PASS
    assert "not applicable" in handshake.detail.lower()
    assert report.can_attempt is True


def test_no_peer_at_all_is_unknown_and_surfaced() -> None:
    """Absent a peer we can neither prove nor disprove reachability, so
    this must land in ``unverified`` -- never silently pass."""
    report = _evaluate(peer_tunnel_ip=None, peer_health=None)
    check = _check(report, PreconditionKey.WIREGUARD_PEER)
    assert check.status is PreconditionStatus.UNKNOWN
    assert check in report.unverified
    assert check.next_step and "WireGuard chunk" in check.next_step
    # Unknown is surfaced, but does not fabricate a block.
    assert report.can_attempt is True


def test_device_api_service_is_always_unknown() -> None:
    """Whether the API user exists on the device is unknowable without
    connecting. Asserting it is present would be a fabricated success."""
    report = _evaluate()
    check = _check(report, PreconditionKey.DEVICE_API_SERVICE)
    assert check.status is PreconditionStatus.UNKNOWN
    assert check in report.unverified
    assert "without connecting" in check.detail
    assert report.unverified != ()


def test_summary_names_the_first_block_and_counts_the_rest() -> None:
    report = _evaluate(host=None, api_username=None, secret=SecretResolution())
    assert report.can_attempt is False
    assert report.summary is not None
    assert "other precondition(s) also unmet" in report.summary
    assert len(report.blocking) == 3


# ============================================================================
# I/O shell
# ============================================================================


async def test_build_preflight_reads_peer_and_health() -> None:
    lookup = FakeWireGuardLookup(peer=FakePeer(), health=HealthStatus.UNKNOWN)
    report = await build_discovery_preflight(
        host=TUNNEL_IP,
        api_username="cloudguest-api",
        secret=_ok_secret(),
        router_id=uuid.uuid4(),
        requesting_organization_id=None,
        wireguard_lookup=lookup,
    )
    assert _check(report, PreconditionKey.WIREGUARD_HANDSHAKE).status is (
        PreconditionStatus.FAIL
    )


async def test_missing_peer_lookup_does_not_block_discovery() -> None:
    lookup = FakeWireGuardLookup(raises=WireGuardPeerNotFoundError(uuid.uuid4()))
    report = await build_discovery_preflight(
        host=TUNNEL_IP,
        api_username="cloudguest-api",
        secret=_ok_secret(),
        router_id=uuid.uuid4(),
        requesting_organization_id=None,
        wireguard_lookup=lookup,
    )
    assert _check(report, PreconditionKey.WIREGUARD_PEER).status is (
        PreconditionStatus.UNKNOWN
    )
    assert report.can_attempt is True


async def test_broken_wireguard_lookup_never_breaks_preflight() -> None:
    """A diagnostic that raises must not become the operator's error."""
    lookup = FakeWireGuardLookup(raises=RuntimeError("wireguard is down"))
    report = await build_discovery_preflight(
        host=TUNNEL_IP,
        api_username="cloudguest-api",
        secret=_ok_secret(),
        router_id=uuid.uuid4(),
        requesting_organization_id=None,
        wireguard_lookup=lookup,
    )
    assert report.can_attempt is True
    assert _check(report, PreconditionKey.WIREGUARD_PEER).status is (
        PreconditionStatus.UNKNOWN
    )


async def test_broken_health_computation_never_breaks_preflight() -> None:
    lookup = FakeWireGuardLookup(
        peer=FakePeer(), health_raises=RuntimeError("clock exploded")
    )
    report = await build_discovery_preflight(
        host=TUNNEL_IP,
        api_username="cloudguest-api",
        secret=_ok_secret(),
        router_id=uuid.uuid4(),
        requesting_organization_id=None,
        wireguard_lookup=lookup,
    )
    assert _check(report, PreconditionKey.WIREGUARD_HANDSHAKE).status is (
        PreconditionStatus.UNKNOWN
    )


# ============================================================================
# DiscoveryService integration -- the button must not reach the socket
# ============================================================================


class NeverCalledReader:
    """Any use of this reader means pre-flight failed to stop the attempt."""

    def __init__(self, creds: object) -> None:
        raise AssertionError(
            "Discovery opened a device connection despite an unmet precondition"
        )


async def test_discover_refuses_before_socket_when_tunnel_never_handshaked() -> None:
    router = _make_router()
    service = DiscoveryService(
        FakeSnapshotRepository(),
        FakeRouterLookup(router),
        reader_factory=NeverCalledReader,
        wireguard_lookup=FakeWireGuardLookup(
            peer=FakePeer(), health=HealthStatus.UNKNOWN
        ),
    )
    with pytest.raises(DiscoveryPreconditionsUnmetError) as excinfo:
        await service.discover_router(router.id)
    assert "never recorded a handshake" in str(excinfo.value)
    assert "WireGuard chunk" in str(excinfo.value)
    assert excinfo.value.status_code == 400


async def test_discover_refuses_when_api_username_missing() -> None:
    router = _make_router(api_username=None)
    service = DiscoveryService(
        FakeSnapshotRepository(),
        FakeRouterLookup(router),
        reader_factory=NeverCalledReader,
        wireguard_lookup=FakeWireGuardLookup(peer=FakePeer()),
    )
    with pytest.raises(DiscoveryPreconditionsUnmetError) as excinfo:
        await service.discover_router(router.id)
    assert "API username" in str(excinfo.value)


async def test_discover_refuses_when_secret_cannot_be_decrypted() -> None:
    """A Fernet-key mismatch must surface as a named precondition, not a
    500 escaping from the crypto layer."""
    router = _make_router()
    lookup = FakeRouterLookup(router)
    lookup.secret_error = RuntimeError("RouterCredentialDecryptionError")
    service = DiscoveryService(
        FakeSnapshotRepository(),
        lookup,
        reader_factory=NeverCalledReader,
        wireguard_lookup=FakeWireGuardLookup(peer=FakePeer()),
    )
    with pytest.raises(DiscoveryPreconditionsUnmetError) as excinfo:
        await service.discover_router(router.id)
    assert "could not be decrypted" in str(excinfo.value)


async def test_precondition_error_carries_the_full_check_list() -> None:
    router = _make_router(api_username=None)
    service = DiscoveryService(
        FakeSnapshotRepository(),
        FakeRouterLookup(router),
        reader_factory=NeverCalledReader,
        wireguard_lookup=FakeWireGuardLookup(peer=FakePeer()),
    )
    with pytest.raises(DiscoveryPreconditionsUnmetError) as excinfo:
        await service.discover_router(router.id)
    checks = excinfo.value.data["preconditions"]
    assert isinstance(checks, list)
    keys = {c["key"] for c in checks}
    assert str(PreconditionKey.DEVICE_API_SERVICE) in keys
    assert str(PreconditionKey.WIREGUARD_HANDSHAKE) in keys


async def test_connection_failure_after_clean_preflight_names_the_candidates() -> None:
    """The founder's *current* state: every checkable precondition passes
    and it still times out. The message must name what is left rather than
    stopping at "timed out"."""
    router = _make_router()

    class ExplodingReader:
        def __init__(self, creds: object) -> None:
            self.creds = creds

        async def read_all(self, sections: object = None) -> ReadOnlyStateCapture:
            raise MikroTikConnectionError(TUNNEL_IP, "timed out")

    service = DiscoveryService(
        FakeSnapshotRepository(),
        FakeRouterLookup(router),
        reader_factory=ExplodingReader,
        wireguard_lookup=FakeWireGuardLookup(
            peer=FakePeer(), health=HealthStatus.HEALTHY
        ),
    )
    with pytest.raises(DiscoveryDeviceConnectionError) as excinfo:
        await service.discover_router(router.id)
    message = str(excinfo.value)
    # The transport's own words survive verbatim -- nothing is masked.
    assert "timed out" in message
    # ...and the message now identifies itself.
    assert "no network route" in message
    assert "routeros api service and user on the device" in message.lower()


async def test_preflight_endpoint_shape_reports_counts() -> None:
    router = _make_router()
    service = DiscoveryService(
        FakeSnapshotRepository(),
        FakeRouterLookup(router),
        wireguard_lookup=FakeWireGuardLookup(
            peer=FakePeer(), health=HealthStatus.UNKNOWN
        ),
    )
    response = await service.get_discovery_preflight(router.id)
    assert response.can_attempt is False
    assert response.blocking_count == 1
    assert response.unverified_count >= 1
    assert response.summary and "WireGuard chunk" in response.summary
    assert {c.key for c in response.checks} >= {
        str(PreconditionKey.MANAGEMENT_ADDRESS),
        str(PreconditionKey.API_USERNAME),
        str(PreconditionKey.API_SECRET),
        str(PreconditionKey.WIREGUARD_PEER),
        str(PreconditionKey.WIREGUARD_HANDSHAKE),
        str(PreconditionKey.DEVICE_API_SERVICE),
    }
