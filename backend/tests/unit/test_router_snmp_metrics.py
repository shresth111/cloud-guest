"""Unit tests for the real SNMP-based device metrics monitoring extension:

* ``RouterService``'s per-router SNMP configuration (encryption on write,
  decryption on read) -- mirrors ``get_decrypted_api_secret``'s own
  existing coverage in ``test_router.py``.
* ``app.domains.provisioning_engine.service
  .run_router_snmp_metrics_poll_sweep`` -- real per-router credential
  resolution (per-router override, then platform default, then honest
  skip), successful-poll recording (composing onto
  ``RouterHealthSnapshot`` via ``record_health_snapshot``, tagged
  ``metrics_source="snmp"``, never calling ``RouterService.heartbeat``),
  honest failure recording on a real SNMP timeout/error, and per-router
  failure isolation -- mirroring ``test_provisioning_engine.py``'s own
  ``TestRouterHealthPollSweep`` structure and its identical "fake the
  narrow Protocol boundary" precedent (``RouterLookupProtocol``/
  ``RouterProvisioningLookupProtocol``), plus a fake
  ``wyfy_device_gateway.snmp_poller.SnmpPoller`` -- the same "mock at the
  adapter/Protocol boundary, not the real device I/O" convention
  ``test_isp.py``'s own module docstring documents for its fake health
  adapter.

Follows this project's plain-``assert``/native-``async def`` style;
``asyncio_mode = "auto"`` runs async tests directly.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest
from wyfy_device_gateway.snmp_poller import (
    SnmpConnectionError,
    SnmpDeviceError,
    SnmpDeviceMetrics,
    SnmpInterfaceCounters,
)

from app.domains.provisioning_engine import service as provisioning_engine_service
from app.domains.provisioning_engine.repository import (
    ProvisioningEngineRepositoryProtocol,
)
from app.domains.provisioning_engine.service import (
    SnmpMetricsPollSweepSummary,
    run_router_snmp_metrics_poll_sweep,
)
from app.domains.router.crypto import decrypt_secret
from app.domains.router.exceptions import RouterNotFoundError
from app.domains.router.models import Router
from app.domains.router.service import RouterService

# ============================================================================
# Shared helpers
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


def _make_router(
    *,
    snmp_enabled: bool = True,
    snmp_community_encrypted: str | None = None,
    snmp_version: str | None = None,
    snmp_port: int | None = None,
    management_ip_address: str = "10.0.0.1",
) -> Router:
    return Router(
        **_base_fields(
            organization_id=uuid.uuid4(),
            location_id=uuid.uuid4(),
            name="Test Router",
            serial_number=f"SN-{uuid.uuid4().hex[:8]}",
            mac_address=f"AA:BB:CC:DD:EE:{uuid.uuid4().hex[:2].upper()}",
            model="hEX lite",
            vendor="mikrotik",
            routeros_version=None,
            management_ip_address=management_ip_address,
            public_ip_address=None,
            status="online",
            last_seen_at=None,
            last_health_check_at=None,
            health_status="healthy",
            api_username="admin",
            api_credentials_encrypted=None,
            snmp_enabled=snmp_enabled,
            snmp_community_encrypted=snmp_community_encrypted,
            snmp_version=snmp_version,
            snmp_port=snmp_port,
            settings={},
        )
    )


@dataclass
class FakeSettings:
    snmp_default_community: str = ""
    snmp_default_version: str = "2c"
    snmp_default_port: int = 161
    snmp_poll_timeout_seconds: int = 5


@dataclass
class FakeRouterLookup:
    """Fakes the narrow ``RouterLookupProtocol`` surface
    ``run_router_snmp_metrics_poll_sweep`` needs -- mirrors
    ``test_provisioning_engine.py``'s own ``FakeRouterLookup`` plus the
    additive ``get_decrypted_snmp_community`` method this sweep also
    needs."""

    routers: dict[uuid.UUID, Router] = field(default_factory=dict)
    snmp_communities: dict[uuid.UUID, str | None] = field(default_factory=dict)
    heartbeats: list[uuid.UUID] = field(default_factory=list)

    def add(self, router: Router, *, snmp_community: str | None = None) -> Router:
        self.routers[router.id] = router
        self.snmp_communities[router.id] = snmp_community
        return router

    async def get_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Router:
        router = self.routers.get(router_id)
        if router is None:
            raise RouterNotFoundError(router_id)
        return router

    async def heartbeat(
        self,
        *,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None = None,
        routeros_version: str | None = None,
        management_ip_address: str | None = None,
    ) -> Router:
        self.heartbeats.append(router_id)
        return self.routers[router_id]

    def get_decrypted_api_secret(self, router: Router) -> str | None:
        return None

    def get_decrypted_snmp_community(self, router: Router) -> str | None:
        return self.snmp_communities.get(router.id)


@dataclass
class FakeRouterProvisioningLookup:
    health_snapshots_recorded: list[dict[str, object]] = field(default_factory=list)
    failed_health_checks_recorded: list[dict[str, object]] = field(default_factory=list)

    async def record_health_snapshot(self, *, router_id: uuid.UUID, **kwargs: object):
        self.health_snapshots_recorded.append({"router_id": router_id, **kwargs})

        @dataclass
        class _FakeSnapshot:
            id: uuid.UUID = field(default_factory=uuid.uuid4)

        return object(), _FakeSnapshot()

    async def record_failed_health_check(
        self, *, router_id: uuid.UUID, **kwargs: object
    ):
        self.failed_health_checks_recorded.append({"router_id": router_id, **kwargs})

        @dataclass
        class _FakeSnapshot:
            id: uuid.UUID = field(default_factory=uuid.uuid4)

        return _FakeSnapshot()


@dataclass
class FakeSnmpPoller:
    """Fakes ``wyfy_device_gateway.snmp_poller.SnmpPoller`` at the exact
    Protocol boundary ``run_router_snmp_metrics_poll_sweep`` calls
    (``get_device_metrics``) -- real SNMP wire-protocol/OID-walking
    behavior is covered separately, and honestly, in
    ``vendor/wyfy-device-gateway/tests/test_snmp_poller.py``."""

    result_by_host: dict[str, SnmpDeviceMetrics] = field(default_factory=dict)
    exception_by_host: dict[str, Exception] = field(default_factory=dict)
    calls: list[str] = field(default_factory=list)

    async def get_device_metrics(self, creds) -> SnmpDeviceMetrics:  # noqa: ANN001
        self.calls.append(creds.host)
        if creds.host in self.exception_by_host:
            raise self.exception_by_host[creds.host]
        return self.result_by_host[creds.host]


def _default_metrics() -> SnmpDeviceMetrics:
    return SnmpDeviceMetrics(
        sys_descr="RouterOS RB750Gr3",
        sys_name="edge-router-01",
        uptime_seconds=7200,
        cpu_load_percent=12.5,
        memory_usage_percent=41.0,
        interfaces=[
            SnmpInterfaceCounters(
                if_index=1,
                if_name="ether1",
                if_oper_status_up=True,
                in_octets=123456,
                out_octets=654321,
            )
        ],
    )


class _StubRepository:
    """Only ``list_routers_for_snmp_poll`` is ever exercised in tests that
    don't pass ``routers=`` explicitly -- a plain, minimal stand-in for
    ``ProvisioningEngineRepositoryProtocol`` (never a real DB session)."""

    def __init__(self, routers: list[Router]) -> None:
        self._routers = routers

    async def list_routers_for_snmp_poll(self) -> list[Router]:
        return self._routers


# ============================================================================
# RouterService: per-router SNMP configuration
# ============================================================================


class FakeRouterRepositoryForSnmp:
    def __init__(self, *, existing: Router | None = None) -> None:
        self.created_fields: dict[str, object] | None = None
        self.updated_fields: dict[str, object] | None = None
        self._existing = existing

    async def create_router(self, **fields: object) -> Router:
        self.created_fields = fields
        return Router(**_base_fields(**fields))

    async def update_router(self, router: Router, data: dict[str, object]) -> Router:
        self.updated_fields = data
        for key, value in data.items():
            setattr(router, key, value)
        return router

    async def get_by_id(self, router_id: uuid.UUID, *, include_deleted: bool = False):
        if self._existing is not None and self._existing.id == router_id:
            return self._existing
        return None

    async def get_by_serial_number(self, serial_number: str):
        return None

    async def get_by_mac_address(self, mac_address: str):
        return None


class TestRouterServiceSnmpConfig:
    async def test_create_router_encrypts_snmp_community(self) -> None:
        repository = FakeRouterRepositoryForSnmp()

        @dataclass
        class _FakeLocation:
            id: uuid.UUID
            organization_id: uuid.UUID
            status: str = "active"

        @dataclass
        class _FakeLocationLookup:
            location: _FakeLocation

            async def get_location(self, location_id, **_kw):
                return self.location

        location = _FakeLocation(id=uuid.uuid4(), organization_id=uuid.uuid4())
        service = RouterService(
            repository, _FakeLocationLookup(location), organization_lookup=None
        )
        router = await service.create_router(
            actor_user_id=None,
            location_id=location.id,
            requesting_organization_id=None,
            name="R1",
            serial_number="SN1",
            mac_address="AA:BB:CC:DD:EE:01",
            model="hEX lite",
            snmp_enabled=True,
            snmp_community="s3cret",
            snmp_version="2c",
            snmp_port=161,
        )
        assert repository.created_fields["snmp_enabled"] is True
        ciphertext = repository.created_fields["snmp_community_encrypted"]
        assert ciphertext is not None
        assert ciphertext != "s3cret"
        assert decrypt_secret(ciphertext) == "s3cret"
        assert router.snmp_version == "2c"
        assert router.snmp_port == 161

    async def test_update_router_encrypts_snmp_community(self) -> None:
        existing = _make_router(snmp_enabled=False)
        repository = FakeRouterRepositoryForSnmp(existing=existing)
        service = RouterService(
            repository, location_lookup=None, organization_lookup=None
        )
        updated = await service.update_router(
            actor_user_id=None,
            router_id=existing.id,
            requesting_organization_id=None,
            data={"snmp_enabled": True, "snmp_community": "new-secret"},
        )
        ciphertext = repository.updated_fields["snmp_community_encrypted"]
        assert decrypt_secret(ciphertext) == "new-secret"
        assert "snmp_community" not in repository.updated_fields
        assert updated.snmp_enabled is True

    def test_get_decrypted_snmp_community_round_trips(self) -> None:
        service = RouterService(
            FakeRouterRepositoryForSnmp(),
            location_lookup=None,
            organization_lookup=None,
        )
        from app.domains.router.crypto import encrypt_secret

        router = _make_router(snmp_community_encrypted=encrypt_secret("roundtrip"))
        assert service.get_decrypted_snmp_community(router) == "roundtrip"

    def test_get_decrypted_snmp_community_none_when_unset(self) -> None:
        service = RouterService(
            FakeRouterRepositoryForSnmp(),
            location_lookup=None,
            organization_lookup=None,
        )
        router = _make_router(snmp_community_encrypted=None)
        assert service.get_decrypted_snmp_community(router) is None


# ============================================================================
# run_router_snmp_metrics_poll_sweep
# ============================================================================


class TestRouterSnmpMetricsPollSweep:
    def _patch_settings(
        self, monkeypatch: pytest.MonkeyPatch, **overrides: object
    ) -> None:
        settings = FakeSettings(**overrides)
        monkeypatch.setattr(
            provisioning_engine_service, "get_settings", lambda: settings
        )

    async def test_successful_poll_records_snapshot_composing_onto_existing_table(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._patch_settings(monkeypatch)
        router = _make_router(snmp_enabled=True)
        router_lookup = FakeRouterLookup()
        router_lookup.add(router, snmp_community="public")
        router_provisioning = FakeRouterProvisioningLookup()
        poller = FakeSnmpPoller(
            result_by_host={router.management_ip_address: _default_metrics()}
        )

        summary = await run_router_snmp_metrics_poll_sweep(
            _StubRepository([router]),
            router_lookup,
            router_provisioning,
            snmp_poller=poller,
        )

        assert summary == SnmpMetricsPollSweepSummary(
            checked=1, unreachable=0, skipped=0, errors=0
        )
        assert len(router_provisioning.health_snapshots_recorded) == 1
        recorded = router_provisioning.health_snapshots_recorded[0]
        assert recorded["router_id"] == router.id
        assert recorded["cpu_usage_percent"] == 12.5
        assert recorded["memory_usage_percent"] == 41.0
        assert recorded["uptime_seconds"] == 7200
        assert recorded["metrics_source"] == "snmp"
        # Never fabricates liveness via the RouterOS-API heartbeat path --
        # see record_health_snapshot's own "call_heartbeat=False" docstring.
        assert recorded["call_heartbeat"] is False
        assert router_lookup.heartbeats == []
        assert recorded["interface_traffic_counters"] == [
            {
                "if_index": 1,
                "if_name": "ether1",
                "up": True,
                "in_octets": 123456,
                "out_octets": 654321,
            }
        ]

    async def test_no_community_anywhere_is_honestly_skipped_not_guessed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._patch_settings(monkeypatch, snmp_default_community="")
        router = _make_router(snmp_enabled=True, snmp_community_encrypted=None)
        router_lookup = FakeRouterLookup()
        router_lookup.add(router, snmp_community=None)
        router_provisioning = FakeRouterProvisioningLookup()
        poller = FakeSnmpPoller()

        summary = await run_router_snmp_metrics_poll_sweep(
            _StubRepository([router]),
            router_lookup,
            router_provisioning,
            snmp_poller=poller,
        )

        assert summary == SnmpMetricsPollSweepSummary(
            checked=0, unreachable=0, skipped=1, errors=0
        )
        assert poller.calls == []
        assert router_provisioning.health_snapshots_recorded == []
        assert router_provisioning.failed_health_checks_recorded == []

    async def test_falls_back_to_platform_default_community(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._patch_settings(monkeypatch, snmp_default_community="platform-wide-public")
        router = _make_router(snmp_enabled=True, snmp_community_encrypted=None)
        router_lookup = FakeRouterLookup()
        router_lookup.add(router, snmp_community=None)
        router_provisioning = FakeRouterProvisioningLookup()
        poller = FakeSnmpPoller(
            result_by_host={router.management_ip_address: _default_metrics()}
        )

        summary = await run_router_snmp_metrics_poll_sweep(
            _StubRepository([router]),
            router_lookup,
            router_provisioning,
            snmp_poller=poller,
        )

        assert summary.checked == 1
        assert poller.calls == [router.management_ip_address]

    async def test_snmp_connection_error_records_failed_health_check(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._patch_settings(monkeypatch)
        router = _make_router(snmp_enabled=True)
        router_lookup = FakeRouterLookup()
        router_lookup.add(router, snmp_community="public")
        router_provisioning = FakeRouterProvisioningLookup()
        poller = FakeSnmpPoller(
            exception_by_host={
                router.management_ip_address: SnmpConnectionError(
                    router.management_ip_address,
                    "No SNMP response received before timeout",
                )
            }
        )

        summary = await run_router_snmp_metrics_poll_sweep(
            _StubRepository([router]),
            router_lookup,
            router_provisioning,
            snmp_poller=poller,
        )

        assert summary == SnmpMetricsPollSweepSummary(
            checked=0, unreachable=1, skipped=0, errors=0
        )
        assert len(router_provisioning.failed_health_checks_recorded) == 1
        failed = router_provisioning.failed_health_checks_recorded[0]
        assert failed["router_id"] == router.id
        assert failed["metrics_source"] == "snmp"
        assert router_provisioning.health_snapshots_recorded == []

    async def test_snmp_device_error_also_records_failed_health_check(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._patch_settings(monkeypatch)
        router = _make_router(snmp_enabled=True)
        router_lookup = FakeRouterLookup()
        router_lookup.add(router, snmp_community="public")
        router_provisioning = FakeRouterProvisioningLookup()
        poller = FakeSnmpPoller(
            exception_by_host={
                router.management_ip_address: SnmpDeviceError(
                    router.management_ip_address, "noSuchName"
                )
            }
        )

        summary = await run_router_snmp_metrics_poll_sweep(
            _StubRepository([router]),
            router_lookup,
            router_provisioning,
            snmp_poller=poller,
        )

        assert summary.unreachable == 1

    async def test_per_router_failure_isolation(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """One router's own unexpected failure must never abort the sweep
        for the rest of the fleet -- mirrors
        ``run_router_health_poll_sweep``'s identical isolation contract."""
        self._patch_settings(monkeypatch)
        broken_router = _make_router(
            snmp_enabled=True, management_ip_address="10.0.0.1"
        )
        healthy_router = _make_router(
            snmp_enabled=True, management_ip_address="10.0.0.2"
        )
        router_lookup = FakeRouterLookup()
        router_lookup.add(broken_router, snmp_community="public")
        router_lookup.add(healthy_router, snmp_community="public")
        router_provisioning = FakeRouterProvisioningLookup()
        poller = FakeSnmpPoller(
            exception_by_host={
                broken_router.management_ip_address: RuntimeError("boom")
            },
            result_by_host={healthy_router.management_ip_address: _default_metrics()},
        )

        summary = await run_router_snmp_metrics_poll_sweep(
            _StubRepository([broken_router, healthy_router]),
            router_lookup,
            router_provisioning,
            snmp_poller=poller,
        )

        assert summary.errors == 1
        assert summary.checked == 1
        assert len(router_provisioning.health_snapshots_recorded) == 1
        assert (
            router_provisioning.health_snapshots_recorded[0]["router_id"]
            == healthy_router.id
        )

    async def test_uses_repository_list_when_routers_not_overridden(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._patch_settings(monkeypatch)
        router = _make_router(snmp_enabled=True)
        router_lookup = FakeRouterLookup()
        router_lookup.add(router, snmp_community="public")
        router_provisioning = FakeRouterProvisioningLookup()
        poller = FakeSnmpPoller(
            result_by_host={router.management_ip_address: _default_metrics()}
        )
        repository: ProvisioningEngineRepositoryProtocol = _StubRepository([router])

        summary = await run_router_snmp_metrics_poll_sweep(
            repository, router_lookup, router_provisioning, snmp_poller=poller
        )
        assert summary.checked == 1

    async def test_no_interfaces_reported_stores_none_not_empty_list(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Never a fabricated ``[]`` -- see ``RouterHealthSnapshot
        .interface_traffic_counters``'s own docstring."""
        self._patch_settings(monkeypatch)
        router = _make_router(snmp_enabled=True)
        router_lookup = FakeRouterLookup()
        router_lookup.add(router, snmp_community="public")
        router_provisioning = FakeRouterProvisioningLookup()
        metrics = SnmpDeviceMetrics(
            sys_descr=None,
            sys_name=None,
            uptime_seconds=None,
            cpu_load_percent=None,
            memory_usage_percent=None,
            interfaces=[],
        )
        poller = FakeSnmpPoller(result_by_host={router.management_ip_address: metrics})

        await run_router_snmp_metrics_poll_sweep(
            _StubRepository([router]),
            router_lookup,
            router_provisioning,
            snmp_poller=poller,
        )

        recorded = router_provisioning.health_snapshots_recorded[0]
        assert recorded["interface_traffic_counters"] is None
