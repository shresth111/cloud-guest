"""Unit tests for the Network Diagnostics domain: the pure RouterOS
reply-parsing helpers (``ping``/``traceroute`` row parsing, duration
parsing) and ``NetworkDiagnosticsService``'s ``run_ping``/
``run_traceroute``/``get_run``/``list_runs`` composed against small,
hand-rolled in-memory fakes for its own repository, the composed
``RouterLookupProtocol``, and an injectable diagnostics adapter -- mirrors
``tests/unit/test_isp.py``'s own identical "fake the narrow Protocol
boundary, inject a fake adapter" precedent. A structural RBAC check
confirms every route carries a permission dependency.

Follows this project's plain-``assert``/native-``async def`` style;
``asyncio_mode = "auto"`` runs async tests directly.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.network_diagnostics.constants import DiagnosticStatus, DiagnosticType
from app.domains.network_diagnostics.device_adapters import (
    DiagnosticsCredentials,
    PingResult,
    TracerouteResult,
    _parse_ping_rows,
    _parse_routeros_duration_ms,
    _parse_traceroute_rows,
)
from app.domains.network_diagnostics.exceptions import (
    CrossOrganizationDiagnosticRunAccessError,
    DiagnosticRunNotFoundError,
    DiagnosticsDeviceConnectionError,
    DiagnosticsDeviceOperationError,
    MissingDiagnosticsCredentialsError,
)
from app.domains.network_diagnostics.models import DiagnosticRun
from app.domains.network_diagnostics.router import router as network_diagnostics_router
from app.domains.network_diagnostics.service import NetworkDiagnosticsService
from app.domains.router.exceptions import RouterNotFoundError
from app.domains.router.models import Router

# ============================================================================
# Pure parsing helpers
# ============================================================================


class TestParseRoutersDurationMs:
    def test_parses_a_simple_millisecond_value(self) -> None:
        assert _parse_routeros_duration_ms("12ms") == 12.0

    def test_parses_a_compound_value(self) -> None:
        assert _parse_routeros_duration_ms("1ms200us") == 1.2

    def test_parses_seconds(self) -> None:
        assert _parse_routeros_duration_ms("2s") == 2000.0

    def test_returns_none_for_empty_or_unparsable(self) -> None:
        assert _parse_routeros_duration_ms("") is None
        assert _parse_routeros_duration_ms(None) is None
        assert _parse_routeros_duration_ms("garbage") is None


class TestParsePingRows:
    def test_reads_the_last_cumulative_row(self) -> None:
        rows = [
            {"sent": "1", "received": "1"},
            {
                "sent": "5",
                "received": "5",
                "packet-loss": "0",
                "avg-rtt": "1ms200us",
            },
        ]
        result = _parse_ping_rows(rows, requested_count=5)
        assert result == PingResult(
            sent=5, received=5, packet_loss_percentage=0.0, avg_rtt_ms=1.2
        )

    def test_empty_rows_is_total_loss(self) -> None:
        result = _parse_ping_rows([], requested_count=5)
        assert result.sent == 5
        assert result.received == 0
        assert result.packet_loss_percentage == 100.0
        assert result.avg_rtt_ms is None

    def test_derives_packet_loss_when_field_missing(self) -> None:
        rows = [{"sent": "4", "received": "2"}]
        result = _parse_ping_rows(rows, requested_count=4)
        assert result.packet_loss_percentage == 50.0


class TestParseTracerouteRows:
    def test_collapses_consecutive_same_address_rows_into_one_hop(self) -> None:
        rows = [
            {"address": "10.0.0.1", "loss": "0", "avg": "1ms"},
            {"address": "10.0.0.1", "loss": "0", "avg": "2ms"},
            {"address": "8.8.8.8", "loss": "0", "avg": "15ms"},
        ]
        hops = _parse_traceroute_rows(rows)
        assert [h.hop_number for h in hops] == [1, 2]
        assert hops[0].address == "10.0.0.1"
        assert hops[0].avg_rtt_ms == 2.0
        assert hops[1].address == "8.8.8.8"

    def test_a_timed_out_hop_has_no_address_and_full_loss(self) -> None:
        rows = [{"address": None, "loss": "100"}]
        (hop,) = _parse_traceroute_rows(rows)
        assert hop.address is None
        assert hop.packet_loss_percentage == 100.0

    def test_empty_rows_returns_no_hops(self) -> None:
        assert _parse_traceroute_rows([]) == []


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
    *, organization_id: uuid.UUID | None = None, location_id: uuid.UUID | None = None
) -> Router:
    return Router(
        **_base_fields(
            organization_id=organization_id or uuid.uuid4(),
            location_id=location_id or uuid.uuid4(),
            name="Test Router",
            serial_number=f"SN-{uuid.uuid4().hex[:8]}",
            mac_address="AA:BB:CC:DD:EE:FF",
            model="RB4011",
            vendor="mikrotik",
            routeros_version=None,
            management_ip_address="10.0.0.1",
            public_ip_address=None,
            status="online",
            last_seen_at=None,
            last_health_check_at=None,
            health_status=None,
            api_username="admin",
            api_credentials_encrypted="encrypted-placeholder",
            settings={},
        )
    )


# ============================================================================
# Fakes
# ============================================================================


@dataclass
class FakeNetworkDiagnosticsRepository:
    runs: dict[uuid.UUID, DiagnosticRun] = field(default_factory=dict)

    async def create_run(self, **fields: object) -> DiagnosticRun:
        run = DiagnosticRun(**_base_fields(**fields))
        self.runs[run.id] = run
        return run

    async def get_run_by_id(self, run_id: uuid.UUID) -> DiagnosticRun | None:
        return self.runs.get(run_id)

    async def list_runs(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
    ):
        values = list(self.runs.values())
        if requesting_organization_id is not None:
            values = [
                v for v in values if v.organization_id == requesting_organization_id
            ]
        if router_id is not None:
            values = [v for v in values if v.router_id == router_id]
        values.sort(key=lambda v: v.created_at, reverse=True)
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))


@dataclass
class FakeAuditLogWriter:
    entries: list[dict[str, object]] = field(default_factory=list)

    async def create_audit_log_entry(self, **fields: object) -> dict[str, object]:
        self.entries.append(fields)
        return fields


@dataclass
class FakeRouterLookup:
    routers: dict[uuid.UUID, Router] = field(default_factory=dict)
    secrets: dict[uuid.UUID, str | None] = field(default_factory=dict)

    def add(self, router: Router, *, secret: str | None = "decrypted-secret") -> Router:
        self.routers[router.id] = router
        self.secrets[router.id] = secret
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
        if (
            requesting_organization_id is not None
            and router.organization_id != requesting_organization_id
        ):
            raise RouterNotFoundError(router_id)
        return router

    def get_decrypted_api_secret(self, router: Router) -> str | None:
        return self.secrets.get(router.id)


@dataclass
class FakeDiagnosticsAdapter:
    vendor: str = "mikrotik"
    next_ping_result: PingResult | None = None
    next_traceroute_result: TracerouteResult | None = None
    should_raise: Exception | None = None
    calls: list[dict[str, object]] = field(default_factory=list)

    async def ping(
        self,
        credentials: DiagnosticsCredentials,
        *,
        target: str,
        count: int,
        timeout_seconds: int,
    ) -> PingResult:
        self.calls.append({"op": "ping", "target": target, "count": count})
        if self.should_raise is not None:
            raise self.should_raise
        return self.next_ping_result or PingResult(
            sent=count, received=count, packet_loss_percentage=0.0, avg_rtt_ms=10.0
        )

    async def traceroute(
        self,
        credentials: DiagnosticsCredentials,
        *,
        target: str,
        max_hops: int,
        timeout_seconds: int,
    ) -> TracerouteResult:
        self.calls.append({"op": "traceroute", "target": target, "max_hops": max_hops})
        if self.should_raise is not None:
            raise self.should_raise
        return self.next_traceroute_result or TracerouteResult(hops=[])


# ============================================================================
# Harness
# ============================================================================


@dataclass
class Harness:
    service: NetworkDiagnosticsService
    repository: FakeNetworkDiagnosticsRepository
    router_lookup: FakeRouterLookup
    audit_writer: FakeAuditLogWriter
    adapter: FakeDiagnosticsAdapter


def make_harness(*, adapter: FakeDiagnosticsAdapter | None = None) -> Harness:
    repository = FakeNetworkDiagnosticsRepository()
    router_lookup = FakeRouterLookup()
    audit_writer = FakeAuditLogWriter()
    adapter = adapter or FakeDiagnosticsAdapter()
    service = NetworkDiagnosticsService(
        repository,
        router_lookup,
        audit_writer=audit_writer,
        device_adapter_resolver=lambda vendor: adapter,
    )
    return Harness(
        service=service,
        repository=repository,
        router_lookup=router_lookup,
        audit_writer=audit_writer,
        adapter=adapter,
    )


# ============================================================================
# run_ping
# ============================================================================


class TestRunPing:
    async def test_records_a_successful_run(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)

        run = await h.service.run_ping(
            router.id,
            target="8.8.8.8",
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
        )

        assert run.diagnostic_type == DiagnosticType.PING.value
        assert run.target == "8.8.8.8"
        assert run.status == DiagnosticStatus.SUCCESS.value
        assert run.result["received"] == run.result["sent"]
        assert run.error_message is None
        assert len(h.audit_writer.entries) == 1

    async def test_records_a_failed_run_on_device_connection_error(self) -> None:
        adapter = FakeDiagnosticsAdapter(
            should_raise=DiagnosticsDeviceConnectionError("10.0.0.1", "refused")
        )
        h = make_harness(adapter=adapter)
        router = _make_router()
        h.router_lookup.add(router)

        run = await h.service.run_ping(
            router.id,
            target="8.8.8.8",
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        assert run.status == DiagnosticStatus.FAILED.value
        assert run.result == {}
        assert run.error_message is not None
        assert "refused" in run.error_message

    async def test_missing_credentials_raises_directly_not_recorded(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router, secret=None)

        with pytest.raises(MissingDiagnosticsCredentialsError):
            await h.service.run_ping(
                router.id,
                target="8.8.8.8",
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )
        assert h.repository.runs == {}

    async def test_unknown_router_raises(self) -> None:
        h = make_harness()
        with pytest.raises(RouterNotFoundError):
            await h.service.run_ping(
                uuid.uuid4(),
                target="8.8.8.8",
                actor_user_id=None,
                requesting_organization_id=None,
            )


# ============================================================================
# run_traceroute
# ============================================================================


class TestRunTraceroute:
    async def test_records_a_successful_run(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)

        run = await h.service.run_traceroute(
            router.id,
            target="8.8.8.8",
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
        )

        assert run.diagnostic_type == DiagnosticType.TRACEROUTE.value
        assert run.status == DiagnosticStatus.SUCCESS.value
        assert run.result == {"hops": []}

    async def test_records_a_failed_run_on_device_operation_error(self) -> None:
        adapter = FakeDiagnosticsAdapter(
            should_raise=DiagnosticsDeviceOperationError("traceroute", "!trap")
        )
        h = make_harness(adapter=adapter)
        router = _make_router()
        h.router_lookup.add(router)

        run = await h.service.run_traceroute(
            router.id,
            target="8.8.8.8",
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )
        assert run.status == DiagnosticStatus.FAILED.value
        assert run.error_message is not None


# ============================================================================
# get_run / list_runs
# ============================================================================


class TestGetAndListRuns:
    async def test_get_run_returns_created_run(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        run = await h.service.run_ping(
            router.id,
            target="8.8.8.8",
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        fetched = await h.service.get_run(
            run.id, requesting_organization_id=router.organization_id
        )
        assert fetched.id == run.id

    async def test_get_run_not_found_raises(self) -> None:
        h = make_harness()
        with pytest.raises(DiagnosticRunNotFoundError):
            await h.service.get_run(uuid.uuid4())

    async def test_get_run_cross_organization_raises(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        run = await h.service.run_ping(
            router.id,
            target="8.8.8.8",
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        with pytest.raises(CrossOrganizationDiagnosticRunAccessError):
            await h.service.get_run(run.id, requesting_organization_id=uuid.uuid4())

    async def test_list_runs_filters_by_router(self) -> None:
        h = make_harness()
        router_a = _make_router()
        router_b = _make_router()
        h.router_lookup.add(router_a)
        h.router_lookup.add(router_b)
        run_a = await h.service.run_ping(
            router_a.id,
            target="8.8.8.8",
            actor_user_id=None,
            requesting_organization_id=router_a.organization_id,
        )
        await h.service.run_ping(
            router_b.id,
            target="8.8.8.8",
            actor_user_id=None,
            requesting_organization_id=router_b.organization_id,
        )

        runs, meta = await h.service.list_runs(
            requesting_organization_id=None, router_id=router_a.id
        )
        assert meta.total_items == 1
        assert runs[0].id == run_a.id


# ============================================================================
# RBAC -- every route requires a permission dependency
# ============================================================================


class TestEveryRouteRequiresPermission:
    def test_every_network_diagnostics_route_has_a_permission_dependency(
        self,
    ) -> None:
        assert len(network_diagnostics_router.routes) == 4
        for route in network_diagnostics_router.routes:
            assert (
                route.dependencies != []
            ), f"{route.path} ({route.methods}) has no permission dependency"
