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

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.location.exceptions import CrossLocationScopeAccessError
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
    DiagnosticCooldownError,
    DiagnosticRateLimitExceededError,
    DiagnosticRunNotFoundError,
    DiagnosticsDeviceConnectionError,
    DiagnosticsDeviceOperationError,
    InvalidDiagnosticTargetError,
    MissingDiagnosticsCredentialsError,
)
from app.domains.network_diagnostics.models import DiagnosticRun
from app.domains.network_diagnostics.router import router as network_diagnostics_router
from app.domains.network_diagnostics.service import (
    NetworkDiagnosticsService,
    purge_expired_runs,
)
from app.domains.network_diagnostics.validators import normalize_target
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
        location_id: uuid.UUID | None = None,
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
        if location_id is not None:
            values = [v for v in values if v.location_id == location_id]
        values.sort(key=lambda v: v.created_at, reverse=True)
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))

    async def delete_runs_older_than(self, cutoff: datetime, *, batch_size: int) -> int:
        doomed = [
            run_id
            for run_id, run in sorted(
                self.runs.items(), key=lambda kv: kv[1].created_at
            )
            if run.created_at < cutoff
        ][:batch_size]
        for run_id in doomed:
            del self.runs[run_id]
        return len(doomed)


@dataclass
class FakeAuditLogWriter:
    entries: list[dict[str, object]] = field(default_factory=list)

    async def create_audit_log_entry(self, **fields: object) -> dict[str, object]:
        self.entries.append(fields)
        return fields


@dataclass
class FakeRedis:
    """The four Redis operations the two abuse controls actually use.

    Deliberately not a full fake: ``SET NX EX`` (the cooldown),
    ``INCR``/``EXPIRE`` (the per-organization window) and ``TTL`` (both
    error messages' real remaining time) are the whole surface, and a
    fake that implemented more than the code under test uses would be
    the same mistake ``test_live_sessions.py``'s rewritten fake was
    called out for.
    """

    store: dict[str, int] = field(default_factory=dict)
    ttls: dict[str, int] = field(default_factory=dict)

    async def set(
        self, key: str, value: object, *, nx: bool = False, ex: int | None = None
    ) -> bool | None:
        if nx and key in self.store:
            return None
        self.store[key] = int(value) if str(value).isdigit() else 1
        if ex is not None:
            self.ttls[key] = ex
        return True

    async def incr(self, key: str) -> int:
        self.store[key] = self.store.get(key, 0) + 1
        return self.store[key]

    async def expire(self, key: str, seconds: int) -> bool:
        self.ttls[key] = seconds
        return True

    async def ttl(self, key: str) -> int:
        return self.ttls.get(key, -1)


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
    redis: FakeRedis | None = None


def make_harness(
    *,
    adapter: FakeDiagnosticsAdapter | None = None,
    redis: FakeRedis | None = None,
) -> Harness:
    repository = FakeNetworkDiagnosticsRepository()
    router_lookup = FakeRouterLookup()
    audit_writer = FakeAuditLogWriter()
    adapter = adapter or FakeDiagnosticsAdapter()
    service = NetworkDiagnosticsService(
        repository,
        router_lookup,
        audit_writer=audit_writer,
        device_adapter_resolver=lambda vendor: adapter,
        redis=redis,
    )
    return Harness(
        service=service,
        repository=repository,
        router_lookup=router_lookup,
        audit_writer=audit_writer,
        adapter=adapter,
        redis=redis,
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


# ============================================================================
# Cross-site scoping -- the defect this branch exists to close
# ============================================================================
#
# A caller whose permission was checked at LOCATION scope for site A could
# name site B's router in the path and run a command on its hardware. Both
# sites belong to one organization, so RouterService's organization guard
# saw nothing wrong, and ScopeResolver.satisfies compares only the
# location_id the caller supplied in X-Location-Id -- never the location
# the router in the URL actually belongs to. Two seeded LOCATION-scoped
# roles (network-administrator, network-engineer) hold
# network_diagnostics.execute, so it was reachable from an ordinary
# site-level networking account.


class TestCrossSiteScoping:
    def _two_sites(self):
        organization_id = uuid.uuid4()
        site_a = uuid.uuid4()
        site_b = uuid.uuid4()
        h = make_harness()
        router_a = h.router_lookup.add(
            _make_router(organization_id=organization_id, location_id=site_a)
        )
        router_b = h.router_lookup.add(
            _make_router(organization_id=organization_id, location_id=site_b)
        )
        return h, organization_id, site_a, site_b, router_a, router_b

    async def test_ping_on_a_sibling_sites_router_is_refused(self) -> None:
        h, org, site_a, _site_b, _a, router_b = self._two_sites()
        with pytest.raises(CrossLocationScopeAccessError):
            await h.service.run_ping(
                router_b.id,
                target="1.1.1.1",
                actor_user_id=uuid.uuid4(),
                requesting_organization_id=org,
                scope_location_id=site_a,
            )

    async def test_a_refused_ping_never_reaches_the_device_or_the_history(
        self,
    ) -> None:
        """The guard must run before anything touches the router. A refusal
        that still sent packets would defeat the point."""
        h, org, site_a, _site_b, _a, router_b = self._two_sites()
        with pytest.raises(CrossLocationScopeAccessError):
            await h.service.run_ping(
                router_b.id,
                target="1.1.1.1",
                actor_user_id=uuid.uuid4(),
                requesting_organization_id=org,
                scope_location_id=site_a,
            )
        assert h.adapter.calls == []
        assert h.repository.runs == {}
        assert h.audit_writer.entries == []

    async def test_traceroute_on_a_sibling_sites_router_is_refused(self) -> None:
        h, org, site_a, _site_b, _a, router_b = self._two_sites()
        with pytest.raises(CrossLocationScopeAccessError):
            await h.service.run_traceroute(
                router_b.id,
                target="1.1.1.1",
                actor_user_id=uuid.uuid4(),
                requesting_organization_id=org,
                scope_location_id=site_a,
            )

    async def test_ping_on_the_callers_own_site_still_works(self) -> None:
        h, org, site_a, _site_b, router_a, _b = self._two_sites()
        run = await h.service.run_ping(
            router_a.id,
            target="1.1.1.1",
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=org,
            scope_location_id=site_a,
        )
        assert run.status == DiagnosticStatus.SUCCESS.value
        assert run.location_id == site_a

    async def test_an_organization_scoped_caller_is_unaffected(self) -> None:
        """``scope_location_id is None`` means the permission check ran at
        ORGANIZATION or GLOBAL scope, which the organization guard already
        covers -- the location guard must not narrow such a caller."""
        h, org, _site_a, _site_b, _a, router_b = self._two_sites()
        run = await h.service.run_ping(
            router_b.id,
            target="1.1.1.1",
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=org,
            scope_location_id=None,
        )
        assert run.status == DiagnosticStatus.SUCCESS.value

    async def test_list_runs_router_id_query_cannot_name_a_sibling_site(self) -> None:
        """``GET /runs?router_id=`` is the read half of the same shape: a
        caller-supplied target the permission check never looked at."""
        h, org, site_a, _site_b, _a, router_b = self._two_sites()
        with pytest.raises(CrossLocationScopeAccessError):
            await h.service.list_runs(
                requesting_organization_id=org,
                router_id=router_b.id,
                scope_location_id=site_a,
            )

    async def test_list_runs_without_a_router_narrows_to_the_scoped_site(
        self,
    ) -> None:
        """Previously an organization-wide read for a location-scoped
        caller: location_id was written on every row and never filtered on."""
        h, org, site_a, _site_b, router_a, router_b = self._two_sites()
        actor = uuid.uuid4()
        await h.service.run_ping(
            router_a.id,
            target="1.1.1.1",
            actor_user_id=actor,
            requesting_organization_id=org,
            scope_location_id=site_a,
        )
        await h.service.run_ping(
            router_b.id,
            target="1.1.1.1",
            actor_user_id=actor,
            requesting_organization_id=org,
            scope_location_id=None,
        )
        runs, meta = await h.service.list_runs(
            requesting_organization_id=org, scope_location_id=site_a
        )
        assert meta.total_items == 1
        assert [r.location_id for r in runs] == [site_a]

    async def test_list_runs_unscoped_still_sees_the_whole_organization(self) -> None:
        h, org, site_a, _site_b, router_a, router_b = self._two_sites()
        actor = uuid.uuid4()
        for router in (router_a, router_b):
            await h.service.run_ping(
                router.id,
                target="1.1.1.1",
                actor_user_id=actor,
                requesting_organization_id=org,
                scope_location_id=None,
            )
        _runs, meta = await h.service.list_runs(
            requesting_organization_id=org, scope_location_id=None
        )
        assert meta.total_items == 2

    async def test_get_run_refuses_a_sibling_sites_run(self) -> None:
        h, org, site_a, _site_b, _a, router_b = self._two_sites()
        run = await h.service.run_ping(
            router_b.id,
            target="1.1.1.1",
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=org,
            scope_location_id=None,
        )
        with pytest.raises(CrossLocationScopeAccessError):
            await h.service.get_run(
                run.id, requesting_organization_id=org, scope_location_id=site_a
            )


# ============================================================================
# Target validation
# ============================================================================


class TestNormalizeTarget:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("1.1.1.1", "1.1.1.1"),
            ("  8.8.8.8  ", "8.8.8.8"),
            # Private is deliberately allowed: the venue's own gateway is
            # the single most useful thing this tool pings.
            ("192.168.1.1", "192.168.1.1"),
            ("10.0.0.1", "10.0.0.1"),
            ("Example.COM.", "example.com"),
            ("gateway", "gateway"),
            ("2001:4860:4860::8888", "2001:4860:4860::8888"),
        ],
    )
    def test_accepts_and_canonicalizes(self, raw: str, expected: str) -> None:
        assert normalize_target(raw) == expected

    @pytest.mark.parametrize(
        "raw",
        [
            "127.0.0.1",
            "::1",
            "0.0.0.0",
            "::",
            "224.0.0.1",
            "ff02::1",
            "169.254.169.254",
            "fe80::1",
            "255.255.255.255",
            "240.0.0.1",
        ],
    )
    def test_rejects_addresses_that_are_meaningless_or_abuse_shaped(
        self, raw: str
    ) -> None:
        with pytest.raises(InvalidDiagnosticTargetError):
            normalize_target(raw)

    @pytest.mark.parametrize(
        "raw",
        [
            "",
            "   ",
            "http://example.com",
            "example.com/path",
            "example.com:8291",
            "1.1.1.1 count=99999",
            "-notahost",
            "exa mple.com",
            "a" * 300,
        ],
    )
    def test_rejects_anything_that_is_not_an_address_or_a_hostname(
        self, raw: str
    ) -> None:
        with pytest.raises(InvalidDiagnosticTargetError):
            normalize_target(raw)


class TestServiceValidatesTarget:
    async def test_an_invalid_target_is_refused_before_the_device(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        with pytest.raises(InvalidDiagnosticTargetError):
            await h.service.run_ping(
                router.id,
                target="127.0.0.1",
                actor_user_id=uuid.uuid4(),
                requesting_organization_id=router.organization_id,
            )
        assert h.adapter.calls == []
        assert h.repository.runs == {}

    async def test_the_normalized_target_is_what_is_persisted(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        run = await h.service.run_ping(
            router.id,
            target="  Example.COM.  ",
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
        )
        assert run.target == "example.com"
        assert h.adapter.calls[0]["target"] == "example.com"


# ============================================================================
# Abuse controls
# ============================================================================


class TestAbuseControls:
    async def _ping(self, h: Harness, router: Router):
        return await h.service.run_ping(
            router.id,
            target="1.1.1.1",
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
        )

    async def test_a_second_run_on_the_same_router_is_refused(self) -> None:
        h = make_harness(redis=FakeRedis())
        router = h.router_lookup.add(_make_router())
        await self._ping(h, router)
        with pytest.raises(DiagnosticCooldownError) as exc:
            await self._ping(h, router)
        assert exc.value.retry_after_seconds > 0

    async def test_the_cooldown_is_per_router_not_global(self) -> None:
        h = make_harness(redis=FakeRedis())
        organization_id = uuid.uuid4()
        first = h.router_lookup.add(_make_router(organization_id=organization_id))
        second = h.router_lookup.add(_make_router(organization_id=organization_id))
        await self._ping(h, first)
        run = await self._ping(h, second)
        assert run.status == DiagnosticStatus.SUCCESS.value

    async def test_the_organization_window_bounds_router_rotation(self) -> None:
        """A per-router cooldown alone does not bound volume: an
        organization with many routers can rotate through them. The
        organization key is the one component the caller cannot vary."""
        redis = FakeRedis()
        h = make_harness(redis=redis)
        organization_id = uuid.uuid4()
        routers = [
            h.router_lookup.add(_make_router(organization_id=organization_id))
            for _ in range(3)
        ]
        # Pre-load the window to one below its cap so the test does not
        # have to run 120 real diagnostics.
        key = "network_diagnostics:rate:" f"{organization_id}"
        redis.store[key] = 119
        redis.ttls[key] = 3600
        await self._ping(h, routers[0])  # 120th -- still allowed
        with pytest.raises(DiagnosticRateLimitExceededError) as exc:
            await self._ping(h, routers[1])  # 121st -- refused
        assert exc.value.retry_after_seconds == 3600

    async def test_without_redis_both_controls_are_no_ops(self) -> None:
        """Mirrors IspService: unit tests and any deployment without a
        Redis client must still be able to run a diagnostic."""
        h = make_harness(redis=None)
        router = h.router_lookup.add(_make_router())
        await self._ping(h, router)
        run = await self._ping(h, router)
        assert run.status == DiagnosticStatus.SUCCESS.value

    async def test_a_refused_run_is_not_recorded(self) -> None:
        h = make_harness(redis=FakeRedis())
        router = h.router_lookup.add(_make_router())
        await self._ping(h, router)
        with pytest.raises(DiagnosticCooldownError):
            await self._ping(h, router)
        assert len(h.repository.runs) == 1


# ============================================================================
# The deadline -- the stall that used to be a bare 500 with no row
# ============================================================================


class TestDeadline:
    async def test_a_stalled_device_is_recorded_as_failed_not_raised(self) -> None:
        """Previously: TimeoutError escaped every except clause in the
        chain (it is an OSError, not a LibRouterosError, not a
        Diagnostics*Error) and surfaced as an HTTP 500 with no
        DiagnosticRun row at all -- the one failure the page most needs to
        report honestly was the one that left no trace."""

        class StallingAdapter(FakeDiagnosticsAdapter):
            async def ping(self, credentials, *, target, count, timeout_seconds):
                self.calls.append({"op": "ping", "target": target, "count": count})
                await asyncio.sleep(5)
                raise AssertionError("should never get here")

        h = make_harness(adapter=StallingAdapter())
        router = h.router_lookup.add(_make_router())
        run = await h.service.run_ping(
            router.id,
            target="1.1.1.1",
            timeout_seconds=1,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
        )
        assert run.status == DiagnosticStatus.FAILED.value
        assert "did not complete within 1s" in run.error_message
        assert run.id in h.repository.runs

    async def test_a_socket_timeout_from_the_adapter_is_also_recorded(self) -> None:
        """The second line of defence: even if a bare TimeoutError escapes
        the gateway (as it did before this branch), the domain records it
        rather than letting it become a 500."""
        adapter = FakeDiagnosticsAdapter(should_raise=TimeoutError())
        h = make_harness(adapter=adapter)
        router = h.router_lookup.add(_make_router())
        run = await h.service.run_ping(
            router.id,
            target="1.1.1.1",
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
        )
        assert run.status == DiagnosticStatus.FAILED.value
        assert run.error_message

    async def test_a_long_error_message_is_truncated_to_the_column_width(
        self,
    ) -> None:
        adapter = FakeDiagnosticsAdapter(
            should_raise=DiagnosticsDeviceOperationError("ping", "x" * 900)
        )
        h = make_harness(adapter=adapter)
        router = h.router_lookup.add(_make_router())
        run = await h.service.run_ping(
            router.id,
            target="1.1.1.1",
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
        )
        assert len(run.error_message) == 500


# ============================================================================
# Retention
# ============================================================================


class TestRetention:
    async def _seed(self, h: Harness, *, ages_in_days: list[int]) -> None:
        router = h.router_lookup.add(_make_router())
        now = _now()
        for age in ages_in_days:
            run = DiagnosticRun(
                **_base_fields(
                    created_at=now - timedelta(days=age),
                    router_id=router.id,
                    organization_id=router.organization_id,
                    location_id=router.location_id,
                    diagnostic_type=DiagnosticType.PING.value,
                    target="1.1.1.1",
                    status=DiagnosticStatus.SUCCESS.value,
                    result={},
                    error_message=None,
                    executed_by_user_id=None,
                )
            )
            h.repository.runs[run.id] = run

    async def test_deletes_only_runs_past_the_window(self) -> None:
        h = make_harness()
        await self._seed(h, ages_in_days=[1, 30, 89, 91, 200])
        summary = await purge_expired_runs(h.repository)
        assert summary["deleted"] == 2
        assert len(h.repository.runs) == 3

    async def test_a_backlog_larger_than_the_cap_drains_over_several_runs(
        self,
    ) -> None:
        """The per-run cap is what keeps the first sweep after deploy from
        being one very long transaction; it must be visible, not silent."""
        h = make_harness()
        await self._seed(h, ages_in_days=[200] * 10)
        summary = await purge_expired_runs(h.repository, batch_size=2, max_batches=3)
        assert summary["deleted"] == 6
        assert summary["batches"] == 3
        assert summary["hit_batch_cap"] is True
        assert len(h.repository.runs) == 4

        rest = await purge_expired_runs(h.repository, batch_size=2, max_batches=3)
        assert rest["deleted"] == 4
        assert rest["hit_batch_cap"] is False
        assert h.repository.runs == {}

    async def test_nothing_to_purge_is_one_batch_and_no_deletions(self) -> None:
        h = make_harness()
        await self._seed(h, ages_in_days=[1, 2])
        summary = await purge_expired_runs(h.repository)
        assert summary["deleted"] == 0
        assert summary["batches"] == 1
        assert summary["hit_batch_cap"] is False


# ============================================================================
# Structural: the location dependency cannot be dropped by a future edit
# ============================================================================


class TestEveryRouteResolvesLocationScope:
    def test_every_route_resolves_current_location(self) -> None:
        """Mirrors the structural check #147 added for the eight guest
        routes: ``enforce_target_location`` is only as good as the
        ``CurrentLocation`` dependency feeding it, and a future edit that
        quietly drops the dependency would re-open the hole with every
        behavioural test still passing. This fails here instead."""
        from app.domains.rbac.dependencies import CurrentLocation

        for route in network_diagnostics_router.routes:
            resolved = [dependency.call for dependency in route.dependant.dependencies]
            assert CurrentLocation in resolved, (
                f"{route.path} ({route.methods}) does not resolve CurrentLocation, "
                "so its cross-site guard has nothing to compare against"
            )


# ============================================================================
# The retention Celery task
# ============================================================================


class TestRetentionTask:
    def test_the_task_delegates_through_the_async_bridge(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The "monkeypatch the bridge, call the plain task function
        directly" contract every other domain's task test uses -- proves
        the task body is wired to the real async function without needing
        a Celery worker, a broker or a database.

        It also pins the thing that is easy to get wrong here: the bridge
        must be ``app.core.async_task_bridge.run_celery_task``, never a
        bare ``asyncio.run``, for the asyncpg cross-event-loop reason that
        module documents.
        """
        import app.domains.network_diagnostics.tasks as tasks_module

        captured: dict[str, object] = {}

        def _fake_bridge(coro):
            captured["coroutine_name"] = coro.cr_code.co_name
            coro.close()
            return {"deleted": 7, "batches": 1, "cutoff": "x", "hit_batch_cap": False}

        monkeypatch.setattr(tasks_module, "run_celery_task", _fake_bridge)
        summary = tasks_module.run_diagnostic_run_retention_sweep()

        assert summary["deleted"] == 7
        assert captured["coroutine_name"] == "_run_diagnostic_run_retention_sweep_async"

    def test_the_sweep_is_registered_on_the_default_queue(self) -> None:
        """Not on DEVICE_IO_QUEUE_NAME: this sweep touches only this
        platform's own database and never opens a RouterOS connection, so
        routing it onto the queue reserved for real per-router device I/O
        would put a pure-DB job behind multi-second device round trips."""
        from app.core.celery_app import DEVICE_IO_QUEUE_NAME, celery_app
        from app.domains.network_diagnostics.constants import (
            TASK_RUN_DIAGNOSTIC_RUN_RETENTION_SWEEP,
        )

        routes = celery_app.conf.task_routes or {}
        assert TASK_RUN_DIAGNOSTIC_RUN_RETENTION_SWEEP not in routes
        assert DEVICE_IO_QUEUE_NAME  # the queue this task deliberately avoids
