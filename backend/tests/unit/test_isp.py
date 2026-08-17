"""Unit tests for the ISP Management domain: WAN/ISP link CRUD (tenant
isolation, primary-uniqueness), real health-check recording and
classification, threshold-gated automatic failover/failback (never on a
single blip), manual failover/failback triggers, the computed
availability-percentage read-model, the platform-wide health-check sweep's
per-link failure isolation, and a structural RBAC check that every route
carries a permission dependency.

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_queue_management.py``); ``asyncio_mode = "auto"`` runs
async tests directly. ``IspService`` is exercised against small,
hand-rolled in-memory fakes for its own repository and every composed
cross-domain protocol (``RouterLookupProtocol``) and a controllable fake
health adapter -- mirrors ``test_queue_management.py``'s own identical
"fake the narrow Protocol boundary" precedent. Real device I/O
(``device_adapters.py``) is not covered here (no live MikroTik device
anywhere in this sandbox -- see that module's own docstring).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.isp.constants import (
    DEFAULT_CONSECUTIVE_FAILURES_BEFORE_FAILOVER,
    SPEED_TEST_DOWNLOAD_URL,
    SPEED_TEST_TIMEOUT_SECONDS,
    HealthStatus,
    IspConnectionMode,
    IspLinkRole,
    IspLinkType,
    WanRoutingMode,
)
from app.domains.isp.device_adapters import IspCredentials, PingResult, SpeedTestResult
from app.domains.isp.exceptions import (
    CrossOrganizationIspLinkAccessError,
    IspDeviceConnectionError,
    IspHealthCheckTargetUnavailableError,
    IspLinkDisabledError,
    IspLinkNotFoundError,
    IspMissingCredentialsError,
    IspNoBackupLinkAvailableError,
    IspPrimaryLinkAlreadyExistsError,
    MixedWanRoutingWeightsError,
)
from app.domains.isp.models import IspHealthCheck, IspLink
from app.domains.isp.router import router as isp_router
from app.domains.isp.service import (
    HealthCheckSweepSummary,
    IspService,
    SpeedTestOutcome,
    TrafficCounters,
    run_health_check_sweep,
)
from app.domains.isp.validators import validate_wan_routing_weights
from app.domains.router.exceptions import RouterNotFoundError
from app.domains.router.models import Router

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
    organization_id: uuid.UUID | None = None,
    location_id: uuid.UUID | None = None,
    vendor: str = "mikrotik",
) -> Router:
    return Router(
        **_base_fields(
            organization_id=organization_id or uuid.uuid4(),
            location_id=location_id or uuid.uuid4(),
            name="Test Router",
            serial_number=f"SN-{uuid.uuid4().hex[:8]}",
            mac_address="AA:BB:CC:DD:EE:FF",
            model="RB4011",
            vendor=vendor,
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
            wan_routing_mode="load_balance",
        )
    )


# ============================================================================
# Fakes: repository
# ============================================================================


@dataclass
class FakeIspRepository:
    links: dict[uuid.UUID, IspLink] = field(default_factory=dict)
    health_checks: dict[uuid.UUID, IspHealthCheck] = field(default_factory=dict)

    async def create_link(self, **fields: object) -> IspLink:
        link = IspLink(**_base_fields(**fields))
        self.links[link.id] = link
        return link

    async def get_link_by_id(
        self, link_id: uuid.UUID, *, include_deleted: bool = False
    ) -> IspLink | None:
        link = self.links.get(link_id)
        if link is None or (link.is_deleted and not include_deleted):
            return None
        return link

    async def get_link_for_update(self, link_id: uuid.UUID) -> IspLink | None:
        # No real row lock to take against an in-memory dict -- same
        # not-deleted semantics as get_link_by_id(include_deleted=False),
        # matching the real repository's own WHERE clause.
        link = self.links.get(link_id)
        if link is None or link.is_deleted:
            return None
        return link

    async def update_link(self, link: IspLink, data: dict[str, object]) -> IspLink:
        for key, value in data.items():
            if hasattr(link, key):
                setattr(link, key, value)
        link.version += 1
        return link

    async def soft_delete_link(self, link: IspLink) -> IspLink:
        link.is_deleted = True
        link.deleted_at = _now()
        return link

    async def list_links(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
        **_kw: object,
    ):
        values = [v for v in self.links.values() if not v.is_deleted]
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

    async def list_links_for_router(self, router_id: uuid.UUID) -> list[IspLink]:
        values = [
            v
            for v in self.links.values()
            if v.router_id == router_id and not v.is_deleted
        ]
        values.sort(key=lambda v: v.priority)
        return values

    async def get_active_uplink_for_router(
        self, router_id: uuid.UUID
    ) -> IspLink | None:
        for v in self.links.values():
            if v.router_id == router_id and v.is_active_uplink and not v.is_deleted:
                return v
        return None

    async def get_primary_link_for_router(self, router_id: uuid.UUID) -> IspLink | None:
        for v in self.links.values():
            if (
                v.router_id == router_id
                and v.role == IspLinkRole.PRIMARY.value
                and not v.is_deleted
            ):
                return v
        return None

    async def list_backup_links_for_router(self, router_id: uuid.UUID) -> list[IspLink]:
        values = [
            v
            for v in self.links.values()
            if v.router_id == router_id
            and v.role == IspLinkRole.BACKUP.value
            and not v.is_deleted
        ]
        values.sort(key=lambda v: v.priority)
        return values

    async def list_enabled_links_for_sweep(self) -> list[IspLink]:
        return [v for v in self.links.values() if v.is_enabled and not v.is_deleted]

    async def create_health_check(self, **fields: object) -> IspHealthCheck:
        check = IspHealthCheck(**_base_fields(**fields))
        self.health_checks[check.id] = check
        return check

    async def list_health_checks_for_link(
        self,
        link_id: uuid.UUID,
        *,
        page: int,
        page_size: int,
        start: datetime | None = None,
        end: datetime | None = None,
    ):
        values = [c for c in self.health_checks.values() if c.isp_link_id == link_id]
        if start is not None:
            values = [c for c in values if c.checked_at >= start]
        if end is not None:
            values = [c for c in values if c.checked_at <= end]
        values.sort(key=lambda c: c.checked_at, reverse=True)
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))

    async def list_recent_health_checks_for_link(
        self, link_id: uuid.UUID, *, limit: int
    ) -> list[IspHealthCheck]:
        values = [c for c in self.health_checks.values() if c.isp_link_id == link_id]
        values.sort(key=lambda c: c.checked_at, reverse=True)
        return values[:limit]

    async def bucketed_health_checks_for_link(
        self,
        link_id: uuid.UUID,
        *,
        start: datetime,
        end: datetime,
        bucket_unit: str,
    ):
        values = [
            c
            for c in self.health_checks.values()
            if c.isp_link_id == link_id and start <= c.checked_at <= end
        ]

        def _bucket_key(checked_at: datetime) -> datetime:
            truncated = checked_at.replace(minute=0, second=0, microsecond=0)
            if bucket_unit == "day":
                truncated = truncated.replace(hour=0)
            return truncated

        buckets: dict[datetime, list[IspHealthCheck]] = {}
        for c in values:
            buckets.setdefault(_bucket_key(c.checked_at), []).append(c)

        rows = []
        for bucket_start in sorted(buckets):
            bucket_checks = buckets[bucket_start]
            total = len(bucket_checks)
            healthy = sum(1 for c in bucket_checks if c.status == HealthStatus.HEALTHY.value)
            degraded = sum(
                1 for c in bucket_checks if c.status == HealthStatus.DEGRADED.value
            )
            unhealthy = sum(
                1 for c in bucket_checks if c.status == HealthStatus.UNHEALTHY.value
            )
            latencies = [c.latency_ms for c in bucket_checks if c.latency_ms is not None]
            losses = [
                c.packet_loss_percentage
                for c in bucket_checks
                if c.packet_loss_percentage is not None
            ]
            downloads = [
                c.download_mbps for c in bucket_checks if c.download_mbps is not None
            ]
            uploads = [
                c.upload_mbps for c in bucket_checks if c.upload_mbps is not None
            ]
            rows.append(
                (
                    bucket_start,
                    total,
                    healthy,
                    degraded,
                    unhealthy,
                    sum(latencies) / len(latencies) if latencies else None,
                    sum(losses) / len(losses) if losses else None,
                    sum(downloads) / len(downloads) if downloads else None,
                    sum(uploads) / len(uploads) if uploads else None,
                    max(downloads) if downloads else None,
                )
            )
        return rows


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

    async def update_router(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        data: dict[str, object],
    ) -> Router:
        router = await self.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        for key, value in data.items():
            if hasattr(router, key):
                setattr(router, key, value)
        return router


@dataclass
class FakeIspHealthAdapter:
    vendor: str = "mikrotik"
    next_result: PingResult | None = None
    should_raise: Exception | None = None
    calls: list[dict[str, object]] = field(default_factory=list)
    # DHCP/PPPoE target-resolution fakes -- see IspService.ping_link's own
    # per-connection-mode branching.
    dynamic_gateway: str | None = None
    pppoe_status_by_interface: dict[str, bool] = field(default_factory=dict)
    # Traffic-load fakes -- see IspService.sample_link_traffic.
    traffic_counters_by_interface: dict[str, tuple[int, int]] = field(
        default_factory=dict
    )
    # Speed-test fakes -- see IspService.run_speed_test.
    next_speed_test_result: SpeedTestResult | None = None
    speed_test_should_raise: Exception | None = None
    speed_test_calls: list[dict[str, object]] = field(default_factory=list)

    async def ping(
        self,
        credentials: IspCredentials,
        *,
        target_ip: str,
        count: int,
        timeout_seconds: int,
    ) -> PingResult:
        self.calls.append({"target_ip": target_ip, "count": count})
        if self.should_raise is not None:
            raise self.should_raise
        return self.next_result or PingResult(
            sent=count, received=count, packet_loss_percentage=0.0, avg_rtt_ms=10.0
        )

    async def get_active_default_gateway(
        self, credentials: IspCredentials
    ) -> str | None:
        return self.dynamic_gateway

    async def get_pppoe_interface_status(
        self, credentials: IspCredentials, *, interface_name: str
    ) -> bool:
        return self.pppoe_status_by_interface.get(interface_name, False)

    async def get_interface_traffic_counters(
        self, credentials: IspCredentials, *, interface_name: str
    ) -> tuple[int, int] | None:
        return self.traffic_counters_by_interface.get(interface_name)

    async def run_speed_test(
        self, credentials: IspCredentials, *, download_url: str
    ) -> SpeedTestResult:
        self.speed_test_calls.append(
            {"download_url": download_url, "timeout_seconds": credentials.timeout_seconds}
        )
        if self.speed_test_should_raise is not None:
            raise self.speed_test_should_raise
        return self.next_speed_test_result or SpeedTestResult(
            download_mbps=13.3, downloaded_bytes=10_000_000, duration_seconds=6.0
        )


# ============================================================================
# Harness
# ============================================================================


@dataclass
class Harness:
    service: IspService
    repository: FakeIspRepository
    router_lookup: FakeRouterLookup
    audit_writer: FakeAuditLogWriter
    health_adapter: FakeIspHealthAdapter


def make_harness(*, health_adapter: FakeIspHealthAdapter | None = None) -> Harness:
    repository = FakeIspRepository()
    router_lookup = FakeRouterLookup()
    audit_writer = FakeAuditLogWriter()
    adapter = health_adapter or FakeIspHealthAdapter()

    service = IspService(
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
        health_adapter=adapter,
    )


async def _create_primary(
    h: Harness, router: Router, *, gateway: str | None = "203.0.113.1"
) -> IspLink:
    return await h.service.create_link(
        actor_user_id=uuid.uuid4(),
        requesting_organization_id=router.organization_id,
        router_id=router.id,
        provider_name="Acme Fiber",
        link_type=IspLinkType.FIBER.value,
        role=IspLinkRole.PRIMARY,
        gateway_ip_address=gateway,
    )


async def _create_backup(
    h: Harness,
    router: Router,
    *,
    priority: int = 0,
    gateway: str | None = "203.0.113.2",
) -> IspLink:
    return await h.service.create_link(
        actor_user_id=uuid.uuid4(),
        requesting_organization_id=router.organization_id,
        router_id=router.id,
        provider_name="Backup DSL",
        link_type=IspLinkType.DSL.value,
        role=IspLinkRole.BACKUP,
        priority=priority,
        gateway_ip_address=gateway,
    )


# ============================================================================
# Link CRUD
# ============================================================================


class TestIspLinkCrud:
    async def test_first_link_is_immediately_active_uplink(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        link = await _create_primary(h, router)
        assert link.is_active_uplink is True
        assert link.organization_id == router.organization_id
        assert link.location_id == router.location_id
        assert len(h.audit_writer.entries) == 1

    async def test_second_link_starts_inactive(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        await _create_primary(h, router)
        backup = await _create_backup(h, router)
        assert backup.is_active_uplink is False

    async def test_second_primary_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        await _create_primary(h, router)
        with pytest.raises(IspPrimaryLinkAlreadyExistsError):
            await _create_primary(h, router)

    async def test_cross_organization_read_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        link = await _create_primary(h, router)
        with pytest.raises(CrossOrganizationIspLinkAccessError):
            await h.service.get_link(link.id, requesting_organization_id=uuid.uuid4())

    async def test_get_missing_link_raises(self) -> None:
        h = make_harness()
        with pytest.raises(IspLinkNotFoundError):
            await h.service.get_link(uuid.uuid4())

    async def test_update_to_primary_conflicts_with_existing_primary(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        await _create_primary(h, router)
        backup = await _create_backup(h, router)
        with pytest.raises(IspPrimaryLinkAlreadyExistsError):
            await h.service.update_link(
                backup.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
                role=IspLinkRole.PRIMARY.value,
            )

    async def test_delete_soft_deletes(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        link = await _create_primary(h, router)
        deleted = await h.service.delete_link(
            link.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )
        assert deleted.is_deleted is True

    async def test_list_links_scoped_to_router(self) -> None:
        h = make_harness()
        router_a = h.router_lookup.add(_make_router())
        router_b = h.router_lookup.add(_make_router())
        await _create_primary(h, router_a)
        await _create_primary(h, router_b)
        links, meta = await h.service.list_links(
            requesting_organization_id=router_a.organization_id, router_id=router_a.id
        )
        assert meta.total_items == 1
        assert links[0].router_id == router_a.id


# ============================================================================
# Health checks
# ============================================================================


class TestHealthChecks:
    async def test_healthy_ping_classifies_healthy_and_resets_counter(self) -> None:
        h = make_harness(
            health_adapter=FakeIspHealthAdapter(
                next_result=PingResult(
                    sent=5, received=5, packet_loss_percentage=0.0, avg_rtt_ms=20.0
                )
            )
        )
        router = h.router_lookup.add(_make_router())
        link = await _create_primary(h, router)
        updated = await h.service.check_link_health(
            link.id, requesting_organization_id=router.organization_id
        )
        assert updated.health_status == HealthStatus.HEALTHY.value
        assert updated.consecutive_unhealthy_count == 0
        checks, meta = await h.repository.list_health_checks_for_link(
            link.id, page=1, page_size=10
        )
        assert meta.total_items == 1
        assert checks[0].status == HealthStatus.HEALTHY.value

    async def test_unhealthy_ping_increments_consecutive_counter(self) -> None:
        h = make_harness(
            health_adapter=FakeIspHealthAdapter(
                next_result=PingResult(
                    sent=5, received=0, packet_loss_percentage=100.0, avg_rtt_ms=None
                )
            )
        )
        router = h.router_lookup.add(_make_router())
        link = await _create_primary(h, router)
        updated = await h.service.check_link_health(
            link.id, requesting_organization_id=router.organization_id
        )
        assert updated.health_status == HealthStatus.UNHEALTHY.value
        assert updated.consecutive_unhealthy_count == 1

    async def test_disabled_link_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        link = await _create_primary(h, router)
        await h.service.update_link(
            link.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            is_enabled=False,
        )
        with pytest.raises(IspLinkDisabledError):
            await h.service.check_link_health(
                link.id, requesting_organization_id=router.organization_id
            )

    async def test_missing_credentials_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        h.router_lookup.secrets[router.id] = None
        link = await _create_primary(h, router)
        with pytest.raises(IspMissingCredentialsError):
            await h.service.ping_link(link)


# ============================================================================
# Run Speed Test -- on-demand real /tool/fetch download + /tool/ping.
# ============================================================================


class TestRunSpeedTest:
    async def test_returns_real_download_and_latency(self) -> None:
        h = make_harness(
            health_adapter=FakeIspHealthAdapter(
                next_result=PingResult(
                    sent=5, received=5, packet_loss_percentage=0.0, avg_rtt_ms=15.5
                ),
                next_speed_test_result=SpeedTestResult(
                    download_mbps=13.3, downloaded_bytes=9765 * 1024, duration_seconds=6.0
                ),
            )
        )
        router = h.router_lookup.add(_make_router())
        link = await _create_primary(h, router)

        outcome = await h.service.run_speed_test(
            link.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
        )

        assert isinstance(outcome, SpeedTestOutcome)
        assert outcome.isp_link_id == link.id
        assert outcome.download_mbps == 13.3
        assert outcome.downloaded_bytes == 9765 * 1024
        assert outcome.duration_seconds == 6.0
        assert outcome.latency_ms == 15.5
        assert outcome.packet_loss_percentage == 0.0
        # Never a fabricated upload figure -- see SpeedTestOutcome's own
        # docstring.
        assert outcome.upload_mbps is None

    async def test_uses_a_larger_timeout_than_the_routine_health_check_ping(
        self,
    ) -> None:
        adapter = FakeIspHealthAdapter()
        h = make_harness(health_adapter=adapter)
        router = h.router_lookup.add(_make_router())
        link = await _create_primary(h, router)

        await h.service.run_speed_test(
            link.id, actor_user_id=None, requesting_organization_id=router.organization_id
        )

        assert len(adapter.speed_test_calls) == 1
        assert adapter.speed_test_calls[0]["download_url"] == SPEED_TEST_DOWNLOAD_URL
        assert adapter.speed_test_calls[0]["timeout_seconds"] == SPEED_TEST_TIMEOUT_SECONDS

    async def test_never_writes_an_isp_health_check_row(self) -> None:
        """See run_speed_test's own docstring: download_mbps/upload_mbps on
        IspHealthCheck carry a distinct, passive-traffic-rate meaning --
        a speed test result must never be folded into that series."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        link = await _create_primary(h, router)

        await h.service.run_speed_test(
            link.id, actor_user_id=None, requesting_organization_id=router.organization_id
        )

        checks, meta = await h.repository.list_health_checks_for_link(
            link.id, page=1, page_size=10
        )
        assert meta.total_items == 0

    async def test_writes_an_audit_log_entry(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        link = await _create_primary(h, router)
        actor_id = uuid.uuid4()

        await h.service.run_speed_test(
            link.id, actor_user_id=actor_id, requesting_organization_id=router.organization_id
        )

        # _create_primary above already wrote its own "isp_link_created"
        # audit entry -- isolate the speed-test action's own entry rather
        # than assuming index/position.
        speed_test_entries = [
            e for e in h.audit_writer.entries if e["action"] == "isp_link_speed_test_run"
        ]
        assert len(speed_test_entries) == 1
        entry = speed_test_entries[0]
        assert entry["actor_user_id"] == actor_id
        assert entry["entity_id"] == link.id

    async def test_disabled_link_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        link = await _create_primary(h, router)
        await h.service.update_link(
            link.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            is_enabled=False,
        )
        with pytest.raises(IspLinkDisabledError):
            await h.service.run_speed_test(
                link.id, actor_user_id=None, requesting_organization_id=router.organization_id
            )

    async def test_missing_credentials_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        h.router_lookup.secrets[router.id] = None
        link = await _create_primary(h, router)
        with pytest.raises(IspMissingCredentialsError):
            await h.service.run_speed_test(
                link.id, actor_user_id=None, requesting_organization_id=router.organization_id
            )

    async def test_real_fetch_failure_propagates(self) -> None:
        h = make_harness(
            health_adapter=FakeIspHealthAdapter(
                speed_test_should_raise=IspDeviceConnectionError(
                    "10.20.0.13", "connection refused"
                )
            )
        )
        router = h.router_lookup.add(_make_router())
        link = await _create_primary(h, router)
        with pytest.raises(IspDeviceConnectionError):
            await h.service.run_speed_test(
                link.id, actor_user_id=None, requesting_organization_id=router.organization_id
            )

    async def test_cross_organization_access_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        other_org = uuid.uuid4()
        link = await _create_primary(h, router)
        with pytest.raises(CrossOrganizationIspLinkAccessError):
            await h.service.run_speed_test(
                link.id, actor_user_id=None, requesting_organization_id=other_org
            )


# ============================================================================
# Health-check history: date-range filter (list_health_checks) and the
# bucketed uptime-chart summary (get_health_check_summary) -- both back the
# "Internet Connection" history dialog's "Last 24 hours / 7 days / 30 days"
# range picker.
# ============================================================================


class TestHealthCheckDateRangeAndSummary:
    async def _seed_checks(self, h: Harness, link: IspLink, base: datetime) -> None:
        # Two checks 3 days apart, well inside a 7-day window, one
        # healthy and one unhealthy -- enough to prove both the
        # date-range filter and the bucketed aggregation.
        await h.repository.create_health_check(
            isp_link_id=link.id,
            checked_at=base,
            status=HealthStatus.HEALTHY.value,
            source="automated",
            latency_ms=10.0,
            packet_loss_percentage=0.0,
            error_message=None,
            download_mbps=None,
            upload_mbps=None,
        )
        await h.repository.create_health_check(
            isp_link_id=link.id,
            checked_at=base + timedelta(days=3),
            status=HealthStatus.UNHEALTHY.value,
            source="automated",
            latency_ms=None,
            packet_loss_percentage=100.0,
            error_message="timeout",
            download_mbps=None,
            upload_mbps=None,
        )
        # A third check well outside the [base, base+3d] window used
        # below -- proves the range filter actually excludes it.
        await h.repository.create_health_check(
            isp_link_id=link.id,
            checked_at=base - timedelta(days=10),
            status=HealthStatus.HEALTHY.value,
            source="automated",
            latency_ms=8.0,
            packet_loss_percentage=0.0,
            error_message=None,
            download_mbps=None,
            upload_mbps=None,
        )

    async def test_list_health_checks_start_end_filters_are_additive(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        link = await _create_primary(h, router)
        base = _now() - timedelta(days=5)
        await self._seed_checks(h, link, base)

        # No range -- every existing caller's exact current behavior,
        # unaffected by the new optional filter.
        checks, meta = await h.service.list_health_checks(
            link.id, requesting_organization_id=router.organization_id, page_size=10
        )
        assert meta.total_items == 3

        # Range -- only the two checks inside [base, base+3d].
        ranged, ranged_meta = await h.service.list_health_checks(
            link.id,
            requesting_organization_id=router.organization_id,
            page_size=10,
            start=base,
            end=base + timedelta(days=3),
        )
        assert ranged_meta.total_items == 2
        assert {c.status for c in ranged} == {
            HealthStatus.HEALTHY.value,
            HealthStatus.UNHEALTHY.value,
        }

    async def test_summary_buckets_by_hour_for_a_short_span(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        link = await _create_primary(h, router)
        base = _now() - timedelta(hours=2)
        await h.repository.create_health_check(
            isp_link_id=link.id,
            checked_at=base,
            status=HealthStatus.HEALTHY.value,
            source="automated",
            latency_ms=10.0,
            packet_loss_percentage=0.0,
            error_message=None,
            download_mbps=None,
            upload_mbps=None,
        )
        await h.repository.create_health_check(
            isp_link_id=link.id,
            checked_at=base + timedelta(minutes=1),
            status=HealthStatus.UNHEALTHY.value,
            source="automated",
            latency_ms=None,
            packet_loss_percentage=100.0,
            error_message="timeout",
            download_mbps=None,
            upload_mbps=None,
        )
        bucket_unit, buckets = await h.service.get_health_check_summary(
            link.id,
            requesting_organization_id=router.organization_id,
            start=base - timedelta(hours=1),
            end=_now(),
        )
        assert bucket_unit == "hour"
        # Both checks land in the same hour bucket.
        matching = [b for b in buckets if b.total_checks > 0]
        assert len(matching) == 1
        bucket = matching[0]
        assert bucket.total_checks == 2
        assert bucket.healthy_count == 1
        assert bucket.unhealthy_count == 1
        assert bucket.uptime_percentage == 50.0

    async def test_summary_buckets_compute_mbps_aggregates_null_safely(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        link = await _create_primary(h, router)
        base = _now() - timedelta(hours=2)
        # Two real traffic samples in the same hour bucket -- avg/max
        # should reflect only these two real numbers.
        await h.repository.create_health_check(
            isp_link_id=link.id,
            checked_at=base,
            status=HealthStatus.HEALTHY.value,
            source="automated",
            latency_ms=10.0,
            packet_loss_percentage=0.0,
            error_message=None,
            download_mbps=20.0,
            upload_mbps=5.0,
        )
        await h.repository.create_health_check(
            isp_link_id=link.id,
            checked_at=base + timedelta(minutes=1),
            status=HealthStatus.HEALTHY.value,
            source="automated",
            latency_ms=10.0,
            packet_loss_percentage=0.0,
            error_message=None,
            download_mbps=40.0,
            upload_mbps=15.0,
        )
        # A third check in the same bucket where the health check itself
        # failed -- no traffic sample was possible, so both are None.
        # This row must NOT drag the average down toward 0.
        await h.repository.create_health_check(
            isp_link_id=link.id,
            checked_at=base + timedelta(minutes=2),
            status=HealthStatus.UNHEALTHY.value,
            source="automated",
            latency_ms=None,
            packet_loss_percentage=100.0,
            error_message="timeout",
            download_mbps=None,
            upload_mbps=None,
        )
        bucket_unit, buckets = await h.service.get_health_check_summary(
            link.id,
            requesting_organization_id=router.organization_id,
            start=base - timedelta(hours=1),
            end=_now(),
        )
        assert bucket_unit == "hour"
        matching = [b for b in buckets if b.total_checks > 0]
        assert len(matching) == 1
        bucket = matching[0]
        assert bucket.total_checks == 3
        # (20 + 40) / 2, never (20 + 40 + 0) / 3.
        assert bucket.avg_download_mbps == 30.0
        assert bucket.avg_upload_mbps == 10.0
        assert bucket.max_download_mbps == 40.0

    async def test_summary_bucket_reports_null_mbps_when_every_check_failed(
        self,
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        link = await _create_primary(h, router)
        base = _now() - timedelta(hours=2)
        await h.repository.create_health_check(
            isp_link_id=link.id,
            checked_at=base,
            status=HealthStatus.UNHEALTHY.value,
            source="automated",
            latency_ms=None,
            packet_loss_percentage=100.0,
            error_message="timeout",
            download_mbps=None,
            upload_mbps=None,
        )
        bucket_unit, buckets = await h.service.get_health_check_summary(
            link.id,
            requesting_organization_id=router.organization_id,
            start=base - timedelta(hours=1),
            end=_now(),
        )
        matching = [b for b in buckets if b.total_checks > 0]
        assert len(matching) == 1
        bucket = matching[0]
        assert bucket.avg_download_mbps is None
        assert bucket.avg_upload_mbps is None
        assert bucket.max_download_mbps is None

    async def test_summary_buckets_by_day_beyond_a_week(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        link = await _create_primary(h, router)
        base = _now() - timedelta(days=20)
        await self._seed_checks(h, link, base)
        bucket_unit, buckets = await h.service.get_health_check_summary(
            link.id,
            requesting_organization_id=router.organization_id,
            start=base - timedelta(days=15),
            end=_now(),
        )
        assert bucket_unit == "day"
        assert sum(b.total_checks for b in buckets) == 3

    async def test_summary_requires_link_in_requesting_organization(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        other_org_id = uuid.uuid4()
        link = await _create_primary(h, router)
        with pytest.raises(CrossOrganizationIspLinkAccessError):
            await h.service.get_health_check_summary(
                link.id,
                requesting_organization_id=other_org_id,
                start=_now() - timedelta(days=1),
                end=_now(),
            )


# ============================================================================
# Manual status override -- the "Internet Connection" dashboard view's one
# real write. Never opens a device connection; see
# IspService.set_manual_health_status's own docstring.
# ============================================================================


class TestManualStatusOverride:
    async def test_manual_override_persists_status_and_source(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        link = await _create_primary(h, router)
        updated = await h.service.set_manual_health_status(
            link.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
            health_status=HealthStatus.UNHEALTHY,
            reason="ISP outage confirmed by phone",
        )
        assert updated.health_status == HealthStatus.UNHEALTHY.value
        assert updated.health_status_source == "manual"

        checks, meta = await h.repository.list_health_checks_for_link(
            link.id, page=1, page_size=10
        )
        assert meta.total_items == 1
        assert checks[0].status == HealthStatus.UNHEALTHY.value
        assert checks[0].source == "manual"
        assert checks[0].error_message == "ISP outage confirmed by phone"

    async def test_manual_override_is_audited(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        link = await _create_primary(h, router)
        await h.service.set_manual_health_status(
            link.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
            health_status=HealthStatus.HEALTHY,
        )
        entries = [
            e
            for e in h.audit_writer.entries
            if e["action"] == "isp_link_manual_status_set"
        ]
        assert len(entries) == 1
        assert entries[0]["entity_id"] == link.id

    async def test_cross_organization_override_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        link = await _create_primary(h, router)
        with pytest.raises(CrossOrganizationIspLinkAccessError):
            await h.service.set_manual_health_status(
                link.id,
                actor_user_id=uuid.uuid4(),
                requesting_organization_id=uuid.uuid4(),
                health_status=HealthStatus.UNHEALTHY,
            )

    async def test_real_ping_reclaims_link_back_to_automated(self) -> None:
        """A manual override is a point-in-time statement, never a
        permanent lockout of the real health-check sweep -- the very next
        real ping must reclaim the link back to AUTOMATED regardless of
        what an admin last set."""
        h = make_harness(
            health_adapter=FakeIspHealthAdapter(
                next_result=PingResult(
                    sent=5, received=5, packet_loss_percentage=0.0, avg_rtt_ms=15.0
                )
            )
        )
        router = h.router_lookup.add(_make_router())
        link = await _create_primary(h, router)
        await h.service.set_manual_health_status(
            link.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
            health_status=HealthStatus.UNHEALTHY,
        )
        updated = await h.service.check_link_health(
            link.id, requesting_organization_id=router.organization_id
        )
        assert updated.health_status == HealthStatus.HEALTHY.value
        assert updated.health_status_source == "automated"


# ============================================================================
# Connection-mode-aware health-check target resolution (static/dhcp/pppoe)
# -- IspService.ping_link's own real-world gap fix: only a STATIC link
# ever has a fixed, admin-known gateway IP. Generic, driven entirely by
# each link's own `connection_mode` -- never hardcoded to a specific
# link/router.
# ============================================================================


class TestConnectionModeHealthChecks:
    async def test_dhcp_resolves_live_gateway_and_pings_it(self) -> None:
        adapter = FakeIspHealthAdapter(dynamic_gateway="198.51.100.7")
        h = make_harness(health_adapter=adapter)
        router = h.router_lookup.add(_make_router())
        link = await h.service.create_link(
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            router_id=router.id,
            provider_name="DHCP ISP",
            link_type=IspLinkType.FIBER.value,
            connection_mode=IspConnectionMode.DHCP.value,
            role=IspLinkRole.PRIMARY,
            gateway_ip_address=None,
        )
        assert link.connection_mode == IspConnectionMode.DHCP.value
        result = await h.service.ping_link(link)
        assert result.packet_loss_percentage == 0.0
        assert adapter.calls[-1]["target_ip"] == "198.51.100.7"

    async def test_dhcp_with_no_dynamic_route_raises_target_unavailable(self) -> None:
        adapter = FakeIspHealthAdapter(dynamic_gateway=None)
        h = make_harness(health_adapter=adapter)
        router = h.router_lookup.add(_make_router())
        link = await h.service.create_link(
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            router_id=router.id,
            provider_name="DHCP ISP",
            link_type=IspLinkType.FIBER.value,
            connection_mode=IspConnectionMode.DHCP.value,
            role=IspLinkRole.PRIMARY,
            gateway_ip_address=None,
        )
        with pytest.raises(IspHealthCheckTargetUnavailableError):
            await h.service.ping_link(link)

    async def test_dhcp_resolves_active_static_fallback_gateway_and_pings_it(
        self,
    ) -> None:
        """The fix for a confirmed fleet-wide production bug (2026-08-17):
        this platform's own Setup Script generator deliberately sets
        ``add-default-route=no`` on every dhcp-client it provisions and
        creates a *static* default route instead (to avoid it fighting
        the routing-mark/failover mangle rules) -- so a router
        provisioned exactly as intended never has a dynamic default
        route at all. ``get_active_default_gateway`` now falls back to a
        genuinely active static default route in that case; from
        ``ping_link``'s own perspective this is indistinguishable from
        the adapter resolving *any* usable gateway -- see
        ``test_isp_device_adapters.TestGetActiveDefaultGateway`` for the
        real RouterOS-route-selection-level coverage of the fallback
        rule itself (including the "genuinely active" requirement)."""
        adapter = FakeIspHealthAdapter(dynamic_gateway="203.0.113.1")
        h = make_harness(health_adapter=adapter)
        router = h.router_lookup.add(_make_router())
        link = await h.service.create_link(
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            router_id=router.id,
            provider_name="DHCP ISP",
            link_type=IspLinkType.FIBER.value,
            connection_mode=IspConnectionMode.DHCP.value,
            role=IspLinkRole.PRIMARY,
            gateway_ip_address=None,
        )
        result = await h.service.ping_link(link)
        assert result.packet_loss_percentage == 0.0
        assert adapter.calls[-1]["target_ip"] == "203.0.113.1"

    async def test_dhcp_static_route_inactive_still_raises_target_unavailable(
        self,
    ) -> None:
        """The other half of the same fix: a static default route that
        exists but is currently *inactive* (RouterOS clears its own
        ``active`` flag the instant a ``check-gateway`` probe fails -- a
        real outage) must never be masked by the new fallback.
        ``get_active_default_gateway`` returns ``None`` in that case
        exactly like "no route at all" -- see
        ``test_isp_device_adapters
        .TestGetActiveDefaultGateway.test_static_route_present_but_inactive_returns_none``
        for the real RouterOS-parsing-level assertion that an inactive
        row is excluded; this confirms ``ping_link`` still correctly
        raises on that ``None``, not a fabricated success."""
        adapter = FakeIspHealthAdapter(dynamic_gateway=None)
        h = make_harness(health_adapter=adapter)
        router = h.router_lookup.add(_make_router())
        link = await h.service.create_link(
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            router_id=router.id,
            provider_name="DHCP ISP",
            link_type=IspLinkType.FIBER.value,
            connection_mode=IspConnectionMode.DHCP.value,
            role=IspLinkRole.PRIMARY,
            gateway_ip_address=None,
        )
        with pytest.raises(IspHealthCheckTargetUnavailableError):
            await h.service.ping_link(link)

    async def test_pppoe_interface_up_classifies_healthy(self) -> None:
        adapter = FakeIspHealthAdapter(
            pppoe_status_by_interface={"pppoe-out1": True}
        )
        h = make_harness(health_adapter=adapter)
        router = h.router_lookup.add(_make_router())
        link = await h.service.create_link(
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            router_id=router.id,
            provider_name="PPPoE ISP",
            link_type=IspLinkType.FIBER.value,
            connection_mode=IspConnectionMode.PPPOE.value,
            role=IspLinkRole.PRIMARY,
            interface="pppoe-out1",
        )
        updated = await h.service.check_link_health(
            link.id, requesting_organization_id=router.organization_id
        )
        assert updated.health_status == HealthStatus.HEALTHY.value

    async def test_pppoe_interface_down_classifies_unhealthy(self) -> None:
        adapter = FakeIspHealthAdapter(
            pppoe_status_by_interface={"pppoe-out1": False}
        )
        h = make_harness(health_adapter=adapter)
        router = h.router_lookup.add(_make_router())
        link = await h.service.create_link(
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            router_id=router.id,
            provider_name="PPPoE ISP",
            link_type=IspLinkType.FIBER.value,
            connection_mode=IspConnectionMode.PPPOE.value,
            role=IspLinkRole.PRIMARY,
            interface="pppoe-out1",
        )
        updated = await h.service.check_link_health(
            link.id, requesting_organization_id=router.organization_id
        )
        assert updated.health_status == HealthStatus.UNHEALTHY.value

    async def test_pppoe_with_no_interface_configured_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        link = await h.service.create_link(
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            router_id=router.id,
            provider_name="PPPoE ISP",
            link_type=IspLinkType.FIBER.value,
            connection_mode=IspConnectionMode.PPPOE.value,
            role=IspLinkRole.PRIMARY,
        )
        with pytest.raises(IspHealthCheckTargetUnavailableError):
            await h.service.ping_link(link)

    async def test_sweep_never_skips_dhcp_link_with_blank_gateway(self) -> None:
        """The real bug this fix addresses: the sweep's own pre-flight
        skip used to check `gateway_ip_address` unconditionally, silently
        skipping every DHCP/PPPoE link forever since neither ever has one
        set."""
        adapter = FakeIspHealthAdapter(dynamic_gateway="198.51.100.9")
        repository = FakeIspRepository()
        router_lookup = FakeRouterLookup()
        router = router_lookup.add(_make_router())
        service = IspService(
            repository,
            router_lookup,
            device_adapter_resolver=lambda vendor: adapter,
        )
        link = await service.create_link(
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            router_id=router.id,
            provider_name="DHCP ISP",
            link_type=IspLinkType.FIBER.value,
            connection_mode=IspConnectionMode.DHCP.value,
            role=IspLinkRole.PRIMARY,
            gateway_ip_address=None,
        )
        assert link.gateway_ip_address is None
        summary = await run_health_check_sweep(
            repository,
            router_lookup,
            device_adapter_resolver=lambda vendor: adapter,
        )
        assert summary.skipped == 0
        assert summary.checked == 1


# ============================================================================
# "Down since" -- a computed read-model derived from real IspHealthCheck
# history, never a new stored column.
# ============================================================================


class TestUnhealthySince:
    async def test_none_when_link_is_currently_healthy(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        link = await _create_primary(h, router)
        assert await h.service.compute_unhealthy_since(link) is None

    async def test_returns_start_of_current_unhealthy_streak(self) -> None:
        h = make_harness(
            health_adapter=FakeIspHealthAdapter(
                next_result=PingResult(
                    sent=5, received=0, packet_loss_percentage=100.0, avg_rtt_ms=None
                )
            )
        )
        router = h.router_lookup.add(_make_router())
        link = await _create_primary(h, router)
        # Three consecutive real unhealthy pings -- "since" must be the
        # *first* one's timestamp, not the most recent.
        for _ in range(3):
            link = await h.service.check_link_health(
                link.id, requesting_organization_id=router.organization_id
            )
        checks, _ = await h.repository.list_health_checks_for_link(
            link.id, page=1, page_size=10
        )
        checks.sort(key=lambda c: c.checked_at)
        since = await h.service.compute_unhealthy_since(link)
        assert since == checks[0].checked_at

    async def test_manual_override_counts_toward_the_streak(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        link = await _create_primary(h, router)
        updated = await h.service.set_manual_health_status(
            link.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            health_status=HealthStatus.UNHEALTHY,
        )
        since = await h.service.compute_unhealthy_since(updated)
        assert since == updated.last_checked_at

    async def test_stops_at_the_last_healthy_reading(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        link = await _create_primary(h, router)
        # Healthy first (from _create_primary's own default adapter
        # result), then manually marked down -- "since" must be the
        # manual override's own timestamp, not further back.
        updated = await h.service.check_link_health(
            link.id, requesting_organization_id=router.organization_id
        )
        assert updated.health_status == HealthStatus.HEALTHY.value
        updated = await h.service.set_manual_health_status(
            link.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            health_status=HealthStatus.UNHEALTHY,
        )
        since = await h.service.compute_unhealthy_since(updated)
        assert since == updated.last_checked_at


# ============================================================================
# Traffic-load monitoring -- "how much traffic is flowing on this link
# right now", real interface byte counters, connection-mode-independent.
# ============================================================================


class TestTrafficLoad:
    async def test_no_interface_configured_returns_none(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        link = await _create_primary(h, router)  # no interface set
        assert await h.service.sample_link_traffic(link) is None

    async def test_first_sample_stores_counters_without_a_rate(self) -> None:
        adapter = FakeIspHealthAdapter(
            traffic_counters_by_interface={"ether1": (1_000_000, 500_000)}
        )
        h = make_harness(health_adapter=adapter)
        router = h.router_lookup.add(_make_router())
        link = await h.service.create_link(
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            router_id=router.id,
            provider_name="Static ISP",
            link_type=IspLinkType.FIBER.value,
            role=IspLinkRole.PRIMARY,
            gateway_ip_address="203.0.113.1",
            interface="ether1",
        )
        updated = await h.service.check_link_health(
            link.id, requesting_organization_id=router.organization_id
        )
        assert updated.last_rx_bytes == 1_000_000
        assert updated.last_tx_bytes == 500_000
        # No previous reading yet -- a rate needs two points, never
        # fabricated from one.
        assert updated.current_download_mbps is None
        assert updated.current_upload_mbps is None

    async def test_second_sample_computes_a_real_rate(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        link = await h.service.create_link(
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            router_id=router.id,
            provider_name="Static ISP",
            link_type=IspLinkType.FIBER.value,
            role=IspLinkRole.PRIMARY,
            gateway_ip_address="203.0.113.1",
            interface="ether1",
        )
        # Seed a "previous reading" 10 real seconds in the past.
        ten_seconds_ago = datetime.now(UTC) - timedelta(seconds=10)
        link = await h.repository.update_link(
            link,
            {
                "last_rx_bytes": 0,
                "last_tx_bytes": 0,
                "last_checked_at": ten_seconds_ago,
            },
        )
        # 10 MB down, 5 MB up over ~10 seconds -> ~8 Mbps down, ~4 Mbps up.
        traffic = TrafficCounters(rx_bytes=10_000_000, tx_bytes=5_000_000)
        updated = await h.service.record_health_check_result(
            link,
            ping_result=PingResult(
                sent=5, received=5, packet_loss_percentage=0.0, avg_rtt_ms=10.0
            ),
            traffic=traffic,
        )
        assert updated.current_download_mbps == pytest.approx(8.0, rel=0.05)
        assert updated.current_upload_mbps == pytest.approx(4.0, rel=0.05)
        checks, _ = await h.repository.list_health_checks_for_link(
            link.id, page=1, page_size=10
        )
        assert checks[0].download_mbps == pytest.approx(8.0, rel=0.05)
        assert checks[0].upload_mbps == pytest.approx(4.0, rel=0.05)

    async def test_counter_regression_yields_no_rate_but_updates_counters(
        self,
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        link = await h.service.create_link(
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            router_id=router.id,
            provider_name="Static ISP",
            link_type=IspLinkType.FIBER.value,
            role=IspLinkRole.PRIMARY,
            gateway_ip_address="203.0.113.1",
            interface="ether1",
        )
        ten_seconds_ago = datetime.now(UTC) - timedelta(seconds=10)
        link = await h.repository.update_link(
            link,
            {
                "last_rx_bytes": 10_000_000,
                "last_tx_bytes": 5_000_000,
                "last_checked_at": ten_seconds_ago,
                "current_download_mbps": 8.0,
                "current_upload_mbps": 4.0,
            },
        )
        # Interface reset (reboot/disable-enable): counters went backwards.
        traffic = TrafficCounters(rx_bytes=100, tx_bytes=50)
        updated = await h.service.record_health_check_result(
            link,
            ping_result=PingResult(
                sent=5, received=5, packet_loss_percentage=0.0, avg_rtt_ms=10.0
            ),
            traffic=traffic,
        )
        assert updated.last_rx_bytes == 100
        assert updated.last_tx_bytes == 50
        # No fabricated negative rate -- and the last known-real rate is
        # left untouched rather than blanked to None.
        assert updated.current_download_mbps == 8.0
        assert updated.current_upload_mbps == 4.0

    async def test_pppoe_link_samples_traffic_on_its_own_virtual_interface(
        self,
    ) -> None:
        """Confirms the same `interface` field ping_link's PPPoE branch
        checks for up/down is also the one traffic sampling reads from --
        real RouterOS PPPoE client interfaces carry their own independent
        counters, not the underlying physical port's."""
        adapter = FakeIspHealthAdapter(
            pppoe_status_by_interface={"pppoe-out1": True},
            traffic_counters_by_interface={"pppoe-out1": (2_000_000, 1_000_000)},
        )
        h = make_harness(health_adapter=adapter)
        router = h.router_lookup.add(_make_router())
        link = await h.service.create_link(
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            router_id=router.id,
            provider_name="PPPoE ISP",
            link_type=IspLinkType.FIBER.value,
            connection_mode=IspConnectionMode.PPPOE.value,
            role=IspLinkRole.PRIMARY,
            interface="pppoe-out1",
        )
        updated = await h.service.check_link_health(
            link.id, requesting_organization_id=router.organization_id
        )
        assert updated.health_status == HealthStatus.HEALTHY.value
        assert updated.last_rx_bytes == 2_000_000
        assert updated.last_tx_bytes == 1_000_000


# ============================================================================
# Failover / failback
# ============================================================================


class TestFailover:
    async def test_threshold_not_reached_never_fails_over(self) -> None:
        h = make_harness(
            health_adapter=FakeIspHealthAdapter(
                next_result=PingResult(
                    sent=5, received=0, packet_loss_percentage=100.0, avg_rtt_ms=None
                )
            )
        )
        router = h.router_lookup.add(_make_router())
        primary = await _create_primary(h, router)
        await _create_backup(h, router)
        assert DEFAULT_CONSECUTIVE_FAILURES_BEFORE_FAILOVER > 1
        for _ in range(DEFAULT_CONSECUTIVE_FAILURES_BEFORE_FAILOVER - 1):
            await h.service.check_link_health(
                primary.id, requesting_organization_id=router.organization_id
            )
        current_active = await h.repository.get_active_uplink_for_router(router.id)
        assert current_active.id == primary.id

    async def test_threshold_reached_fails_over_to_backup(self) -> None:
        h = make_harness(
            health_adapter=FakeIspHealthAdapter(
                next_result=PingResult(
                    sent=5, received=0, packet_loss_percentage=100.0, avg_rtt_ms=None
                )
            )
        )
        router = h.router_lookup.add(_make_router())
        primary = await _create_primary(h, router)
        backup = await _create_backup(h, router)
        for _ in range(DEFAULT_CONSECUTIVE_FAILURES_BEFORE_FAILOVER):
            await h.service.check_link_health(
                primary.id, requesting_organization_id=router.organization_id
            )
        current_active = await h.repository.get_active_uplink_for_router(router.id)
        assert current_active.id == backup.id
        failover_entries = [
            e for e in h.audit_writer.entries if e["action"] == "isp_failover_triggered"
        ]
        assert len(failover_entries) == 1

    async def test_manual_failover_picks_lowest_priority_healthy_backup(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        await _create_primary(h, router)
        low_priority_backup = await _create_backup(
            h, router, priority=5, gateway="203.0.113.3"
        )
        high_priority_backup = await _create_backup(
            h, router, priority=1, gateway="203.0.113.4"
        )
        promoted = await h.service.trigger_failover(
            router.id, actor_user_id=None, reason="manual_test"
        )
        assert promoted.id == high_priority_backup.id
        assert low_priority_backup.is_active_uplink is False

    async def test_manual_failover_raises_when_no_backup_available(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        await _create_primary(h, router)
        with pytest.raises(IspNoBackupLinkAvailableError):
            await h.service.trigger_failover(
                router.id, actor_user_id=None, reason="manual_test"
            )

    async def test_manual_failover_skips_unhealthy_backups(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        await _create_primary(h, router)
        unhealthy_backup = await _create_backup(
            h, router, priority=0, gateway="203.0.113.5"
        )
        await h.repository.update_link(
            unhealthy_backup, {"health_status": HealthStatus.UNHEALTHY.value}
        )
        healthy_backup = await _create_backup(
            h, router, priority=1, gateway="203.0.113.6"
        )
        promoted = await h.service.trigger_failover(
            router.id, actor_user_id=None, reason="manual_test"
        )
        assert promoted.id == healthy_backup.id


class TestFailback:
    async def test_failback_requires_healthy_primary(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        await _create_primary(h, router)
        await _create_backup(h, router)
        await h.service.trigger_failover(router.id, actor_user_id=None, reason="test")
        with pytest.raises(IspNoBackupLinkAvailableError):
            await h.service.trigger_failback(router.id, actor_user_id=None)

    async def test_failback_restores_healthy_primary(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        primary = await _create_primary(h, router)
        await _create_backup(h, router)
        await h.service.trigger_failover(router.id, actor_user_id=None, reason="test")
        await h.repository.update_link(
            primary, {"health_status": HealthStatus.HEALTHY.value}
        )
        restored = await h.service.trigger_failback(router.id, actor_user_id=None)
        assert restored.id == primary.id
        assert restored.is_active_uplink is True

    async def test_auto_failback_on_healthy_reading_when_enabled(self) -> None:
        h = make_harness(
            health_adapter=FakeIspHealthAdapter(
                next_result=PingResult(
                    sent=5, received=0, packet_loss_percentage=100.0, avg_rtt_ms=None
                )
            )
        )
        router = h.router_lookup.add(_make_router())
        primary = await _create_primary(h, router)
        await _create_backup(h, router)
        for _ in range(DEFAULT_CONSECUTIVE_FAILURES_BEFORE_FAILOVER):
            await h.service.check_link_health(
                primary.id, requesting_organization_id=router.organization_id
            )
        current_active = await h.repository.get_active_uplink_for_router(router.id)
        assert current_active.id != primary.id

        h.health_adapter.next_result = PingResult(
            sent=5, received=5, packet_loss_percentage=0.0, avg_rtt_ms=15.0
        )
        await h.service.check_link_health(
            primary.id, requesting_organization_id=router.organization_id
        )
        current_active = await h.repository.get_active_uplink_for_router(router.id)
        assert current_active.id == primary.id


# ============================================================================
# Availability (computed read-model)
# ============================================================================


class TestAvailability:
    def test_no_history_returns_none(self) -> None:
        h = make_harness()
        assert h.service.compute_availability_percentage([]) is None

    def test_computes_percentage_excluding_unhealthy(self) -> None:
        h = make_harness()
        checks = [
            IspHealthCheck(
                **_base_fields(
                    isp_link_id=uuid.uuid4(),
                    checked_at=_now(),
                    status=status,
                    latency_ms=None,
                    packet_loss_percentage=None,
                    error_message=None,
                )
            )
            for status in [
                HealthStatus.HEALTHY.value,
                HealthStatus.HEALTHY.value,
                HealthStatus.DEGRADED.value,
                HealthStatus.UNHEALTHY.value,
            ]
        ]
        assert h.service.compute_availability_percentage(checks) == 75.0


# ============================================================================
# Health-check sweep: per-link failure isolation
# ============================================================================


class TestHealthCheckSweep:
    async def test_sweep_isolates_per_link_failures(self) -> None:
        repository = FakeIspRepository()
        router_lookup = FakeRouterLookup()
        audit_writer = FakeAuditLogWriter()
        good_router = router_lookup.add(_make_router())
        bad_router = router_lookup.add(_make_router())

        good_link = IspLink(
            **_base_fields(
                router_id=good_router.id,
                organization_id=good_router.organization_id,
                location_id=good_router.location_id,
                provider_name="Good ISP",
                link_type=IspLinkType.FIBER.value,
                connection_mode=IspConnectionMode.STATIC.value,
                role=IspLinkRole.PRIMARY.value,
                is_active_uplink=True,
                auto_failback=True,
                is_enabled=True,
                priority=0,
                interface=None,
                gateway_ip_address="203.0.113.10",
                dns_primary=None,
                dns_secondary=None,
                download_bandwidth_mbps=None,
                upload_bandwidth_mbps=None,
                health_status=HealthStatus.UNKNOWN.value,
                latency_ms=None,
                packet_loss_percentage=None,
                last_checked_at=None,
                consecutive_unhealthy_count=0,
            )
        )
        repository.links[good_link.id] = good_link

        bad_link = IspLink(
            **_base_fields(
                router_id=bad_router.id,
                organization_id=bad_router.organization_id,
                location_id=bad_router.location_id,
                provider_name="Bad ISP",
                link_type=IspLinkType.FIBER.value,
                connection_mode=IspConnectionMode.STATIC.value,
                role=IspLinkRole.PRIMARY.value,
                is_active_uplink=True,
                auto_failback=True,
                is_enabled=True,
                priority=0,
                interface=None,
                gateway_ip_address="203.0.113.11",
                dns_primary=None,
                dns_secondary=None,
                download_bandwidth_mbps=None,
                upload_bandwidth_mbps=None,
                health_status=HealthStatus.UNKNOWN.value,
                latency_ms=None,
                packet_loss_percentage=None,
                last_checked_at=None,
                consecutive_unhealthy_count=0,
            )
        )
        repository.links[bad_link.id] = bad_link

        skipped_link = IspLink(
            **_base_fields(
                router_id=good_router.id,
                organization_id=good_router.organization_id,
                location_id=good_router.location_id,
                provider_name="No Gateway ISP",
                link_type=IspLinkType.FIBER.value,
                connection_mode=IspConnectionMode.STATIC.value,
                role=IspLinkRole.BACKUP.value,
                is_active_uplink=False,
                auto_failback=True,
                is_enabled=True,
                priority=1,
                interface=None,
                gateway_ip_address=None,
                dns_primary=None,
                dns_secondary=None,
                download_bandwidth_mbps=None,
                upload_bandwidth_mbps=None,
                health_status=HealthStatus.UNKNOWN.value,
                latency_ms=None,
                packet_loss_percentage=None,
                last_checked_at=None,
                consecutive_unhealthy_count=0,
            )
        )
        repository.links[skipped_link.id] = skipped_link

        # Router lookup raises for the "bad" router's own link -- simulates
        # an unreachable/misconfigured device, never aborting the sweep for
        # everyone else's links.
        original_get_router = router_lookup.get_router

        async def flaky_get_router(router_id, **kwargs):
            if router_id == bad_router.id:
                raise RouterNotFoundError(router_id)
            return await original_get_router(router_id, **kwargs)

        router_lookup.get_router = flaky_get_router  # type: ignore[method-assign]

        adapter = FakeIspHealthAdapter(
            next_result=PingResult(
                sent=5, received=5, packet_loss_percentage=0.0, avg_rtt_ms=10.0
            )
        )
        summary = await run_health_check_sweep(
            repository,
            router_lookup,
            audit_writer=audit_writer,
            device_adapter_resolver=lambda vendor: adapter,
        )
        assert isinstance(summary, HealthCheckSweepSummary)
        assert summary.checked == 1
        assert summary.errors == 1
        assert summary.skipped == 1
        assert good_link.health_status == HealthStatus.HEALTHY.value

    async def test_sweep_records_unhealthy_when_router_is_genuinely_unreachable(
        self,
    ) -> None:
        """Confirmed live, real bug: a router that goes completely
        unreachable (e.g. its WAN uplink -- which its own management
        tunnel also rides -- is pulled) used to fall into the same
        skip-and-log branch as a missing-credentials config error, so its
        link's `last_checked_at`/`health_status` froze at its last
        successful reading *forever*, indistinguishable from a router
        checked seconds ago and genuinely healthy. A real connection
        failure must now flow through the same recording pipeline a real
        failed ping would, landing on `UNHEALTHY` with a real, current
        `last_checked_at` and an incremented consecutive-failure count --
        not a silent skip."""
        repository = FakeIspRepository()
        router_lookup = FakeRouterLookup()
        router = router_lookup.add(_make_router())

        link = IspLink(
            **_base_fields(
                router_id=router.id,
                organization_id=router.organization_id,
                location_id=router.location_id,
                provider_name="Airtel",
                link_type=IspLinkType.FIBER.value,
                connection_mode=IspConnectionMode.STATIC.value,
                role=IspLinkRole.PRIMARY.value,
                is_active_uplink=True,
                auto_failback=True,
                is_enabled=True,
                priority=0,
                interface=None,
                gateway_ip_address="203.0.113.20",
                dns_primary=None,
                dns_secondary=None,
                download_bandwidth_mbps=None,
                upload_bandwidth_mbps=None,
                health_status=HealthStatus.HEALTHY.value,
                latency_ms=1.2,
                packet_loss_percentage=0.0,
                last_checked_at=None,
                consecutive_unhealthy_count=0,
            )
        )
        repository.links[link.id] = link

        adapter = FakeIspHealthAdapter(
            should_raise=IspDeviceConnectionError(router.management_ip_address, "no route to host")
        )
        summary = await run_health_check_sweep(
            repository,
            router_lookup,
            device_adapter_resolver=lambda vendor: adapter,
        )

        assert summary.checked == 1
        assert summary.errors == 0
        assert summary.skipped == 0
        assert link.health_status == HealthStatus.UNHEALTHY.value
        assert link.last_checked_at is not None
        assert link.consecutive_unhealthy_count == 1


# ============================================================================
# RBAC -- every route requires a permission dependency
# ============================================================================


class TestEveryRouteRequiresPermission:
    def test_every_isp_route_has_a_permission_dependency(self) -> None:
        # 9 original routes + POST /links/{link_id}/status (manual
        # health-status override, see IspService.set_manual_health_status)
        # + GET /links/{link_id}/health-checks/summary (bucketed uptime
        # chart, see IspService.get_health_check_summary)
        # + POST /links/{link_id}/speed-test (on-demand real speed test,
        # see IspService.run_speed_test)
        # + PUT /routers/{router_id}/wan-routing-mode (see
        # IspService.set_wan_routing_mode).
        assert len(isp_router.routes) == 13
        for route in isp_router.routes:
            assert (
                route.dependencies != []
            ), f"{route.path} ({route.methods}) has no permission dependency"


# ============================================================================
# WAN routing mode + load-balance weight
# ============================================================================


class TestValidateWanRoutingWeights:
    """Pure validator -- no service/harness needed."""

    def test_noop_in_failover_only_mode_regardless_of_weights(self) -> None:
        # Weights are simply unused in failover-only, not an error --
        # see WanRoutingMode's own docstring on why they're left alone
        # (not cleared) for a possible switch back to load-balance later.
        validate_wan_routing_weights(
            router_id=uuid.uuid4(),
            mode=WanRoutingMode.FAILOVER_ONLY,
            enabled_link_weights=[5, None, 3],
        )

    def test_noop_with_fewer_than_two_enabled_links(self) -> None:
        validate_wan_routing_weights(
            router_id=uuid.uuid4(),
            mode=WanRoutingMode.LOAD_BALANCE,
            enabled_link_weights=[5],
        )

    def test_noop_when_no_link_is_weighted(self) -> None:
        # The existing, unweighted even-split behavior -- every
        # pre-existing router's real, current state.
        validate_wan_routing_weights(
            router_id=uuid.uuid4(),
            mode=WanRoutingMode.LOAD_BALANCE,
            enabled_link_weights=[None, None],
        )

    def test_noop_when_every_enabled_link_is_weighted(self) -> None:
        validate_wan_routing_weights(
            router_id=uuid.uuid4(),
            mode=WanRoutingMode.LOAD_BALANCE,
            enabled_link_weights=[7, 3],
        )

    def test_raises_on_partial_weighting(self) -> None:
        with pytest.raises(MixedWanRoutingWeightsError):
            validate_wan_routing_weights(
                router_id=uuid.uuid4(),
                mode=WanRoutingMode.LOAD_BALANCE,
                enabled_link_weights=[7, None],
            )

    def test_raises_on_non_positive_weight(self) -> None:
        with pytest.raises(ValueError):
            validate_wan_routing_weights(
                router_id=uuid.uuid4(),
                mode=WanRoutingMode.LOAD_BALANCE,
                enabled_link_weights=[0, 5],
            )


class TestSetWanRoutingMode:
    async def test_sets_mode_and_records_audit_event(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())

        updated = await h.service.set_wan_routing_mode(
            router.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
            mode=WanRoutingMode.FAILOVER_ONLY,
        )
        assert updated.wan_routing_mode == WanRoutingMode.FAILOVER_ONLY.value
        assert any(
            e["action"] == "router_wan_routing_mode_changed"
            and e["entity_type"] == "router"
            for e in h.audit_writer.entries
        )

    async def test_switching_to_load_balance_rejects_partial_weighting(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        primary = await _create_primary(h, router)
        await _create_backup(h, router)
        await h.service.update_link(
            primary.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
            load_balance_weight=7,
        )

        with pytest.raises(MixedWanRoutingWeightsError):
            await h.service.set_wan_routing_mode(
                router.id,
                actor_user_id=uuid.uuid4(),
                requesting_organization_id=router.organization_id,
                mode=WanRoutingMode.LOAD_BALANCE,
            )

    async def test_switching_to_failover_only_never_validates_weights(self) -> None:
        # A partial weighting is only a real problem in LOAD_BALANCE mode
        # (see WanRoutingMode's own docstring) -- switching *to*
        # FAILOVER_ONLY must always succeed regardless of whatever weights
        # happen to already be on file.
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        primary = await _create_primary(h, router)
        await _create_backup(h, router)
        await h.service.update_link(
            primary.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
            load_balance_weight=7,
        )

        updated = await h.service.set_wan_routing_mode(
            router.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
            mode=WanRoutingMode.FAILOVER_ONLY,
        )
        assert updated.wan_routing_mode == WanRoutingMode.FAILOVER_ONLY.value

    async def test_disabled_links_excluded_when_confirming_load_balance(self) -> None:
        # A disabled link never carries traffic -- its own missing weight
        # must not block confirming load-balance mode once every *enabled*
        # link is weighted. Three links total; the second backup is
        # disabled and left unweighted throughout.
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        primary = await _create_primary(h, router)
        backup_1 = await _create_backup(h, router, priority=0)
        backup_2 = await _create_backup(h, router, priority=1)
        await h.service.update_link(
            backup_2.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
            is_enabled=False,
        )
        await h.service.update_link(
            primary.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
            load_balance_weight=7,
        )
        await h.service.update_link(
            backup_1.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
            load_balance_weight=3,
        )

        updated = await h.service.set_wan_routing_mode(
            router.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
            mode=WanRoutingMode.LOAD_BALANCE,
        )
        assert updated.wan_routing_mode == WanRoutingMode.LOAD_BALANCE.value


class TestUpdateLinkWeight:
    async def test_can_weight_every_enabled_link_together(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        primary = await _create_primary(h, router)
        backup = await _create_backup(h, router)

        updated_primary = await h.service.update_link(
            primary.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
            load_balance_weight=7,
        )
        updated_backup = await h.service.update_link(
            backup.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
            load_balance_weight=3,
        )
        assert updated_primary.load_balance_weight == 7
        assert updated_backup.load_balance_weight == 3

    async def test_partial_weighting_is_allowed_transiently(self) -> None:
        # update_link deliberately does NOT cross-validate against sibling
        # links (see that method's own comment) -- an admin sets one
        # link's weight per call, so the first weighted link must not
        # conflict with its still-unweighted siblings. The "every enabled
        # link or none" rule is enforced later, at set_wan_routing_mode
        # (see TestSetWanRoutingMode.
        # test_switching_to_load_balance_rejects_partial_weighting).
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        primary = await _create_primary(h, router)
        await _create_backup(h, router)

        updated_primary = await h.service.update_link(
            primary.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
            load_balance_weight=7,
        )
        assert updated_primary.load_balance_weight == 7

    async def test_disabled_link_can_be_weighted_independently(self) -> None:
        # A disabled link's own weight is simply unused (see
        # IspLink.load_balance_weight's own docstring) -- update_link
        # doesn't special-case it, so setting one is a plain no-op write,
        # not an error.
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        backup = await _create_backup(h, router)
        await h.service.update_link(
            backup.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
            is_enabled=False,
        )

        updated = await h.service.update_link(
            backup.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
            load_balance_weight=3,
        )
        assert updated.load_balance_weight == 3
