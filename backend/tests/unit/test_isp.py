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
from datetime import UTC, datetime

import pytest

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.isp.constants import (
    DEFAULT_CONSECUTIVE_FAILURES_BEFORE_FAILOVER,
    HealthStatus,
    IspLinkRole,
    IspLinkType,
)
from app.domains.isp.device_adapters import IspCredentials, PingResult
from app.domains.isp.exceptions import (
    CrossOrganizationIspLinkAccessError,
    IspLinkDisabledError,
    IspLinkNotFoundError,
    IspMissingCredentialsError,
    IspNoBackupLinkAvailableError,
    IspPrimaryLinkAlreadyExistsError,
)
from app.domains.isp.models import IspHealthCheck, IspLink
from app.domains.isp.router import router as isp_router
from app.domains.isp.service import (
    HealthCheckSweepSummary,
    IspService,
    run_health_check_sweep,
)
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
        self, link_id: uuid.UUID, *, page: int, page_size: int
    ):
        values = [c for c in self.health_checks.values() if c.isp_link_id == link_id]
        values.sort(key=lambda c: c.checked_at, reverse=True)
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
class FakeIspHealthAdapter:
    vendor: str = "mikrotik"
    next_result: PingResult | None = None
    should_raise: Exception | None = None
    calls: list[dict[str, object]] = field(default_factory=list)

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


# ============================================================================
# RBAC -- every route requires a permission dependency
# ============================================================================


class TestEveryRouteRequiresPermission:
    def test_every_isp_route_has_a_permission_dependency(self) -> None:
        assert len(isp_router.routes) == 9
        for route in isp_router.routes:
            assert (
                route.dependencies != []
            ), f"{route.path} ({route.methods}) has no permission dependency"
