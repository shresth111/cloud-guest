"""Unit tests for the Device Synchronization domain: orchestration
across three composed protocols (Connected Devices/Queue Management/
Provisioning Engine), per-component failure isolation, overall-status
computation (SUCCESS/PARTIAL/FAILED), the honest "not_provisioned"
reporting for DHCP/VLAN/Port Forwarding, immutable sync history reads,
tenant isolation, and a structural RBAC check that every route carries a
permission dependency.

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_isp.py``); ``asyncio_mode = "auto"`` runs async tests
directly. ``DeviceSyncService`` is exercised against small, hand-rolled
in-memory fakes for its own repository and every composed cross-domain
protocol -- mirrors ``test_isp.py``'s own identical "fake the narrow
Protocol boundary" precedent.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.device_sync.constants import SyncComponent, SyncRunStatus
from app.domains.device_sync.exceptions import (
    CrossOrganizationDeviceSyncRunAccessError,
    DeviceSyncRunNotFoundError,
)
from app.domains.device_sync.models import DeviceSyncRun
from app.domains.device_sync.router import router as device_sync_router
from app.domains.device_sync.service import DeviceSyncService
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
class FakeDeviceSyncRepository:
    runs: dict[uuid.UUID, DeviceSyncRun] = field(default_factory=dict)

    async def create_run(self, **fields: object) -> DeviceSyncRun:
        run = DeviceSyncRun(**_base_fields(**fields))
        self.runs[run.id] = run
        return run

    async def get_run_by_id(self, run_id: uuid.UUID) -> DeviceSyncRun | None:
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
        values.sort(key=lambda v: v.started_at, reverse=True)
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))


@dataclass
class FakeRouterLookup:
    routers: dict[uuid.UUID, Router] = field(default_factory=dict)

    def add(self, router: Router) -> Router:
        self.routers[router.id] = router
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


@dataclass
class FakeDeviceSyncSummary:
    discovered: int = 3
    updated: int = 1
    disconnected: int = 0


@dataclass
class FakeConnectedDeviceSync:
    should_fail: bool = False

    async def sync_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> FakeDeviceSyncSummary:
        if self.should_fail:
            raise RuntimeError("connected device sync failed")
        return FakeDeviceSyncSummary()


@dataclass
class FakeQueueReapplySummary:
    reapplied: int = 2
    failed: int = 0


@dataclass
class FakeQueueSync:
    should_fail: bool = False

    async def reapply_assignments_for_router(
        self,
        router_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> FakeQueueReapplySummary:
        if self.should_fail:
            raise RuntimeError("queue reapply failed")
        return FakeQueueReapplySummary()


@dataclass
class FakeProvisionJob:
    id: uuid.UUID
    status: str = "success"


@dataclass
class FakeProvisioningLookup:
    jobs: list[FakeProvisionJob] = field(default_factory=list)
    should_fail: bool = False

    async def list_jobs(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        status: object | None = None,
        page: int = 1,
        page_size: int = 25,
    ):
        if self.should_fail:
            raise RuntimeError("provisioning lookup failed")
        meta = PaginationMeta.from_total(
            PageParams(page=page, page_size=page_size), len(self.jobs)
        )
        return self.jobs[:page_size], meta


@dataclass
class FakeAuditLogWriter:
    entries: list[dict[str, object]] = field(default_factory=list)

    async def create_audit_log_entry(self, **fields: object) -> dict[str, object]:
        self.entries.append(fields)
        return fields


# ============================================================================
# Harness
# ============================================================================


@dataclass
class Harness:
    service: DeviceSyncService
    repository: FakeDeviceSyncRepository
    router_lookup: FakeRouterLookup
    connected_device_sync: FakeConnectedDeviceSync
    queue_sync: FakeQueueSync
    provisioning_lookup: FakeProvisioningLookup
    audit_writer: FakeAuditLogWriter


def make_harness(
    *,
    connected_device_sync: FakeConnectedDeviceSync | None = None,
    queue_sync: FakeQueueSync | None = None,
    provisioning_lookup: FakeProvisioningLookup | None = None,
) -> Harness:
    repository = FakeDeviceSyncRepository()
    router_lookup = FakeRouterLookup()
    cd_sync = connected_device_sync or FakeConnectedDeviceSync()
    q_sync = queue_sync or FakeQueueSync()
    prov_lookup = provisioning_lookup or FakeProvisioningLookup()
    audit_writer = FakeAuditLogWriter()
    service = DeviceSyncService(
        repository,
        router_lookup,
        cd_sync,
        q_sync,
        prov_lookup,
        audit_writer=audit_writer,
    )
    return Harness(
        service=service,
        repository=repository,
        router_lookup=router_lookup,
        connected_device_sync=cd_sync,
        queue_sync=q_sync,
        provisioning_lookup=prov_lookup,
        audit_writer=audit_writer,
    )


# ============================================================================
# Orchestration
# ============================================================================


class TestSyncRouter:
    async def test_all_components_succeed_yields_overall_success(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        run = await h.service.sync_router(
            router.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
        )
        assert run.status == SyncRunStatus.SUCCESS.value
        assert (
            run.component_results[SyncComponent.CONNECTED_DEVICES.value]["status"]
            == "success"
        )
        assert (
            run.component_results[SyncComponent.QUEUE_MANAGEMENT.value]["status"]
            == "success"
        )
        assert (
            run.component_results[SyncComponent.DHCP.value]["status"]
            == "not_provisioned"
        )
        assert (
            run.component_results[SyncComponent.VLAN.value]["status"]
            == "not_provisioned"
        )
        assert (
            run.component_results[SyncComponent.PORT_FORWARDING.value]["status"]
            == "not_provisioned"
        )
        assert len(h.audit_writer.entries) == 1

    async def test_one_failed_component_yields_partial(self) -> None:
        h = make_harness(
            connected_device_sync=FakeConnectedDeviceSync(should_fail=True)
        )
        router = h.router_lookup.add(_make_router())
        run = await h.service.sync_router(
            router.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )
        assert run.status == SyncRunStatus.PARTIAL.value
        assert (
            run.component_results[SyncComponent.CONNECTED_DEVICES.value]["status"]
            == "failed"
        )
        assert (
            "error"
            in run.component_results[SyncComponent.CONNECTED_DEVICES.value]["summary"]
        )

    async def test_all_real_components_failing_yields_failed(self) -> None:
        h = make_harness(
            connected_device_sync=FakeConnectedDeviceSync(should_fail=True),
            queue_sync=FakeQueueSync(should_fail=True),
            provisioning_lookup=FakeProvisioningLookup(should_fail=True),
        )
        router = h.router_lookup.add(_make_router())
        run = await h.service.sync_router(
            router.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )
        assert run.status == SyncRunStatus.FAILED.value

    async def test_no_provisioning_jobs_is_not_a_failure(self) -> None:
        h = make_harness(provisioning_lookup=FakeProvisioningLookup(jobs=[]))
        router = h.router_lookup.add(_make_router())
        run = await h.service.sync_router(
            router.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )
        assert run.status == SyncRunStatus.SUCCESS.value
        assert (
            run.component_results[SyncComponent.PROVISIONING.value]["status"]
            == "no_jobs"
        )

    async def test_reports_latest_provisioning_job_status(self) -> None:
        job = FakeProvisionJob(id=uuid.uuid4(), status="failed")
        h = make_harness(provisioning_lookup=FakeProvisioningLookup(jobs=[job]))
        router = h.router_lookup.add(_make_router())
        run = await h.service.sync_router(
            router.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )
        # The provisioning *lookup* itself succeeded (status=success),
        # even though the underlying job's own status was "failed" --
        # that real detail lives in the summary, not the lookup status.
        assert (
            run.component_results[SyncComponent.PROVISIONING.value]["status"]
            == "success"
        )
        assert (
            run.component_results[SyncComponent.PROVISIONING.value]["summary"][
                "job_status"
            ]
            == "failed"
        )


# ============================================================================
# Sync history reads
# ============================================================================


class TestSyncHistory:
    async def test_cross_organization_read_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        run = await h.service.sync_router(
            router.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )
        with pytest.raises(CrossOrganizationDeviceSyncRunAccessError):
            await h.service.get_run(run.id, requesting_organization_id=uuid.uuid4())

    async def test_get_missing_run_raises(self) -> None:
        h = make_harness()
        with pytest.raises(DeviceSyncRunNotFoundError):
            await h.service.get_run(uuid.uuid4())

    async def test_list_runs_scoped_to_router(self) -> None:
        h = make_harness()
        router_a = h.router_lookup.add(_make_router())
        router_b = h.router_lookup.add(_make_router())
        await h.service.sync_router(
            router_a.id,
            actor_user_id=None,
            requesting_organization_id=router_a.organization_id,
        )
        await h.service.sync_router(
            router_b.id,
            actor_user_id=None,
            requesting_organization_id=router_b.organization_id,
        )
        runs, meta = await h.service.list_runs(
            requesting_organization_id=router_a.organization_id, router_id=router_a.id
        )
        assert meta.total_items == 1
        assert runs[0].router_id == router_a.id


# ============================================================================
# RBAC -- every route requires a permission dependency
# ============================================================================


class TestEveryRouteRequiresPermission:
    def test_every_device_sync_route_has_a_permission_dependency(self) -> None:
        assert len(device_sync_router.routes) == 3
        for route in device_sync_router.routes:
            assert (
                route.dependencies != []
            ), f"{route.path} ({route.methods}) has no permission dependency"
