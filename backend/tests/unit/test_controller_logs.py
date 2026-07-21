"""Unit tests for the Controller Logs domain: a read-only aggregator
over six real log sources (Provision/Configuration/Router/Authentication
admin+guest/System), composed entirely through narrow Protocols -- no
new table, no new migration.

Follows this project's plain-``assert``/native-``async def`` style
(see ``tests/unit/test_isp.py``); ``ControllerLogsService`` is exercised
against small, hand-rolled in-memory fakes for each of its seven
composed Protocols -- mirrors ``test_device_sync.py``'s own identical
"fake the narrow Protocol boundary" precedent. A structural RBAC check
confirms every route carries a permission dependency.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from app.database.constants import MAX_PAGE_SIZE
from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.controller_logs.constants import (
    MAX_EXPORT_ROWS,
    MAX_PROVISION_JOBS_FOR_LOG_MERGE,
)
from app.domains.controller_logs.router import router as controller_logs_router
from app.domains.controller_logs.service import ControllerLogsService


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass
class _Job:
    id: uuid.UUID = field(default_factory=uuid.uuid4)


@dataclass
class _LogEntry:
    id: uuid.UUID
    job_id: uuid.UUID
    level: str
    message: str
    logged_at: datetime


@dataclass
class _Simple:
    id: uuid.UUID = field(default_factory=uuid.uuid4)


class FakeProvisioningJobLookup:
    def __init__(self, jobs: list[_Job]) -> None:
        self.jobs = jobs
        self.calls: list[dict[str, object]] = []

    async def get_history(
        self,
        *,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[_Job], PaginationMeta]:
        self.calls.append({"page": page, "page_size": page_size})
        jobs = self.jobs[:page_size]
        params = PageParams(page=page, page_size=page_size)
        return jobs, PaginationMeta.from_total(params, len(self.jobs))


class FakeProvisionLogLookup:
    def __init__(self, logs_by_job: dict[uuid.UUID, list[_LogEntry]]) -> None:
        self.logs_by_job = logs_by_job

    async def list_logs_for_job(self, job_id: uuid.UUID) -> list[_LogEntry]:
        return self.logs_by_job.get(job_id, [])


class FakePagedLookup:
    """Generic pass-through fake for the four simple, already-paginated
    protocols (Configuration/Router/Admin-Authentication/System) --
    each just records its call kwargs and returns a fixed page."""

    def __init__(self, items: list[object]) -> None:
        self.items = items
        self.calls: list[dict[str, object]] = []

    async def _respond(self, *, page: int, page_size: int, **kwargs: object):
        self.calls.append({"page": page, "page_size": page_size, **kwargs})
        params = PageParams(page=page, page_size=page_size)
        paged = self.items[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(self.items))


class FakeConfigVersionLookup(FakePagedLookup):
    async def list_versions(
        self,
        *,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
    ):
        return await self._respond(
            page=page,
            page_size=page_size,
            router_id=router_id,
            requesting_organization_id=requesting_organization_id,
        )


class FakeRouterEventLookup(FakePagedLookup):
    async def list_events(
        self,
        *,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
    ):
        return await self._respond(
            page=page,
            page_size=page_size,
            router_id=router_id,
            requesting_organization_id=requesting_organization_id,
        )


class FakeLoginAttemptLookup(FakePagedLookup):
    async def list_login_attempts(
        self,
        *,
        email: str | None = None,
        success: bool | None = None,
        page: int = 1,
        page_size: int = 25,
    ):
        return await self._respond(
            page=page, page_size=page_size, email=email, success=success
        )


class FakeGuestLoginHistoryLookup(FakePagedLookup):
    async def list_login_history(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        guest_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
    ):
        return await self._respond(
            page=page,
            page_size=page_size,
            organization_id=organization_id,
            location_id=location_id,
            guest_id=guest_id,
        )


class FakeHealthCheckLookup(FakePagedLookup):
    async def get_health_history(self, *, component: object, page: int, page_size: int):
        return await self._respond(page=page, page_size=page_size, component=component)


def _make_service(
    *,
    jobs: list[_Job] | None = None,
    logs_by_job: dict[uuid.UUID, list[_LogEntry]] | None = None,
    config_versions: list[object] | None = None,
    router_events: list[object] | None = None,
    login_attempts: list[object] | None = None,
    guest_login_history: list[object] | None = None,
    health_checks: list[object] | None = None,
) -> tuple[ControllerLogsService, dict[str, object]]:
    fakes = {
        "job_lookup": FakeProvisioningJobLookup(jobs or []),
        "log_lookup": FakeProvisionLogLookup(logs_by_job or {}),
        "config_lookup": FakeConfigVersionLookup(config_versions or []),
        "event_lookup": FakeRouterEventLookup(router_events or []),
        "login_attempt_lookup": FakeLoginAttemptLookup(login_attempts or []),
        "guest_history_lookup": FakeGuestLoginHistoryLookup(guest_login_history or []),
        "health_lookup": FakeHealthCheckLookup(health_checks or []),
    }
    service = ControllerLogsService(
        fakes["job_lookup"],
        fakes["log_lookup"],
        fakes["config_lookup"],
        fakes["event_lookup"],
        fakes["login_attempt_lookup"],
        fakes["guest_history_lookup"],
        fakes["health_lookup"],
    )
    return service, fakes


# ============================================================================
# Provision Logs -- merged across jobs, bounded, sorted, paginated
# ============================================================================


class TestListProvisionLogs:
    async def test_merges_and_sorts_logs_across_jobs_newest_first(self) -> None:
        job_a, job_b = _Job(), _Job()
        older = _LogEntry(
            uuid.uuid4(), job_a.id, "info", "a", _now() - timedelta(minutes=5)
        )
        newer = _LogEntry(uuid.uuid4(), job_b.id, "info", "b", _now())
        service, _ = _make_service(
            jobs=[job_a, job_b],
            logs_by_job={job_a.id: [older], job_b.id: [newer]},
        )
        entries, meta = await service.list_provision_logs(router_id=uuid.uuid4())
        assert [e.id for e in entries] == [newer.id, older.id]
        assert meta.total_items == 2

    async def test_bounds_job_fetch_to_max_provision_jobs_for_log_merge(self) -> None:
        service, fakes = _make_service(jobs=[_Job() for _ in range(50)])
        await service.list_provision_logs(router_id=uuid.uuid4())
        assert (
            fakes["job_lookup"].calls[0]["page_size"]
            == MAX_PROVISION_JOBS_FOR_LOG_MERGE
        )

    async def test_paginates_merged_results_in_memory(self) -> None:
        job = _Job()
        logs = [
            _LogEntry(
                uuid.uuid4(), job.id, "info", str(i), _now() - timedelta(minutes=i)
            )
            for i in range(5)
        ]
        service, _ = _make_service(jobs=[job], logs_by_job={job.id: logs})
        entries, meta = await service.list_provision_logs(
            router_id=uuid.uuid4(), page=2, page_size=2
        )
        assert len(entries) == 2
        assert meta.page == 2
        assert meta.total_items == 5


# ============================================================================
# Configuration / Router Logs -- simple pass-through
# ============================================================================


class TestListConfigurationLogs:
    async def test_passes_router_and_organization_through(self) -> None:
        router_id, org_id = uuid.uuid4(), uuid.uuid4()
        service, fakes = _make_service(config_versions=[_Simple()])
        await service.list_configuration_logs(
            router_id=router_id, requesting_organization_id=org_id
        )
        call = fakes["config_lookup"].calls[0]
        assert call["router_id"] == router_id
        assert call["requesting_organization_id"] == org_id


class TestListRouterLogs:
    async def test_passes_router_and_organization_through(self) -> None:
        router_id, org_id = uuid.uuid4(), uuid.uuid4()
        service, fakes = _make_service(router_events=[_Simple()])
        await service.list_router_logs(
            router_id=router_id, requesting_organization_id=org_id
        )
        call = fakes["event_lookup"].calls[0]
        assert call["router_id"] == router_id
        assert call["requesting_organization_id"] == org_id


# ============================================================================
# Authentication Logs -- admin (platform-wide) vs guest (tenant-scoped)
# ============================================================================


class TestListAdminAuthenticationLogs:
    async def test_passes_email_and_success_filters_through(self) -> None:
        service, fakes = _make_service(login_attempts=[_Simple()])
        await service.list_admin_authentication_logs(email="a@b.com", success=False)
        call = fakes["login_attempt_lookup"].calls[0]
        assert call["email"] == "a@b.com"
        assert call["success"] is False

    async def test_never_receives_an_organization_filter(self) -> None:
        service, fakes = _make_service(login_attempts=[_Simple()])
        await service.list_admin_authentication_logs()
        assert "organization_id" not in fakes["login_attempt_lookup"].calls[0]


class TestListGuestAuthenticationLogs:
    async def test_passes_organization_location_and_guest_through(self) -> None:
        org_id, loc_id, guest_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        service, fakes = _make_service(guest_login_history=[_Simple()])
        await service.list_guest_authentication_logs(
            requesting_organization_id=org_id, location_id=loc_id, guest_id=guest_id
        )
        call = fakes["guest_history_lookup"].calls[0]
        assert call["organization_id"] == org_id
        assert call["location_id"] == loc_id
        assert call["guest_id"] == guest_id


# ============================================================================
# System Logs -- requires a component
# ============================================================================


class TestListSystemLogs:
    async def test_passes_component_through(self) -> None:
        service, fakes = _make_service(health_checks=[_Simple()])
        await service.list_system_logs(component="database")
        assert fakes["health_lookup"].calls[0]["component"] == "database"


# ============================================================================
# CSV export bound
# ============================================================================


class TestExportBound:
    async def test_max_export_rows_matches_the_real_pagination_ceiling(self) -> None:
        """``MAX_EXPORT_ROWS`` must equal ``MAX_PAGE_SIZE`` -- every
        category here except Provision Logs is a thin pass-through to
        some domain's own ``GenericRepository.paginate``, which clamps
        ``page_size`` to ``MAX_PAGE_SIZE`` regardless of what is
        requested. A larger export bound would silently be truncated
        one layer down, which is exactly the silent-truncation this
        domain's own docstrings promise never happens."""
        assert MAX_EXPORT_ROWS == MAX_PAGE_SIZE

    async def test_export_page_size_is_honored_up_to_the_real_ceiling(self) -> None:
        service, fakes = _make_service(
            login_attempts=[_Simple() for _ in range(MAX_EXPORT_ROWS + 10)]
        )
        entries, meta = await service.list_admin_authentication_logs(
            page=1, page_size=MAX_EXPORT_ROWS
        )
        assert len(entries) == MAX_EXPORT_ROWS
        assert meta.total_items == MAX_EXPORT_ROWS + 10


# ============================================================================
# RBAC -- every route requires a permission dependency
# ============================================================================


class TestEveryRouteRequiresPermission:
    def test_every_controller_logs_route_has_a_permission_dependency(self) -> None:
        assert len(controller_logs_router.routes) == 12
        for route in controller_logs_router.routes:
            assert (
                route.dependencies != []
            ), f"{route.path} ({route.methods}) has no permission dependency"
