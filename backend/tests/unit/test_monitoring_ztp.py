"""Unit tests for BE-011 Part 3's ZTP Monitoring Dashboard + Analytics and
Platform Dashboard Statistics: ``validators.compute_lifecycle_stage``
against constructed fixtures for every one of the 9 documented lifecycle
states (plus the documented edge cases), ``ZtpMonitoringService.get_dashboard``
(stage-count tallying, pagination, unclaimed-enrollment listing),
``ZtpMonitoringService.get_analytics`` (success-rate denominator, failure
breakdown, retry dashboard, activation timing), and
``PlatformDashboardService.get_dashboard_statistics`` (device/health/alert
statistics, visitor-stats scoping).

Follows this project's established convention (plain ``assert``/native
``async def``; duck-typed stand-in dataclasses for cross-domain models --
see ``test_monitoring_alerts.py``'s own ``FakeRouter``/``FakeSnapshot``).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.monitoring.constants import RouterLifecycleStage
from app.domains.monitoring.service import (
    PlatformDashboardService,
    ZtpMonitoringService,
)
from app.domains.monitoring.validators import compute_lifecycle_stage
from app.domains.router.enums import RouterStatus
from app.domains.router_provisioning.constants import (
    EnrollmentStatus,
    ProvisioningJobStatus,
)


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass
class FakeRouter:
    """Duck-typed stand-in for ``app.domains.router.models.Router`` -- only
    the attributes this part's code actually reads."""

    id: uuid.UUID
    status: str
    last_seen_at: datetime | None
    serial_number: str = "SN-1"
    mac_address: str = "AA:BB:CC:DD:EE:01"
    model: str = "RB750Gr3"
    name: str = "Router 1"
    organization_id: uuid.UUID | None = None
    location_id: uuid.UUID | None = None


@dataclass
class FakeEnrollment:
    """Duck-typed stand-in for
    ``app.domains.router_provisioning.models.RouterEnrollmentRequest``."""

    id: uuid.UUID
    status: str
    serial_number: str = "SN-1"
    mac_address: str = "AA:BB:CC:DD:EE:01"
    model: str = "RB750Gr3"
    approved_router_id: uuid.UUID | None = None
    reviewed_at: datetime | None = None


@dataclass
class FakeJob:
    """Duck-typed stand-in for
    ``app.domains.router_provisioning.models.ProvisioningJob``."""

    id: uuid.UUID
    router_id: uuid.UUID
    job_type: str
    status: str
    attempts: int
    max_attempts: int = 3
    scheduled_at: datetime = field(default_factory=_now)
    completed_at: datetime | None = None
    error_message: str | None = None


def _router(
    *, status: RouterStatus, last_seen_at: datetime | None = None, **kwargs: object
) -> FakeRouter:
    return FakeRouter(
        id=uuid.uuid4(), status=status.value, last_seen_at=last_seen_at, **kwargs
    )


def _job(
    *,
    status: ProvisioningJobStatus,
    attempts: int = 0,
    max_attempts: int = 3,
    job_type: str = "initial_config",
    **kwargs: object,
) -> FakeJob:
    return FakeJob(
        id=uuid.uuid4(),
        router_id=uuid.uuid4(),
        job_type=job_type,
        status=status.value,
        attempts=attempts,
        max_attempts=max_attempts,
        **kwargs,
    )


# ============================================================================
# compute_lifecycle_stage -- all 9 states + documented edge cases
# ============================================================================


def test_lifecycle_pending_when_no_router_and_no_enrollment():
    stage = compute_lifecycle_stage(router=None, enrollment=None, latest_job=None)
    assert stage == RouterLifecycleStage.PENDING


def test_lifecycle_pending_when_enrollment_pending():
    enrollment = FakeEnrollment(id=uuid.uuid4(), status=EnrollmentStatus.PENDING.value)
    stage = compute_lifecycle_stage(router=None, enrollment=enrollment, latest_job=None)
    assert stage == RouterLifecycleStage.PENDING


def test_lifecycle_failed_when_enrollment_rejected():
    enrollment = FakeEnrollment(id=uuid.uuid4(), status=EnrollmentStatus.REJECTED.value)
    stage = compute_lifecycle_stage(router=None, enrollment=enrollment, latest_job=None)
    assert stage == RouterLifecycleStage.FAILED


def test_lifecycle_warning_when_enrollment_approved_but_router_unresolvable():
    enrollment = FakeEnrollment(id=uuid.uuid4(), status=EnrollmentStatus.APPROVED.value)
    stage = compute_lifecycle_stage(router=None, enrollment=enrollment, latest_job=None)
    assert stage == RouterLifecycleStage.WARNING


def test_lifecycle_warning_when_suspended():
    router = _router(status=RouterStatus.SUSPENDED)
    stage = compute_lifecycle_stage(router=router, enrollment=None, latest_job=None)
    assert stage == RouterLifecycleStage.WARNING


def test_lifecycle_approved_when_pending_provisioning_no_job():
    router = _router(status=RouterStatus.PENDING_PROVISIONING)
    stage = compute_lifecycle_stage(router=router, enrollment=None, latest_job=None)
    assert stage == RouterLifecycleStage.APPROVED


def test_lifecycle_claimed_when_pending_provisioning_job_queued():
    router = _router(status=RouterStatus.PENDING_PROVISIONING)
    job = _job(status=ProvisioningJobStatus.QUEUED)
    stage = compute_lifecycle_stage(router=router, enrollment=None, latest_job=job)
    assert stage == RouterLifecycleStage.CLAIMED


def test_lifecycle_warning_when_pending_provisioning_job_failed_retryable():
    router = _router(status=RouterStatus.PENDING_PROVISIONING)
    job = _job(status=ProvisioningJobStatus.FAILED, attempts=1, max_attempts=3)
    stage = compute_lifecycle_stage(router=router, enrollment=None, latest_job=job)
    assert stage == RouterLifecycleStage.WARNING


def test_lifecycle_failed_when_pending_provisioning_job_failed_exhausted():
    router = _router(status=RouterStatus.PENDING_PROVISIONING)
    job = _job(status=ProvisioningJobStatus.FAILED, attempts=3, max_attempts=3)
    stage = compute_lifecycle_stage(router=router, enrollment=None, latest_job=job)
    assert stage == RouterLifecycleStage.FAILED


def test_lifecycle_provisioning_when_job_running():
    router = _router(status=RouterStatus.PROVISIONING)
    job = _job(status=ProvisioningJobStatus.RUNNING)
    stage = compute_lifecycle_stage(router=router, enrollment=None, latest_job=job)
    assert stage == RouterLifecycleStage.PROVISIONING


def test_lifecycle_provisioned_when_job_succeeded():
    router = _router(status=RouterStatus.PROVISIONING)
    job = _job(status=ProvisioningJobStatus.SUCCEEDED)
    stage = compute_lifecycle_stage(router=router, enrollment=None, latest_job=job)
    assert stage == RouterLifecycleStage.PROVISIONED


def test_lifecycle_warning_when_provisioning_job_failed_retryable():
    router = _router(status=RouterStatus.PROVISIONING)
    job = _job(status=ProvisioningJobStatus.FAILED, attempts=2, max_attempts=3)
    stage = compute_lifecycle_stage(router=router, enrollment=None, latest_job=job)
    assert stage == RouterLifecycleStage.WARNING


def test_lifecycle_failed_when_provisioning_job_failed_exhausted():
    router = _router(status=RouterStatus.PROVISIONING)
    job = _job(status=ProvisioningJobStatus.FAILED, attempts=3, max_attempts=3)
    stage = compute_lifecycle_stage(router=router, enrollment=None, latest_job=job)
    assert stage == RouterLifecycleStage.FAILED


def test_lifecycle_offline_when_router_status_offline():
    router = _router(status=RouterStatus.OFFLINE)
    stage = compute_lifecycle_stage(router=router, enrollment=None, latest_job=None)
    assert stage == RouterLifecycleStage.OFFLINE


def test_lifecycle_online_when_heartbeat_fresh():
    router = _router(status=RouterStatus.ONLINE, last_seen_at=_now())
    stage = compute_lifecycle_stage(router=router, enrollment=None, latest_job=None)
    assert stage == RouterLifecycleStage.ONLINE


def test_lifecycle_warning_when_heartbeat_stale():
    router = _router(
        status=RouterStatus.ONLINE, last_seen_at=_now() - timedelta(minutes=8)
    )
    stage = compute_lifecycle_stage(router=router, enrollment=None, latest_job=None)
    assert stage == RouterLifecycleStage.WARNING


def test_lifecycle_offline_when_heartbeat_very_stale():
    router = _router(
        status=RouterStatus.ONLINE, last_seen_at=_now() - timedelta(minutes=30)
    )
    stage = compute_lifecycle_stage(router=router, enrollment=None, latest_job=None)
    assert stage == RouterLifecycleStage.OFFLINE


def test_lifecycle_offline_when_online_but_never_seen():
    router = _router(status=RouterStatus.ONLINE, last_seen_at=None)
    stage = compute_lifecycle_stage(router=router, enrollment=None, latest_job=None)
    assert stage == RouterLifecycleStage.OFFLINE


def test_lifecycle_decommissioned_defensive_fallback_is_warning():
    router = _router(status=RouterStatus.DECOMMISSIONED)
    stage = compute_lifecycle_stage(router=router, enrollment=None, latest_job=None)
    assert stage == RouterLifecycleStage.WARNING


# ============================================================================
# ZtpMonitoringService.get_dashboard / get_analytics
# ============================================================================


@dataclass
class FakeZtpRepository:
    """Stand-in for the ``MonitoringRepositoryProtocol`` surface
    ``ZtpMonitoringService``/``PlatformDashboardService`` need."""

    routers: list[FakeRouter] = field(default_factory=list)
    enrollments: list[FakeEnrollment] = field(default_factory=list)
    jobs: list[FakeJob] = field(default_factory=list)
    service_health_rows: list[object] = field(default_factory=list)
    health_check_stats: tuple[int, int, float | None] = (0, 0, None)
    alert_severity_counts: list[tuple[str, int]] = field(default_factory=list)
    alert_status_counts: list[tuple[str, int]] = field(default_factory=list)

    async def list_routers(self, *, organization_id=None):
        if organization_id is None:
            return list(self.routers)
        return [r for r in self.routers if r.organization_id == organization_id]

    async def list_all_enrollment_requests(self):
        return list(self.enrollments)

    async def get_enrollment_for_router(self, router_id):
        for e in self.enrollments:
            if e.approved_router_id == router_id:
                return e
        return None

    async def get_latest_provisioning_job_for_router(self, router_id):
        matching = [j for j in self.jobs if j.router_id == router_id]
        if not matching:
            return None
        return max(matching, key=lambda j: j.scheduled_at)

    async def count_pending_enrollment_requests(self):
        return len([e for e in self.enrollments if e.status == "pending"])

    async def count_routers_by_status(self, *, organization_id=None):
        routers = await self.list_routers(organization_id=organization_id)
        counts: dict[str, int] = {}
        for r in routers:
            counts[r.status] = counts.get(r.status, 0) + 1
        return list(counts.items())

    async def compute_provisioning_job_outcome_counts(
        self, *, organization_id=None, start, end
    ):
        jobs = [
            j
            for j in self.jobs
            if j.status in ("succeeded", "failed") and start <= j.scheduled_at <= end
        ]
        if organization_id is not None:
            router_ids = {
                r.id for r in self.routers if r.organization_id == organization_id
            }
            jobs = [j for j in jobs if j.router_id in router_ids]
        succeeded = len([j for j in jobs if j.status == "succeeded"])
        return succeeded, len(jobs)

    async def list_provisioning_failure_counts(
        self, *, organization_id=None, start, end
    ):
        jobs = [
            j
            for j in self.jobs
            if j.status == "failed" and start <= j.scheduled_at <= end
        ]
        counts: dict[str, int] = {}
        for j in jobs:
            counts[j.job_type] = counts.get(j.job_type, 0) + 1
        return list(counts.items())

    async def list_provisioning_failure_samples(
        self, *, organization_id=None, start, end, limit
    ):
        jobs = [
            j
            for j in self.jobs
            if j.status == "failed" and start <= j.scheduled_at <= end
        ]
        jobs.sort(key=lambda j: j.scheduled_at, reverse=True)
        return jobs[:limit]

    async def list_retry_jobs(self, *, organization_id=None, page=1, page_size=25):
        jobs = [j for j in self.jobs if j.attempts > 0]
        jobs.sort(
            key=lambda j: (j.max_attempts - j.attempts, -j.scheduled_at.timestamp())
        )
        params = PageParams(page=page, page_size=page_size)
        start_index = (page - 1) * page_size
        page_items = jobs[start_index : start_index + page_size]
        return page_items, PaginationMeta.from_total(params, len(jobs))

    async def compute_activation_duration_stats(
        self, *, organization_id=None, start, end
    ):
        durations: list[float] = []
        for job in self.jobs:
            if job.job_type != "initial_config" or job.status != "succeeded":
                continue
            if job.completed_at is None or not (start <= job.completed_at <= end):
                continue
            enrollment = await self.get_enrollment_for_router(job.router_id)
            if enrollment is None or enrollment.reviewed_at is None:
                continue
            durations.append(
                (job.completed_at - enrollment.reviewed_at).total_seconds()
            )
        if not durations:
            return None, 0
        return sum(durations) / len(durations), len(durations)

    async def compute_alert_counts_by_severity(
        self, *, organization_id=None, start, end
    ):
        return list(self.alert_severity_counts)

    async def compute_alert_counts_by_status(self, *, organization_id=None, start, end):
        return list(self.alert_status_counts)

    async def list_service_health(self):
        return list(self.service_health_rows)

    async def compute_health_check_stats(self, *, component=None, start, end):
        return self.health_check_stats


async def test_ztp_dashboard_tallies_stage_counts_across_all_matching_rows():
    repo = FakeZtpRepository()
    online_router = _router(status=RouterStatus.ONLINE, last_seen_at=_now())
    offline_router = _router(status=RouterStatus.OFFLINE)
    repo.routers = [online_router, offline_router]
    repo.enrollments = [
        FakeEnrollment(id=uuid.uuid4(), status=EnrollmentStatus.PENDING.value),
    ]

    service = ZtpMonitoringService(repo)
    result = await service.get_dashboard(page=1, page_size=10)

    assert result.stage_counts[RouterLifecycleStage.ONLINE.value] == 1
    assert result.stage_counts[RouterLifecycleStage.OFFLINE.value] == 1
    assert result.stage_counts[RouterLifecycleStage.PENDING.value] == 1
    assert result.total_items == 3
    assert result.pending_enrollment_count == 1


async def test_ztp_dashboard_excludes_approved_enrollments_from_unclaimed_list():
    """An APPROVED enrollment already has a Router row -- it must not be
    double-counted as a second, still-router-less dashboard entry."""
    repo = FakeZtpRepository()
    router = _router(status=RouterStatus.PENDING_PROVISIONING)
    repo.routers = [router]
    repo.enrollments = [
        FakeEnrollment(
            id=uuid.uuid4(),
            status=EnrollmentStatus.APPROVED.value,
            approved_router_id=router.id,
        )
    ]

    service = ZtpMonitoringService(repo)
    result = await service.get_dashboard(page=1, page_size=10)

    assert result.total_items == 1
    assert result.items[0].router_id == router.id
    assert result.items[0].enrollment_status == EnrollmentStatus.APPROVED.value


async def test_ztp_dashboard_unclaimed_enrollments_only_shown_platform_wide():
    repo = FakeZtpRepository()
    repo.enrollments = [
        FakeEnrollment(id=uuid.uuid4(), status=EnrollmentStatus.PENDING.value)
    ]
    service = ZtpMonitoringService(repo)

    platform_wide = await service.get_dashboard(organization_id=None)
    scoped = await service.get_dashboard(organization_id=uuid.uuid4())

    assert platform_wide.total_items == 1
    assert scoped.total_items == 0


async def test_ztp_dashboard_pagination():
    repo = FakeZtpRepository()
    repo.routers = [
        _router(status=RouterStatus.ONLINE, last_seen_at=_now()) for _ in range(5)
    ]
    service = ZtpMonitoringService(repo)

    page1 = await service.get_dashboard(page=1, page_size=2)
    page2 = await service.get_dashboard(page=2, page_size=2)

    assert page1.total_items == 5
    assert len(page1.items) == 2
    assert page1.has_next is True
    assert page1.has_previous is False
    assert len(page2.items) == 2
    assert page2.has_previous is True


async def test_ztp_analytics_success_rate_excludes_in_flight_jobs():
    repo = FakeZtpRepository()
    start, end = _now() - timedelta(days=1), _now() + timedelta(days=1)
    repo.jobs = [
        _job(status=ProvisioningJobStatus.SUCCEEDED),
        _job(status=ProvisioningJobStatus.SUCCEEDED),
        _job(status=ProvisioningJobStatus.FAILED, attempts=3, max_attempts=3),
        _job(status=ProvisioningJobStatus.QUEUED),  # excluded: still in flight
        _job(status=ProvisioningJobStatus.RUNNING),  # excluded: still in flight
    ]
    service = ZtpMonitoringService(repo)
    result = await service.get_analytics(start=start, end=end)

    assert result.succeeded_job_count == 2
    assert result.terminal_job_count == 3
    assert result.success_rate_percentage == round((2 / 3) * 100, 4)


async def test_ztp_analytics_success_rate_none_with_no_terminal_jobs():
    repo = FakeZtpRepository()
    start, end = _now() - timedelta(days=1), _now() + timedelta(days=1)
    service = ZtpMonitoringService(repo)
    result = await service.get_analytics(start=start, end=end)
    assert result.success_rate_percentage is None
    assert result.terminal_job_count == 0


async def test_ztp_analytics_failure_breakdown_grouped_by_job_type():
    repo = FakeZtpRepository()
    start, end = _now() - timedelta(days=1), _now() + timedelta(days=1)
    repo.jobs = [
        _job(status=ProvisioningJobStatus.FAILED, attempts=1, job_type="config_push"),
        _job(status=ProvisioningJobStatus.FAILED, attempts=1, job_type="config_push"),
        _job(status=ProvisioningJobStatus.FAILED, attempts=1, job_type="backup"),
    ]
    service = ZtpMonitoringService(repo)
    result = await service.get_analytics(start=start, end=end)

    breakdown = {item.job_type: item.failure_count for item in result.failure_breakdown}
    assert breakdown == {"config_push": 2, "backup": 1}


async def test_ztp_analytics_retry_dashboard_orders_nearest_to_exhaustion_first():
    repo = FakeZtpRepository()
    start, end = _now() - timedelta(days=1), _now() + timedelta(days=1)
    far_from_exhaustion = _job(
        status=ProvisioningJobStatus.FAILED, attempts=1, max_attempts=5
    )
    near_exhaustion = _job(
        status=ProvisioningJobStatus.FAILED, attempts=4, max_attempts=5
    )
    repo.jobs = [far_from_exhaustion, near_exhaustion]
    service = ZtpMonitoringService(repo)
    result = await service.get_analytics(start=start, end=end)

    assert result.retry_jobs[0].job_id == near_exhaustion.id
    assert result.retry_jobs[0].attempts_remaining == 1
    assert result.retry_jobs[1].job_id == far_from_exhaustion.id


async def test_ztp_analytics_activation_timing_average_and_sample_size():
    repo = FakeZtpRepository()
    start, end = _now() - timedelta(days=2), _now() + timedelta(days=1)
    router = _router(status=RouterStatus.ONLINE, last_seen_at=_now())
    reviewed_at = _now() - timedelta(hours=1)
    completed_at = _now()
    repo.routers = [router]
    repo.enrollments = [
        FakeEnrollment(
            id=uuid.uuid4(),
            status=EnrollmentStatus.APPROVED.value,
            approved_router_id=router.id,
            reviewed_at=reviewed_at,
        )
    ]
    job = _job(status=ProvisioningJobStatus.SUCCEEDED, job_type="initial_config")
    job.router_id = router.id
    job.completed_at = completed_at
    repo.jobs = [job]

    service = ZtpMonitoringService(repo)
    result = await service.get_analytics(start=start, end=end)

    assert result.activation_sample_size == 1
    assert (
        result.average_activation_seconds
        == (completed_at - reviewed_at).total_seconds()
    )


# ============================================================================
# PlatformDashboardService.get_dashboard_statistics
# ============================================================================


@dataclass
class FakeVisitorSummary:
    visitors: int
    unique_guests: int


@dataclass
class FakeGuestVisitorLookup:
    summary: FakeVisitorSummary

    async def get_summary(self, *, organization_id, location_id, start, end):
        return self.summary


async def test_platform_dashboard_composes_device_and_alert_statistics():
    repo = FakeZtpRepository()
    repo.routers = [
        _router(status=RouterStatus.ONLINE, last_seen_at=_now()),
        _router(status=RouterStatus.OFFLINE),
    ]
    repo.alert_severity_counts = [("critical", 2), ("warning", 1)]
    repo.alert_status_counts = [("triggered", 1), ("resolved", 2)]
    repo.health_check_stats = (10, 8, 42.5)

    ztp_service = ZtpMonitoringService(repo)
    dashboard_service = PlatformDashboardService(repo, ztp_service)

    result = await dashboard_service.get_dashboard_statistics(
        organization_id=None,
        start=_now() - timedelta(days=1),
        end=_now() + timedelta(days=1),
    )

    assert result.device_counts_by_status["online"] == 1
    assert result.device_counts_by_status["offline"] == 1
    assert result.alert_counts_by_severity == {"critical": 2, "warning": 1}
    assert result.alert_counts_by_status == {"triggered": 1, "resolved": 2}
    assert result.availability_percentage == round((8 / 10) * 100, 4)
    assert result.average_response_time_ms == 42.5
    assert result.visitors is None
    assert result.unique_guests is None


async def test_platform_dashboard_visitors_populated_only_with_organization_id():
    repo = FakeZtpRepository()
    ztp_service = ZtpMonitoringService(repo)
    dashboard_service = PlatformDashboardService(repo, ztp_service)
    guest_lookup = FakeGuestVisitorLookup(
        summary=FakeVisitorSummary(visitors=42, unique_guests=30)
    )
    organization_id = uuid.uuid4()

    with_org = await dashboard_service.get_dashboard_statistics(
        organization_id=organization_id,
        start=_now() - timedelta(days=1),
        end=_now() + timedelta(days=1),
        guest_visitor_lookup=guest_lookup,
    )
    without_org = await dashboard_service.get_dashboard_statistics(
        organization_id=None,
        start=_now() - timedelta(days=1),
        end=_now() + timedelta(days=1),
        guest_visitor_lookup=guest_lookup,
    )

    assert with_org.visitors == 42
    assert with_org.unique_guests == 30
    assert without_org.visitors is None
    assert without_org.unique_guests is None
