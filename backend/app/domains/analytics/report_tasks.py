"""Celery task definitions for the Report Engine's scheduler (BE-012 Part 5:
``report_tasks.run_scheduled_reports``, the Beat-scheduled task
``app.core.celery_app``'s own ``beat_schedule`` registers).

Mirrors ``tasks.py``'s exact async-bridge + per-item-failure-isolation
pattern (BE-012 Part 1) -- a plain, synchronous ``@celery_app.task`` body
delegating immediately to a module-level ``async def`` via ``asyncio.run``,
which opens a fresh ``AsyncSession``/Redis client, builds the real
repository/service graph, does the actual work, commits, and returns a
plain, JSON-serializable result. See ``tasks.py``'s own module docstring for
why ``asyncio.run`` is safe here (a Celery worker task body never itself has
a running event loop underneath it).

## Why hourly, not every 15 minutes

``analytics-rolling-today``'s 15-minute cadence exists because a dashboard
should feel "near real-time". A :class:`~.models.ScheduledReport`'s
coarsest-grained unit is a whole day (``ReportFrequency.DAILY``) -- checking
for due schedules every 15 minutes would mean up to 96 no-op sweeps for
every real delivery, for no freshness benefit anyone asked for (nobody is
watching a report email arrive within 15 minutes of its scheduled time the
way they watch a dashboard tile refresh). An hourly sweep still delivers
every ``DAILY``/``WEEKLY``/``MONTHLY`` schedule within an hour of its
``next_run_at``, at a fraction of the query volume.

## Per-schedule failure isolation -- the same guarantee as Part 1's own
## per-organization aggregation batch

One :class:`~.models.ScheduledReport` failing to render/send (a template
whose underlying organization was since archived, a malformed
``config``, a transient email-provider error) must never block every other
due schedule in the same hourly sweep from running -- exactly
``AnalyticsService.run_daily_aggregation_for_all_organizations``'s own
per-organization isolation contract (see ``tasks.py``'s module docstring).
Each schedule's generate-render-send-and-update-state sequence runs inside
its own ``try/except``; a failure is logged, the schedule's own
``last_run_status``/``last_run_at``/``next_run_at`` are still updated (so a
persistently broken schedule retries at its normal cadence next time, not
on every single hourly tick forever -- a real backoff, not a busy-loop), and
the sweep moves on to the next due schedule. The batch result reports
every failure; it never re-raises a single schedule's failure to the Beat
scheduler.

## Email delivery: real dispatch, honest attachment limitation

``app.domains.otp``'s ``EmailProviderProtocol``/``LoggingEmailProvider`` are
reused exactly as specified -- no second email abstraction is built for
this part. That protocol's own contract is ``send(email, subject, body)
-> None``: three strings, no attachment parameter. The rendered report's
bytes (``export.render_report``'s output) are real and correct regardless
of format; what this task's email honestly cannot do is attach them to the
message, since the shared protocol was never built with a MIME/attachment
concept. The notification email therefore describes the generated report
(title, format, size, generation time) rather than attaching it -- an
honest limitation of composing with the existing protocol as specified,
not a shortcut around building one. A future part wiring a real
transactional-email provider with attachment support is a natural
follow-up; it is out of this part's own scope (reusing what already exists,
not extending ``otp``'s own interface -- see this part's directory rule).
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from app.core.celery_app import celery_app
from app.core.config import get_settings
from app.core.logging import get_logger
from app.database.redis import create_redis_client
from app.database.session import SessionLocal
from app.domains.guest.repository import GuestRepository
from app.domains.guest.service import GuestAnalyticsService
from app.domains.location.repository import LocationRepository
from app.domains.location.service import LocationService
from app.domains.organization.repository import OrganizationRepository
from app.domains.organization.service import OrganizationService
from app.domains.otp.service import EmailProviderProtocol, LoggingEmailProvider
from app.domains.rbac.authorization import RoleResolver
from app.domains.rbac.repository import RBACRepository
from app.domains.router.repository import RouterRepository
from app.domains.router.service import RouterService
from app.domains.wireguard.repository import WireGuardRepository
from app.domains.wireguard.service import WireGuardService

from .business_service import BusinessAnalyticsService
from .constants import (
    TASK_RUN_SCHEDULED_REPORTS,
    ExportFormat,
    ReportFrequency,
    ReportRunStatus,
    ReportType,
)
from .dashboard_scope import DashboardScopeResolver
from .dashboard_service import DashboardService
from .domain_analytics_service import DomainAnalyticsService
from .export import render_report
from .forecast_service import ForecastService
from .insight_service import InsightService
from .models import ScheduledReport
from .report_repository import ReportRepository
from .report_service import ReportGenerationService, compute_next_run_at
from .repository import AnalyticsRepository

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class ScheduledReportBatchResult:
    total_due: int
    succeeded: int
    failed: list[tuple[uuid.UUID, str]] = field(default_factory=list)


async def _run_one_scheduled_report(
    report_repository: ReportRepository,
    generation_service: ReportGenerationService,
    email_provider: EmailProviderProtocol,
    schedule: ScheduledReport,
    *,
    now: datetime,
) -> None:
    """Generates, renders, and "sends" exactly one due
    :class:`~.models.ScheduledReport`. Raises on any failure -- the caller
    (:func:`_run_scheduled_reports_async`) is the one that isolates this
    per-schedule, per the module docstring."""
    template = await report_repository.get_template(schedule.template_id)
    if template is None:
        raise ValueError(
            f"ReportTemplate {schedule.template_id} referenced by "
            f"ScheduledReport {schedule.id} no longer exists"
        )

    actor_user_id = schedule.created_by_user_id or template.created_by_user_id
    if actor_user_id is None:
        raise ValueError(
            f"ScheduledReport {schedule.id} has no attributable creator user "
            f"id to authorize report generation against"
        )

    config = template.config or {}
    location_id = (
        uuid.UUID(str(config["location_id"])) if config.get("location_id") else None
    )
    window_days = config.get("window_days")
    start = now - timedelta(days=int(window_days)) if window_days else None
    end = now if window_days else None

    payload = await generation_service.generate(
        actor_user_id,
        report_type=ReportType(template.report_type),
        organization_id=schedule.organization_id,
        location_id=location_id,
        start=start,
        end=end,
        include_router_failure_risk=bool(
            config.get("include_router_failure_risk", True)
        ),
        export_format=ExportFormat(schedule.export_format),
        template_id=schedule.template_id,
    )
    rendered = render_report(payload, ExportFormat(schedule.export_format))

    subject = f"{payload.title} - {now.date().isoformat()}"
    body = (
        f"Your scheduled {payload.report_type} report has been generated "
        f"({rendered.content_type}, {len(rendered.content)} bytes). See "
        f"this module's own docstring for why the file itself is not "
        f"attached to this notification."
    )
    for recipient in schedule.recipient_emails:
        await email_provider.send(recipient, subject, body)


async def run_scheduled_report_batch(
    report_repository: ReportRepository,
    generation_service: ReportGenerationService,
    email_provider: EmailProviderProtocol,
    due_schedules: list[ScheduledReport],
    *,
    now: datetime,
) -> ScheduledReportBatchResult:
    """The per-schedule failure-isolation loop itself -- deliberately kept
    as a standalone function taking already-constructed dependencies
    (rather than inlined into :func:`_run_scheduled_reports_async`, which
    is the only piece of this module that actually needs a real
    ``AsyncSession``/Redis client) so it is unit-testable with fakes, no
    live database required -- mirrors ``AnalyticsService.run_daily_
    aggregation_for_all_organizations``'s own identical split (BE-012 Part
    1): the real per-organization/per-schedule isolation logic lives in a
    plain, fake-repository-testable function; only the Celery task's own
    async bridge (:func:`_run_scheduled_reports_async`) needs a real
    session and is instead tested by mocking that whole bridge out (see
    ``tasks.py``'s own precedent for this exact split)."""
    succeeded = 0
    failed: list[tuple[uuid.UUID, str]] = []
    for schedule in due_schedules:
        next_run_at = compute_next_run_at(ReportFrequency(schedule.frequency), now)
        try:
            await _run_one_scheduled_report(
                report_repository, generation_service, email_provider, schedule, now=now
            )
            await report_repository.update_schedule(
                schedule,
                {
                    "last_run_at": now,
                    "last_run_status": ReportRunStatus.SUCCESS.value,
                    "next_run_at": next_run_at,
                },
            )
            succeeded += 1
        except Exception as exc:  # noqa: BLE001 -- per-schedule isolation, see above
            logger.exception(
                "scheduled_report_run_failed",
                extra={"scheduled_report_id": str(schedule.id)},
            )
            failed.append((schedule.id, str(exc)))
            try:
                await report_repository.update_schedule(
                    schedule,
                    {
                        "last_run_at": now,
                        "last_run_status": ReportRunStatus.FAILED.value,
                        "next_run_at": next_run_at,
                    },
                )
            except Exception:
                logger.exception(
                    "scheduled_report_status_update_failed",
                    extra={"scheduled_report_id": str(schedule.id)},
                )

    return ScheduledReportBatchResult(
        total_due=len(due_schedules), succeeded=succeeded, failed=failed
    )


async def _run_scheduled_reports_async(
    *, now_iso: str | None = None
) -> ScheduledReportBatchResult:
    """The actual async work behind ``run_scheduled_reports`` -- a fresh
    session and a fresh Redis client per task run (never shared across
    separate task invocations), mirroring ``tasks.py``'s own "fresh session
    per run" discipline."""
    now = datetime.fromisoformat(now_iso) if now_iso else datetime.now(UTC)
    settings = get_settings()

    async with SessionLocal() as session:
        redis = create_redis_client(settings)
        try:
            report_repository = ReportRepository(session)
            due_schedules = await report_repository.get_due_scheduled_reports(now=now)

            analytics_repository = AnalyticsRepository(session)
            guest_analytics_service = GuestAnalyticsService(GuestRepository(session))
            rbac_repository = RBACRepository(session)
            organization_service = OrganizationService(
                OrganizationRepository(session), audit_writer=rbac_repository
            )
            location_service = LocationService(
                LocationRepository(session),
                organization_service,
                audit_writer=rbac_repository,
            )
            role_resolver = RoleResolver(rbac_repository)
            scope_resolver = DashboardScopeResolver(
                role_resolver, organization_service, location_service
            )
            router_service = RouterService(
                RouterRepository(session),
                location_service,
                organization_service,
                audit_writer=rbac_repository,
                provisioning_token_ttl_hours=(
                    settings.router_provisioning_token_expire_hours
                ),
            )
            wireguard_service = WireGuardService(
                WireGuardRepository(session),
                router_service,
                audit_writer=rbac_repository,
                handshake_stale_after_minutes=(
                    settings.wireguard_handshake_stale_after_minutes
                ),
            )
            dashboard_service = DashboardService(
                analytics_repository,
                guest_analytics_service,
                scope_resolver,
                organization_service,
                location_service,
                redis,
                audit_writer=rbac_repository,
            )
            domain_analytics_service = DomainAnalyticsService(
                analytics_repository,
                guest_analytics_service,
                scope_resolver,
                wireguard_service,
                redis,
                audit_writer=rbac_repository,
            )
            business_analytics_service = BusinessAnalyticsService(
                analytics_repository,
                scope_resolver,
                redis,
                audit_writer=rbac_repository,
            )
            forecast_service = ForecastService(
                analytics_repository,
                scope_resolver,
                redis,
                settings,
                audit_writer=rbac_repository,
            )
            insight_service = InsightService(
                analytics_repository,
                scope_resolver,
                redis,
                settings,
                audit_writer=rbac_repository,
            )
            generation_service = ReportGenerationService(
                dashboard_service,
                domain_analytics_service,
                business_analytics_service,
                forecast_service,
                insight_service,
                audit_writer=rbac_repository,
            )
            email_provider: EmailProviderProtocol = LoggingEmailProvider()

            result = await run_scheduled_report_batch(
                report_repository,
                generation_service,
                email_provider,
                due_schedules,
                now=now,
            )
            await session.commit()
            return result
        except Exception:
            await session.rollback()
            raise
        finally:
            await redis.aclose()


@celery_app.task(name=TASK_RUN_SCHEDULED_REPORTS)
def run_scheduled_reports(now_iso: str | None = None) -> dict[str, object]:
    """Beat-scheduled periodic task (see ``app.core.celery_app``'s
    ``beat_schedule`` -- every ``constants
    .SCHEDULED_REPORTS_CHECK_INTERVAL_SECONDS``, i.e. hourly). Never
    re-raises a single schedule's failure -- see module docstring for the
    full per-schedule isolation write-up. ``now_iso`` is exposed (rather
    than always using the real current time) purely so tests/manual
    triggers can pin "now" deterministically -- the Beat schedule itself
    never passes it, always taking the real current time.
    """
    result = asyncio.run(_run_scheduled_reports_async(now_iso=now_iso))
    logger.info(
        "analytics_task_run_scheduled_reports_completed",
        extra={
            "total_due": result.total_due,
            "succeeded": result.succeeded,
            "failed_count": len(result.failed),
        },
    )
    return {
        "total_due": result.total_due,
        "succeeded": result.succeeded,
        "failed": [
            {"scheduled_report_id": str(schedule_id), "error": error}
            for schedule_id, error in result.failed
        ],
    }


__all__ = [
    "run_scheduled_reports",
    "run_scheduled_report_batch",
    "ScheduledReportBatchResult",
]
