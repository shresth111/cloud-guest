"""The Report Generation Service (BE-012 Part 5): composes the existing
Parts 2-4 analytics services (``DashboardService``/``DomainAnalyticsService``/
``BusinessAnalyticsService``/``ForecastService``/``InsightService``) into one
assembled, format-agnostic ``report_types.ReportPayload`` -- plus the CRUD
services for the two new persisted tables, :class:`~.models.ReportTemplate`
and :class:`~.models.ScheduledReport`.

## Composition, never recomputation

``ReportGenerationService.generate`` contains **zero** metric arithmetic --
every number in a generated report was already computed by whichever
existing service call produced it (a dashboard rollup, a Part 3 analytics
query, a Part 4 forecast/insight). This module's only real logic is *which*
existing call(s) each :class:`~.constants.ReportType` maps to, and how their
already-typed Pydantic responses become :class:`~.report_types.
ReportSection` entries (via ``.model_dump(mode="json")`` -- the exact same
shape those services' own HTTP endpoints already return). See each
``ReportType`` member's own docstring in ``constants.py`` for the exact
service call it maps to.

## Manual vs. scheduled generation -- no separate persisted state

Every call to :meth:`ReportGenerationService.generate` is "manual" in the
sense that nothing about the method itself distinguishes an on-demand
``POST /reports`` call from ``report_tasks.run_scheduled_reports``'s own
per-``ScheduledReport`` call -- both paths call the exact same method with
the exact same contract. See :class:`~.models.ReportTemplate`'s own
docstring for why no additional "manual report run" table exists: the
permanent record of a generation happening is ``audit_log_entries`` (written
unconditionally by :meth:`ReportGenerationService.generate` -- see below),
not a second row in this domain's own tables.

## Audit: full, not throttled

Every call to :meth:`generate` writes exactly one
``audit_log_entries`` row, unconditionally -- unlike Part 2's own
dashboard-view audit (``dashboard_audit.DashboardAuditThrottle``, at most
one row per 15-minute window per caller+kind+scope, see that module's own
volume-tiering docstring). Report generation is inherently a much
lower-volume event than a dashboard *view* (nothing auto-polls/refreshes a
report the way an admin UI's dashboard tile does; generating one is always
a deliberate, one-off action, or a Beat tick capped at whatever schedules
exist), and the module brief is explicit that this is exactly the kind of
event compliance/security visibility cares about ("who generated what
report, for which organization, in what format, and when"). Unconditional,
un-throttled auditing is therefore the correct call here, not a gap in an
otherwise-consistent throttling policy.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Protocol

from pydantic import BaseModel

from app.database.utils.pagination import PaginationMeta

from .business_service import BusinessAnalyticsService
from .constants import (
    AUDIT_ACTION_REPORT_GENERATED,
    AUDIT_ACTION_REPORT_TEMPLATE_CREATED,
    AUDIT_ACTION_REPORT_TEMPLATE_DELETED,
    AUDIT_ACTION_REPORT_TEMPLATE_UPDATED,
    AUDIT_ACTION_SCHEDULED_REPORT_CREATED,
    AUDIT_ACTION_SCHEDULED_REPORT_DELETED,
    AUDIT_ACTION_SCHEDULED_REPORT_UPDATED,
    MONTHLY_WINDOW_DAYS,
    WEEKLY_WINDOW_DAYS,
    ExportFormat,
    ReportFrequency,
    ReportType,
)
from .dashboard_scope import DashboardScopeLevel, DashboardScopeResolver
from .dashboard_service import DashboardService
from .domain_analytics_service import DomainAnalyticsService
from .exceptions import (
    MissingReportParametersError,
    ReportTemplateNotFoundError,
    ScheduledReportNotFoundError,
)
from .forecast_service import ForecastService
from .insight_service import InsightService
from .models import ReportTemplate, ScheduledReport
from .report_repository import ReportRepositoryProtocol
from .report_schemas import (
    ReportTemplateCreateRequest,
    ReportTemplateUpdateRequest,
    ScheduledReportCreateRequest,
    ScheduledReportUpdateRequest,
)
from .report_types import ReportPayload, ReportSection
from .validators import resolve_analytics_window

_TITLES: dict[ReportType, str] = {
    ReportType.DASHBOARD: "Platform Dashboard Report",
    ReportType.ORGANIZATION: "Organization Report",
    ReportType.LOCATION: "Location Report",
    ReportType.ROUTER: "Router Analytics Report",
    ReportType.GUEST: "Guest Analytics Report",
    ReportType.NETWORK: "Network Analytics Report",
    ReportType.REVENUE: "Business & Revenue Report",
    ReportType.HEALTH: "Platform & Organization Health Report",
}

# How many days :func:`compute_next_run_at` advances ``next_run_at`` by, per
# ``ReportFrequency``. ``WEEKLY``/``MONTHLY`` reuse this domain's own
# existing ``WEEKLY_WINDOW_DAYS``/``MONTHLY_WINDOW_DAYS`` constants (Part
# 2's "how many days is a week/month" figures) rather than re-deriving the
# same numbers under a new name; a calendar-month-aware "same day next
# month" is deliberately not attempted -- a fixed 30-day cadence is the same
# honest approximation this domain's own ``MONTHLY_WINDOW_DAYS`` already
# makes for "monthly" everywhere else it appears.
_FREQUENCY_DAYS: dict[ReportFrequency, int] = {
    ReportFrequency.DAILY: 1,
    ReportFrequency.WEEKLY: WEEKLY_WINDOW_DAYS,
    ReportFrequency.MONTHLY: MONTHLY_WINDOW_DAYS,
}


def compute_next_run_at(frequency: ReportFrequency, base: datetime) -> datetime:
    """The next occurrence of ``frequency`` after ``base`` -- used both when
    a :class:`~.models.ScheduledReport` is first created (``base=now``) and
    after every run (``base=the run's own now``, never ``next_run_at``
    itself, so a schedule that was somehow skipped for a while does not
    fire a burst of catch-up runs -- see ``report_tasks.py``'s own
    docstring for the exact write-up)."""
    return base + timedelta(days=_FREQUENCY_DAYS[frequency])


class AuditLogWriter(Protocol):
    async def create_audit_log_entry(self, **fields: object) -> object: ...


def _section(key: str, title: str, response: BaseModel) -> ReportSection:
    return ReportSection(key=key, title=title, data=response.model_dump(mode="json"))


class ReportGenerationService:
    """Composes existing analytics services into an assembled
    :class:`~.report_types.ReportPayload` -- see module docstring."""

    def __init__(
        self,
        dashboard_service: DashboardService,
        domain_analytics_service: DomainAnalyticsService,
        business_analytics_service: BusinessAnalyticsService,
        forecast_service: ForecastService,
        insight_service: InsightService,
        *,
        audit_writer: AuditLogWriter | None = None,
    ) -> None:
        self.dashboard_service = dashboard_service
        self.domain_analytics_service = domain_analytics_service
        self.business_analytics_service = business_analytics_service
        self.forecast_service = forecast_service
        self.insight_service = insight_service
        self.audit_writer = audit_writer

    async def generate(
        self,
        user_id: uuid.UUID,
        *,
        report_type: ReportType,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        start: datetime | None,
        end: datetime | None,
        include_router_failure_risk: bool = True,
        export_format: ExportFormat | None = None,
        template_id: uuid.UUID | None = None,
    ) -> ReportPayload:
        """Assembles a :class:`~.report_types.ReportPayload` for
        ``report_type``. ``export_format``/``template_id`` are optional,
        audit-only context (this method itself never renders/exports
        anything -- see ``export.render_report`` for that) -- see module
        docstring for the audit contract.

        Every scope check is delegated entirely to whichever existing
        service method is called below (``DashboardScope.require_global``/
        ``require_organization``/``require_location``, already exercised by
        that service's own HTTP endpoint) -- this method adds no second,
        parallel scope check of its own, exactly this part's own
        composition-not-reimplementation mandate.
        """
        now = datetime.now(UTC)
        sections: list[ReportSection] = []
        period_start: str | None = None
        period_end: str | None = None

        if report_type == ReportType.DASHBOARD:
            response = await self.dashboard_service.get_super_admin_dashboard(user_id)
            sections.append(
                _section("platform_dashboard", "Platform Dashboard", response)
            )

        elif report_type == ReportType.ORGANIZATION:
            if organization_id is None:
                raise MissingReportParametersError(
                    "organization_id is required to generate an ORGANIZATION report"
                )
            response = await self.dashboard_service.get_organization_dashboard(
                user_id, organization_id
            )
            sections.append(
                _section("organization_dashboard", "Organization Dashboard", response)
            )

        elif report_type == ReportType.LOCATION:
            if location_id is None:
                raise MissingReportParametersError(
                    "location_id is required to generate a LOCATION report"
                )
            response = await self.dashboard_service.get_location_dashboard(
                user_id, location_id
            )
            sections.append(
                _section("location_dashboard", "Location Dashboard", response)
            )

        elif report_type in (ReportType.ROUTER, ReportType.GUEST, ReportType.NETWORK):
            if organization_id is None:
                raise MissingReportParametersError(
                    f"organization_id is required to generate a "
                    f"{report_type.value.upper()} report"
                )
            window_start, window_end = resolve_analytics_window(start, end)
            period_start, period_end = window_start.isoformat(), window_end.isoformat()

            if report_type == ReportType.ROUTER:
                response = await self.domain_analytics_service.get_router_analytics(
                    user_id,
                    organization_id,
                    location_id=location_id,
                    start=window_start,
                    end=window_end,
                )
                sections.append(
                    _section("router_analytics", "Router Analytics", response)
                )
            elif report_type == ReportType.GUEST:
                response = await self.domain_analytics_service.get_guest_analytics(
                    user_id,
                    organization_id,
                    location_id=location_id,
                    start=window_start,
                    end=window_end,
                )
                sections.append(
                    _section("guest_analytics", "Guest Analytics", response)
                )
            else:
                response = await self.domain_analytics_service.get_network_analytics(
                    user_id,
                    organization_id,
                    location_id=location_id,
                    start=window_start,
                    end=window_end,
                )
                sections.append(
                    _section("network_analytics", "Network Analytics", response)
                )

        elif report_type == ReportType.REVENUE:
            response = await self.business_analytics_service.get_business_analytics(
                user_id
            )
            sections.append(
                _section("business_analytics", "Business Analytics (Revenue)", response)
            )

        elif report_type == ReportType.HEALTH:
            business_insights = await self.insight_service.get_business_insights(
                user_id
            )
            sections.append(
                _section("business_insights", "Business Insights", business_insights)
            )
            operational = await self.insight_service.get_operational_recommendations(
                user_id
            )
            sections.append(
                _section(
                    "operational_recommendations",
                    "Operational Recommendations",
                    operational,
                )
            )
            if organization_id is not None and include_router_failure_risk:
                risk = await self.forecast_service.get_router_failure_risk(
                    user_id, organization_id, location_id=location_id
                )
                sections.append(
                    _section("router_failure_risk", "Router Failure Risk", risk)
                )

        payload = ReportPayload(
            report_type=report_type.value,
            title=_TITLES[report_type],
            generated_at=now.isoformat(),
            organization_id=organization_id,
            location_id=location_id,
            period_start=period_start,
            period_end=period_end,
            sections=sections,
        )

        await self._audit(
            user_id,
            report_type=report_type,
            organization_id=organization_id,
            location_id=location_id,
            export_format=export_format,
            template_id=template_id,
        )
        return payload

    async def _audit(
        self,
        user_id: uuid.UUID,
        *,
        report_type: ReportType,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        export_format: ExportFormat | None,
        template_id: uuid.UUID | None,
    ) -> None:
        """Unconditional -- see module docstring's "full, not throttled"
        write-up. No Redis dedup gate, unlike every ``_maybe_audit`` this
        domain's Parts 2-4 services define."""
        if self.audit_writer is None:
            return
        description = f"{report_type.value} report generated"
        if export_format is not None:
            description = f"{description} ({export_format.value})"
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=user_id,
            action=AUDIT_ACTION_REPORT_GENERATED,
            entity_type="report_template" if template_id else "report",
            entity_id=template_id,
            description=description,
            event_metadata={
                "report_type": report_type.value,
                "export_format": export_format.value if export_format else None,
                "template_id": str(template_id) if template_id else None,
            },
            organization_id=organization_id,
            location_id=location_id,
        )


class ReportTemplateService:
    """CRUD over :class:`~.models.ReportTemplate`, gated by the same
    ``DashboardScopeResolver`` every other analytics service in this domain
    composes with (never reimplemented)."""

    def __init__(
        self,
        repository: ReportRepositoryProtocol,
        scope_resolver: DashboardScopeResolver,
        *,
        audit_writer: AuditLogWriter | None = None,
    ) -> None:
        self.repository = repository
        self.scope_resolver = scope_resolver
        self.audit_writer = audit_writer

    async def create_template(
        self,
        user_id: uuid.UUID,
        organization_id: uuid.UUID | None,
        payload: ReportTemplateCreateRequest,
    ) -> ReportTemplate:
        scope = await self.scope_resolver.resolve(user_id)
        if organization_id is None:
            scope.require_global()
        else:
            scope.require_organization(organization_id)

        template = await self.repository.create_template(
            name=payload.name,
            description=payload.description,
            organization_id=organization_id,
            report_type=payload.report_type.value,
            config=payload.config,
            is_active=payload.is_active,
            created_by_user_id=user_id,
        )
        await self._audit(
            user_id,
            action=AUDIT_ACTION_REPORT_TEMPLATE_CREATED,
            template=template,
            description=f"Report template '{template.name}' created",
        )
        return template

    async def get_visible_template(
        self, user_id: uuid.UUID, template_id: uuid.UUID
    ) -> ReportTemplate:
        """Raises :class:`~.exceptions.ReportTemplateNotFoundError` for both
        a truly-nonexistent id and one that exists but belongs to an
        organization outside the caller's ``DashboardScope`` -- see that
        exception's own docstring for why both collapse to the same
        response."""
        template = await self.repository.get_template(template_id)
        if template is None:
            raise ReportTemplateNotFoundError(template_id)
        if template.organization_id is not None:
            scope = await self.scope_resolver.resolve(user_id)
            if not scope.allows_organization(template.organization_id):
                raise ReportTemplateNotFoundError(template_id)
        return template

    async def list_templates(
        self, user_id: uuid.UUID, *, page: int, page_size: int
    ) -> tuple[list[ReportTemplate], PaginationMeta]:
        scope = await self.scope_resolver.resolve(user_id)
        see_all = scope.level == DashboardScopeLevel.GLOBAL
        organization_ids = list(scope.organization_ids) if not see_all else None
        return await self.repository.list_templates(
            see_all=see_all,
            organization_ids=organization_ids,
            page=page,
            page_size=page_size,
        )

    async def update_template(
        self,
        user_id: uuid.UUID,
        template_id: uuid.UUID,
        payload: ReportTemplateUpdateRequest,
    ) -> ReportTemplate:
        template = await self.get_visible_template(user_id, template_id)
        fields = payload.model_dump(exclude_unset=True)
        updated = await self.repository.update_template(template, fields)
        await self._audit(
            user_id,
            action=AUDIT_ACTION_REPORT_TEMPLATE_UPDATED,
            template=updated,
            description=f"Report template '{updated.name}' updated",
        )
        return updated

    async def delete_template(self, user_id: uuid.UUID, template_id: uuid.UUID) -> None:
        template = await self.get_visible_template(user_id, template_id)
        await self.repository.soft_delete_template(template)
        await self._audit(
            user_id,
            action=AUDIT_ACTION_REPORT_TEMPLATE_DELETED,
            template=template,
            description=f"Report template '{template.name}' deleted",
        )

    async def _audit(
        self,
        user_id: uuid.UUID,
        *,
        action: str,
        template: ReportTemplate,
        description: str,
    ) -> None:
        if self.audit_writer is None:
            return
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=user_id,
            action=action,
            entity_type="report_template",
            entity_id=template.id,
            description=description,
            event_metadata={"report_type": template.report_type},
            organization_id=template.organization_id,
            location_id=None,
        )


class ScheduledReportService:
    """CRUD over :class:`~.models.ScheduledReport` -- ``next_run_at`` is
    always computed here (never trusted from the request), from
    :func:`compute_next_run_at`."""

    def __init__(
        self,
        repository: ReportRepositoryProtocol,
        scope_resolver: DashboardScopeResolver,
        template_service: ReportTemplateService,
        *,
        audit_writer: AuditLogWriter | None = None,
    ) -> None:
        self.repository = repository
        self.scope_resolver = scope_resolver
        self.template_service = template_service
        self.audit_writer = audit_writer

    async def create_schedule(
        self,
        user_id: uuid.UUID,
        organization_id: uuid.UUID,
        payload: ScheduledReportCreateRequest,
    ) -> ScheduledReport:
        scope = await self.scope_resolver.resolve(user_id)
        scope.require_organization(organization_id)
        # Confirms the template both exists and is visible to this caller --
        # reuses ReportTemplateService's own visibility rule rather than a
        # second, parallel lookup.
        await self.template_service.get_visible_template(user_id, payload.template_id)

        now = datetime.now(UTC)
        schedule = await self.repository.create_schedule(
            template_id=payload.template_id,
            organization_id=organization_id,
            frequency=payload.frequency.value,
            recipient_emails=payload.recipient_emails,
            export_format=payload.export_format.value,
            next_run_at=compute_next_run_at(payload.frequency, now),
            is_active=payload.is_active,
            created_by_user_id=user_id,
        )
        await self._audit(
            user_id,
            action=AUDIT_ACTION_SCHEDULED_REPORT_CREATED,
            schedule=schedule,
            description="Scheduled report created",
        )
        return schedule

    async def get_visible_schedule(
        self, user_id: uuid.UUID, schedule_id: uuid.UUID
    ) -> ScheduledReport:
        schedule = await self.repository.get_schedule(schedule_id)
        if schedule is None:
            raise ScheduledReportNotFoundError(schedule_id)
        scope = await self.scope_resolver.resolve(user_id)
        if not scope.allows_organization(schedule.organization_id):
            raise ScheduledReportNotFoundError(schedule_id)
        return schedule

    async def list_schedules(
        self, user_id: uuid.UUID, *, page: int, page_size: int
    ) -> tuple[list[ScheduledReport], PaginationMeta]:
        scope = await self.scope_resolver.resolve(user_id)
        see_all = scope.level == DashboardScopeLevel.GLOBAL
        organization_ids = list(scope.organization_ids) if not see_all else None
        return await self.repository.list_schedules(
            see_all=see_all,
            organization_ids=organization_ids,
            page=page,
            page_size=page_size,
        )

    async def update_schedule(
        self,
        user_id: uuid.UUID,
        schedule_id: uuid.UUID,
        payload: ScheduledReportUpdateRequest,
    ) -> ScheduledReport:
        schedule = await self.get_visible_schedule(user_id, schedule_id)
        fields = payload.model_dump(exclude_unset=True)
        if "frequency" in fields and fields["frequency"] is not None:
            fields["frequency"] = payload.frequency.value
            # A cadence change re-bases next_run_at from now, rather than
            # leaving a stale value computed under the old frequency.
            fields["next_run_at"] = compute_next_run_at(
                payload.frequency, datetime.now(UTC)
            )
        if "export_format" in fields and fields["export_format"] is not None:
            fields["export_format"] = payload.export_format.value
        updated = await self.repository.update_schedule(schedule, fields)
        await self._audit(
            user_id,
            action=AUDIT_ACTION_SCHEDULED_REPORT_UPDATED,
            schedule=updated,
            description="Scheduled report updated",
        )
        return updated

    async def delete_schedule(self, user_id: uuid.UUID, schedule_id: uuid.UUID) -> None:
        schedule = await self.get_visible_schedule(user_id, schedule_id)
        await self.repository.soft_delete_schedule(schedule)
        await self._audit(
            user_id,
            action=AUDIT_ACTION_SCHEDULED_REPORT_DELETED,
            schedule=schedule,
            description="Scheduled report deleted",
        )

    async def _audit(
        self,
        user_id: uuid.UUID,
        *,
        action: str,
        schedule: ScheduledReport,
        description: str,
    ) -> None:
        if self.audit_writer is None:
            return
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=user_id,
            action=action,
            entity_type="scheduled_report",
            entity_id=schedule.id,
            description=description,
            event_metadata={"frequency": schedule.frequency},
            organization_id=schedule.organization_id,
            location_id=None,
        )


__all__ = [
    "ReportGenerationService",
    "ReportTemplateService",
    "ScheduledReportService",
    "AuditLogWriter",
    "compute_next_run_at",
]
