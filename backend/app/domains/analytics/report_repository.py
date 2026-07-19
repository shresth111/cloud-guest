"""Data access layer for the Report Engine (BE-012 Part 5): CRUD over
:class:`~.models.ReportTemplate`/:class:`~.models.ScheduledReport`, plus the
one hand-written query neither ``GenericRepository`` nor a plain equality
filter can express -- "which schedules are due right now"
(``get_due_scheduled_reports``, a ``next_run_at <= now`` range comparison).

Kept as its own small file, separate from ``repository.py``
(``AnalyticsRepository``, BE-012 Part 1's own 75KB, ``AnalyticsSnapshot``-
centric data-access module) -- these two tables have nothing to do with
snapshot aggregation, and appending them there would make an already large
file larger for no cohesion benefit. Both classes still live in this same
domain package (``app.domains.analytics``), per this part's own directory
rule.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Protocol

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PageParams, PaginationMeta, paginate

from .models import ReportTemplate, ScheduledReport


class ReportRepositoryProtocol(Protocol):
    """The narrow surface ``report_service.py`` needs -- lets the service
    layer and its tests depend on this ``Protocol`` rather than the
    concrete, ``AsyncSession``-backed implementation below (the same
    composition pattern ``AnalyticsRepositoryProtocol`` already
    establishes for this domain)."""

    async def create_template(self, **fields: object) -> ReportTemplate: ...

    async def get_template(
        self, template_id: uuid.UUID, *, include_deleted: bool = False
    ) -> ReportTemplate | None: ...

    async def list_templates(
        self,
        *,
        see_all: bool,
        organization_ids: list[uuid.UUID] | None,
        page: int,
        page_size: int,
    ) -> tuple[list[ReportTemplate], PaginationMeta]: ...

    async def update_template(
        self, template: ReportTemplate, fields: dict[str, object]
    ) -> ReportTemplate: ...

    async def soft_delete_template(
        self, template: ReportTemplate
    ) -> ReportTemplate: ...

    async def create_schedule(self, **fields: object) -> ScheduledReport: ...

    async def get_schedule(
        self, schedule_id: uuid.UUID, *, include_deleted: bool = False
    ) -> ScheduledReport | None: ...

    async def list_schedules(
        self,
        *,
        see_all: bool,
        organization_ids: list[uuid.UUID] | None,
        page: int,
        page_size: int,
    ) -> tuple[list[ScheduledReport], PaginationMeta]: ...

    async def update_schedule(
        self, schedule: ScheduledReport, fields: dict[str, object]
    ) -> ScheduledReport: ...

    async def soft_delete_schedule(
        self, schedule: ScheduledReport
    ) -> ScheduledReport: ...

    async def get_due_scheduled_reports(
        self, *, now: datetime
    ) -> list[ScheduledReport]: ...


class ReportRepository:
    """Concrete, SQLAlchemy-backed implementation of
    :class:`ReportRepositoryProtocol`."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.templates = GenericRepository(ReportTemplate, session)
        self.schedules = GenericRepository(ScheduledReport, session)

    # -- ReportTemplate CRUD -------------------------------------------------

    async def create_template(self, **fields: object) -> ReportTemplate:
        return await self.templates.create(fields)

    async def get_template(
        self, template_id: uuid.UUID, *, include_deleted: bool = False
    ) -> ReportTemplate | None:
        return await self.templates.get_by_id(
            template_id, include_deleted=include_deleted
        )

    async def list_templates(
        self,
        *,
        see_all: bool,
        organization_ids: list[uuid.UUID] | None,
        page: int,
        page_size: int,
    ) -> tuple[list[ReportTemplate], PaginationMeta]:
        """Every template visible to one caller.

        ``see_all=True`` (a GLOBAL-scoped caller): every template, platform-
        wide and every organization's, no filter at all -- a Super Admin's
        dashboard scope already covers every organization, so narrowing
        this query would just be slower for the same result.

        ``see_all=False``: platform-wide (``NULL`` ``organization_id``)
        **system templates are always included** -- they carry no
        tenant-specific data, only a report *definition*, so every caller
        may see them regardless of their own ``DashboardScope`` -- unioned
        with whatever real organizations ``organization_ids`` names
        (``None``/empty means "no organization-scoped templates are
        visible on top of the platform-wide ones", e.g. a caller with no
        resolved organization/location scope at all)."""
        conditions = [ReportTemplate.is_deleted.is_(False)]
        if not see_all:
            scope_conditions = [ReportTemplate.organization_id.is_(None)]
            if organization_ids:
                scope_conditions.append(
                    ReportTemplate.organization_id.in_(organization_ids)
                )
            conditions.append(or_(*scope_conditions))

        params = PageParams(page=page, page_size=page_size)

        count_statement = (
            select(func.count()).select_from(ReportTemplate).where(*conditions)
        )
        total_items = int((await self.session.execute(count_statement)).scalar_one())

        statement = (
            select(ReportTemplate)
            .where(*conditions)
            .order_by(ReportTemplate.created_at.desc())
        )
        result = await self.session.execute(paginate(statement, params))
        items = list(result.scalars().all())
        return items, PaginationMeta.from_total(params, total_items)

    async def update_template(
        self, template: ReportTemplate, fields: dict[str, object]
    ) -> ReportTemplate:
        return await self.templates.partial_update(template, fields)

    async def soft_delete_template(self, template: ReportTemplate) -> ReportTemplate:
        return await self.templates.soft_delete(template)

    # -- ScheduledReport CRUD -------------------------------------------------

    async def create_schedule(self, **fields: object) -> ScheduledReport:
        return await self.schedules.create(fields)

    async def get_schedule(
        self, schedule_id: uuid.UUID, *, include_deleted: bool = False
    ) -> ScheduledReport | None:
        return await self.schedules.get_by_id(
            schedule_id, include_deleted=include_deleted
        )

    async def list_schedules(
        self,
        *,
        see_all: bool,
        organization_ids: list[uuid.UUID] | None,
        page: int,
        page_size: int,
    ) -> tuple[list[ScheduledReport], PaginationMeta]:
        """Unlike :meth:`list_templates`, a :class:`ScheduledReport` has no
        platform-wide row to also union in (``organization_id`` is
        required, never ``NULL`` -- see that model's own docstring). A
        GLOBAL-scoped caller (``see_all=True``) sees every organization's
        schedules; otherwise an empty/``None`` ``organization_ids``
        genuinely means "this caller can see zero schedules", not "apply no
        filter" -- ``GenericRepository.paginate``'s own filter convention
        treats a missing filter value as "no constraint", which would
        incorrectly return every organization's schedules here, so that
        case is special-cased to an explicit empty page instead of falling
        through to it."""
        if see_all:
            return await self.schedules.paginate(page=page, page_size=page_size)
        if not organization_ids:
            return [], PaginationMeta.from_total(
                PageParams(page=page, page_size=page_size), 0
            )
        return await self.schedules.paginate(
            page=page,
            page_size=page_size,
            filters={"organization_id": organization_ids},
        )

    async def update_schedule(
        self, schedule: ScheduledReport, fields: dict[str, object]
    ) -> ScheduledReport:
        return await self.schedules.partial_update(schedule, fields)

    async def soft_delete_schedule(self, schedule: ScheduledReport) -> ScheduledReport:
        return await self.schedules.soft_delete(schedule)

    # -- Scheduler sweep -------------------------------------------------

    async def get_due_scheduled_reports(
        self, *, now: datetime
    ) -> list[ScheduledReport]:
        """Every active, non-deleted :class:`ScheduledReport` whose
        ``next_run_at`` has arrived -- the exact query
        ``report_tasks.run_scheduled_reports``'s hourly Beat tick runs (see
        that module's docstring for the full resilience write-up)."""
        statement = (
            select(ScheduledReport)
            .where(
                ScheduledReport.is_deleted.is_(False),
                ScheduledReport.is_active.is_(True),
                ScheduledReport.next_run_at <= now,
            )
            .order_by(ScheduledReport.next_run_at.asc())
        )
        result = await self.session.execute(statement)
        return list(result.scalars().all())


__all__ = ["ReportRepository", "ReportRepositoryProtocol"]
