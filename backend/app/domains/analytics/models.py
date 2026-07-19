"""SQLAlchemy ORM models for the Analytics domain (BE-012 Part 1: Analytics
Core Infrastructure).

Extends ``app.database.base.BaseModel`` (UUID PK, timestamps, soft-delete,
audit, version columns) for the same reason every other domain does --
Alembic autogenerate, ``GenericRepository``, and cross-domain FKs all keep
working uniformly.

One table: :class:`AnalyticsSnapshot` -- a pre-computed, persisted rollup
over a time window, the answer to "how do we query analytics fast across
millions of underlying ``GuestSession``/``GuestLoginHistory``/``Router``
rows without re-aggregating them on every dashboard request." This is
**not** a duplicate of ``app.domains.router_provisioning.models
.RouterHealthSnapshot`` -- that table is a per-router, point-in-time
metrics reading (CPU/memory/uptime/connected-clients for *one device*);
this table is a higher-level, organization/location/platform-scoped rollup
*across many routers and guests* for a time window. Nothing here
duplicates a single router's own health history, and nothing in
``router_provisioning`` is touched by this domain.

## Why Redis, not a second ``analytics_cache`` table

The module brief that inspired this part named ``analytics_cache`` as an
example table. This codebase already has an established, working pattern
for exactly this need -- "cache a computed result behind a TTL so a hot
read path doesn't repeat expensive work" -- in
``app.domains.rbac.cache.PermissionCache``, a Redis-backed cache with no
backing SQL table at all. A **second**, SQL-backed cache table here would
duplicate that pattern for no benefit: it would need its own TTL/eviction
logic (Postgres has no native per-row TTL), an index-maintenance cost this
table's write-heavy nature (busy dashboards re-warming a cache on every
near-miss) would make a real problem in practice, and would leave two
different "cache expiry" idioms in the same codebase to keep straight. This
domain therefore has **no** ``analytics_cache`` table: any future BE-012
part that wants request-scoped read-through caching in front of
``AnalyticsSnapshot`` queries should reuse Redis directly (the same TTL'd
key pattern ``PermissionCache`` already establishes), not add a redundant
table. See ``docs/analytics/FLOW.md`` for the full write-up of this
decision.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel


class AnalyticsSnapshot(BaseModel):
    """A pre-computed rollup over ``[period_start, period_end]`` for one
    ``snapshot_type`` (:class:`~.constants.AnalyticsSnapshotType`).

    ``organization_id``/``location_id`` are both nullable real foreign keys:
    ``NULL``/``NULL`` means a platform-wide snapshot
    (``PLATFORM_DAILY_SUMMARY``); ``organization_id`` set, ``location_id``
    ``NULL`` means an organization-wide snapshot (``ORG_DAILY_SUMMARY``);
    both set means a location-scoped snapshot (``LOCATION_DAILY_SUMMARY``).
    ``ondelete="SET NULL"`` on both mirrors
    ``app.domains.monitoring.models.PlatformEvent``'s identical convention
    for an optional-scope analytics/event row -- a deleted organization/
    location does not need its historical snapshots hard-deleted along with
    it, it only loses the (no-longer-resolvable) scope pointer.

    ``metrics`` (JSONB) is the actual computed numbers -- shape varies by
    ``snapshot_type``:

    * ``ORG_DAILY_SUMMARY`` / ``LOCATION_DAILY_SUMMARY`` (identical shape,
      the latter additionally scoped by ``location_id``)::

        {
          "guest_count_unique": int,
          "guest_count_new": int,
          "guest_count_returning": int,
          "session_count_total": int,
          "session_count_active": int,
          "average_session_duration_seconds": float | null,
          "total_bandwidth_bytes": int,
          "router_count_online": int,
          "router_count_offline": int,
          "router_count_total": int
        }

    * ``PLATFORM_DAILY_SUMMARY``::

        {
          "organization_count_total": int,
          "location_count_total": int,
          "router_count_online": int,
          "router_count_offline": int,
          "router_count_total": int,
          "guest_count_unique_today": int,
          "session_count_total_today": int
        }

    See ``app.domains.analytics.aggregation`` for exactly how each field is
    computed and ``docs/analytics/DATABASE.md`` for this table's full
    reference.

    ``computed_at``/``computation_duration_ms`` are the aggregation
    pipeline's own self-monitoring: when a row was actually produced (which
    may lag ``period_end`` by the Beat schedule's own cadence -- see
    ``app.core.celery_app``'s module docstring) and how long the real SQL
    aggregate queries behind it took to run, useful for noticing an
    aggregation job that is starting to slow down as data volume grows.

    ## Indexing rationale

    This table is explicitly the answer to "how do we query analytics fast
    across millions of underlying rows" -- so its own query pattern must
    itself stay fast regardless of how large it grows. The dashboard read
    path (both this part's own ``GET /analytics/snapshots`` and every later
    BE-012 part's per-domain dashboards) is always "give me the latest (or a
    date-ranged history of) snapshots for one organization/location and one
    snapshot_type" -- so
    ``(organization_id, snapshot_type, period_start)`` is indexed together
    as this table's primary query pattern (a composite index lets Postgres
    satisfy an equality-on-the-first-two-columns, range-on-the-third query
    with a single index scan instead of a full table scan or a
    bitmap-AND of two separate single-column indexes). ``location_id`` gets
    its own index for the location-scoped read path (a location is always
    also naturally scoped by its owning ``organization_id``, but is
    additionally indexed alone since ``GET /analytics/snapshots?location_id=``
    without an explicit ``organization_id`` is a legal, tenant-validated
    query -- see ``router.py``). ``period_start``/``period_end`` each get
    their own index too, for a date-range query that spans every
    organization (e.g. a future platform-wide historical trend view).
    """

    __tablename__ = "analytics_snapshots"

    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
    )
    location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("locations.id", ondelete="SET NULL"),
        nullable=True,
    )
    snapshot_type: Mapped[str] = mapped_column(String(30), nullable=False)
    period_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    period_end: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    granularity: Mapped[str] = mapped_column(String(20), nullable=False)
    metrics: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    computation_duration_ms: Mapped[float | None] = mapped_column(Float, nullable=True)

    __table_args__ = (
        # Primary query pattern -- see docstring's indexing rationale.
        Index(
            "ix_analytics_snapshots_org_type_period_start",
            "organization_id",
            "snapshot_type",
            "period_start",
        ),
        Index("ix_analytics_snapshots_location_id", "location_id"),
        Index("ix_analytics_snapshots_snapshot_type", "snapshot_type"),
        Index("ix_analytics_snapshots_period_start", "period_start"),
        Index("ix_analytics_snapshots_period_end", "period_end"),
    )

    def __repr__(self) -> str:
        return (
            f"<AnalyticsSnapshot(snapshot_type={self.snapshot_type}, "
            f"organization_id={self.organization_id}, "
            f"location_id={self.location_id}, period_start={self.period_start})>"
        )


class ReportTemplate(BaseModel):
    """A reusable, persisted definition of *what* a report contains (BE-012
    Part 5: Report Engine + Export Engine) -- ``report_type`` (:class:`~.
    constants.ReportType`) says *which* existing analytics service(s)
    ``report_service.ReportGenerationService`` composes to fill it in, and
    ``config`` (JSONB) carries the caller's own defaults for that
    composition (a default ``location_id``, a default trailing-window size
    in days for the Router/Guest/Network report types, and whether the
    ``HEALTH`` report type's optional per-organization Router Failure Risk
    section is included) -- never a second copy of any computed metric.

    ``organization_id`` nullable, ``ondelete="SET NULL"`` -- mirrors
    ``AnalyticsSnapshot``'s own optional-scope convention (see that model's
    docstring): ``NULL`` means a platform-wide **system template** (visible
    to every GLOBAL-scoped caller), a real organization id scopes the
    template to that one organization (and whichever callers'
    ``DashboardScope`` covers it -- see ``report_service.
    ReportTemplateService`` for the exact visibility rule, composed from
    the same ``DashboardScopeResolver`` every other analytics service in
    this domain already uses).

    ## Why no separate "Manual Report" / "Dashboard Report" table

    The module brief this part implements also names "Manual Reports" and
    "Dashboard Reports" as report categories. Both are simply an on-demand,
    unscheduled *render* of a ``ReportTemplate`` (or of an ad-hoc
    ``report_type`` + params with no template at all) -- there is no
    additional state to persist for the *act* of generating one beyond what
    this table (the reusable definition) and ``audit_log_entries`` (the
    permanent record that a specific generation happened, written
    unconditionally for every generation -- see ``report_service.py``'s
    module docstring) already capture. Introducing a
    ``manual_report_runs`` table would duplicate ``audit_log_entries`` for
    no queryable benefit this domain's existing audit trail doesn't already
    provide. A **recurring** render, by contrast, genuinely needs its own
    persisted row -- *which* template, *how often*, *who* to email, *when*
    it last/next runs -- which is exactly what :class:`ScheduledReport`
    is for.
    """

    __tablename__ = "report_templates"

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
    )
    report_type: Mapped[str] = mapped_column(String(30), nullable=False)
    config: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )

    __table_args__ = (
        Index("ix_report_templates_organization_id", "organization_id"),
        Index("ix_report_templates_report_type", "report_type"),
        Index("ix_report_templates_is_active", "is_active"),
    )

    def __repr__(self) -> str:
        return (
            f"<ReportTemplate(name={self.name!r}, report_type={self.report_type}, "
            f"organization_id={self.organization_id})>"
        )


class ScheduledReport(BaseModel):
    """A recurring render of one :class:`ReportTemplate`, emailed to
    ``recipient_emails`` on ``frequency``'s cadence -- the persisted state
    ``report_tasks.run_scheduled_reports`` (the Celery Beat task, see that
    module's docstring for the exact resilience pattern) sweeps every hour
    looking for ``next_run_at <= now() AND is_active``.

    ``organization_id`` is required (not nullable) -- unlike
    ``ReportTemplate``'s own optional scope, a *schedule* always belongs to
    one real organization's own recipients/cadence even when it renders a
    platform-wide system template (``ReportTemplate.organization_id IS
    NULL``); there is no "platform-wide schedule" concept in this part's
    scope. ``ondelete="CASCADE"`` on both FKs: a deleted organization's
    schedules (and a deleted template's schedules) have no reason to
    survive their parent.

    ``last_run_status``/``last_run_at`` are ``NULL`` until this schedule's
    first run; ``last_run_status`` is one of :class:`~.constants.
    ReportRunStatus` once set. ``next_run_at`` is always populated (computed
    at creation time from ``frequency``, and recomputed after every run --
    see ``report_service.ScheduledReportService`` /
    ``report_tasks.py`` for the exact "next occurrence" arithmetic).
    """

    __tablename__ = "scheduled_reports"

    template_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("report_templates.id", ondelete="CASCADE"),
        nullable=False,
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    frequency: Mapped[str] = mapped_column(String(20), nullable=False)
    recipient_emails: Mapped[list[str]] = mapped_column(
        JSONB, default=list, nullable=False
    )
    export_format: Mapped[str] = mapped_column(String(10), nullable=False)
    next_run_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    last_run_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_run_status: Mapped[str | None] = mapped_column(String(10), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )

    __table_args__ = (
        Index("ix_scheduled_reports_template_id", "template_id"),
        Index("ix_scheduled_reports_organization_id", "organization_id"),
        # Primary query pattern for report_tasks.run_scheduled_reports's
        # "which schedules are due" sweep -- an equality-on-is_active,
        # range-on-next_run_at composite index lets Postgres satisfy it with
        # a single index scan, mirroring AnalyticsSnapshot's own
        # composite-index-for-the-primary-query-pattern rationale.
        Index("ix_scheduled_reports_is_active_next_run_at", "is_active", "next_run_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<ScheduledReport(template_id={self.template_id}, "
            f"organization_id={self.organization_id}, frequency={self.frequency})>"
        )


__all__ = ["AnalyticsSnapshot", "ReportTemplate", "ScheduledReport"]
