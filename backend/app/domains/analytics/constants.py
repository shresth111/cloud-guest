"""Enumerations and small constants for the Analytics domain (BE-012 Part 1:
Analytics Core Infrastructure).

Stored as plain ``String`` columns on the ORM model (mirroring every other
domain's own convention -- e.g. ``app.domains.monitoring.constants``) rather
than native PostgreSQL enum types, so adding a new snapshot type in a later
BE-012 part never requires an ``ALTER TYPE`` migration.
"""

from __future__ import annotations

from enum import StrEnum


class AnalyticsSnapshotType(StrEnum):
    """The kind of rollup a :class:`~.models.AnalyticsSnapshot` row
    represents.

    This part deliberately seeds a small, real set that this part actually
    populates -- ``ORG_DAILY_SUMMARY``/``LOCATION_DAILY_SUMMARY``/
    ``PLATFORM_DAILY_SUMMARY`` -- rather than pre-enumerating every future
    dashboard's snapshot type (per-domain analytics, forecasting, and
    reporting/export snapshot types are later BE-012 parts' job to add,
    additively, to this same enum). See ``models.AnalyticsSnapshot``'s
    docstring for the exact ``metrics`` JSONB schema per type.

    * ``ORG_DAILY_SUMMARY`` -- one organization's guest/session/router
      rollup for one day. ``organization_id`` populated, ``location_id``
      ``NULL``.
    * ``LOCATION_DAILY_SUMMARY`` -- the same shape, scoped to one location.
      Both ``organization_id`` (the location's owning organization) and
      ``location_id`` populated.
    * ``PLATFORM_DAILY_SUMMARY`` -- platform-wide totals across every
      organization/location/router. Both ``organization_id`` and
      ``location_id`` ``NULL`` (the "platform-wide" convention this
      domain's own ``AnalyticsSnapshot.organization_id``/``location_id``
      docstring establishes).
    """

    ORG_DAILY_SUMMARY = "org_daily_summary"
    LOCATION_DAILY_SUMMARY = "location_daily_summary"
    PLATFORM_DAILY_SUMMARY = "platform_daily_summary"


class AnalyticsGranularity(StrEnum):
    """The time-bucket width a snapshot's ``[period_start, period_end]``
    window represents. This part only ever populates ``DAILY`` rows (see
    ``AnalyticsSnapshotType``'s docstring) -- ``HOURLY``/``WEEKLY``/
    ``MONTHLY`` are defined now, ready for a later part's rollup without a
    migration, the same "defined, not yet produced" posture
    ``app.domains.monitoring.constants.HeartbeatComponentType.WIREGUARD_PEER``
    already establishes for an enum member with no current writer.
    """

    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


DEFAULT_LIST_PAGE = 1
DEFAULT_LIST_PAGE_SIZE = 25

# Celery task names -- kept as constants (rather than re-deriving the string
# in more than one place) so `app.core.celery_app`'s `beat_schedule` and
# `app.domains.analytics.tasks`'s `@celery_app.task(name=...)` decorators
# can never silently drift apart.
TASK_RUN_DAILY_AGGREGATION_FOR_ALL_ORGANIZATIONS = (
    "app.domains.analytics.tasks.run_daily_aggregation_for_all_organizations"
)
TASK_RUN_DAILY_AGGREGATION_FOR_ORGANIZATION = (
    "app.domains.analytics.tasks.run_daily_aggregation_for_organization"
)


# ============================================================================
# BE-012 Part 2: Super Admin + Organization + Location Dashboards
# ============================================================================

# How many days back "growth" trend comparisons look for a prior period of
# equal length (day-over-day at 1, but every dashboard's default trend
# window uses this) -- see ``dashboard_aggregation.compute_growth``.
DEFAULT_GROWTH_LOOKBACK_DAYS = 7

# How many days of daily LOCATION_DAILY_SUMMARY snapshots "weekly"/"monthly"
# visitor counts sum across -- see ``dashboard_aggregation
# .sum_metric_across_snapshots``.
WEEKLY_WINDOW_DAYS = 7
MONTHLY_WINDOW_DAYS = 30

# How far back "open alerts" are considered for the Organization Health
# Score's alert component -- see ``health_score.py``. An alert that has been
# open for a very long time still counts (there is no age-decay in this
# heuristic, see that module's docstring), but this bounds the query itself
# to a sane recent window rather than scanning a tenant's entire alert
# history on every dashboard read.
HEALTH_SCORE_ALERT_LOOKBACK_DAYS = 30

# ``audit_log_entries.action`` values this domain writes -- kept as local,
# plain string constants (not added to ``app.domains.rbac.enums.AuditAction``)
# because this part's directory rule scopes changes to
# ``app.domains.analytics`` only; ``AuditLogEntry.action`` is a plain,
# unconstrained ``String(50)`` column (see
# ``app.domains.rbac.models.AuditLogEntry``), so a value that is not also a
# member of RBAC's own enum works identically for storage/querying -- it is
# simply not registered in that shared, cross-domain registry. See
# ``docs/analytics/FLOW.md`` for the full write-up of this scoping decision.
AUDIT_ACTION_DASHBOARD_SUPER_ADMIN_VIEWED = "dashboard_super_admin_viewed"
AUDIT_ACTION_DASHBOARD_ORGANIZATION_VIEWED = "dashboard_organization_viewed"
AUDIT_ACTION_DASHBOARD_LOCATION_VIEWED = "dashboard_location_viewed"

# Dashboard-view audit throttling: see ``dashboard_audit.py`` for the full
# volume-tiering write-up (mirrors OTP/Voucher's own audit-volume judgment
# calls). A dashboard view is always logged via the structured logger; it is
# only written into the moderate-volume ``audit_log_entries`` table once per
# this many minutes, per (user, dashboard kind, scope).
DASHBOARD_AUDIT_THROTTLE_MINUTES = 15
DASHBOARD_AUDIT_THROTTLE_KEY_TEMPLATE = "dashboard_audit_throttle:{key}"

# ============================================================================
# BE-012 Part 3: Router + Network + Guest + Authentication Analytics
# ============================================================================

# Default trailing window (days) applied to every Part 3 analytics endpoint
# when the caller omits explicit ``start_date``/``end_date`` query params --
# reuses the exact same "30 days" figure ``MONTHLY_WINDOW_DAYS`` already
# establishes elsewhere in this domain, kept as its own named constant here
# since it plays a different role (an HTTP query-param default, not a
# snapshot-summation window).
DEFAULT_ANALYTICS_WINDOW_DAYS = MONTHLY_WINDOW_DAYS

# How many days of ``RouterHealthSnapshot`` history feed the "average"
# baseline a router's current CPU/RAM reading is compared against to derive
# a trend direction (see ``domain_analytics_service.py``'s Router Analytics
# docstring for the exact formula: current reading vs. this window's own
# average, via ``dashboard_aggregation.compute_growth``).
ROUTER_HEALTH_TREND_WINDOW_DAYS = 7

# Default/maximum "top N" size for Network Analytics' Top Consumers/
# Locations/Routers and Guest Analytics' Top Devices/Locations.
TOP_N_DEFAULT = 10
TOP_N_MAX = 50

# ``audit_log_entries.action`` values this part's four new endpoints write --
# same local-string-constant posture as Part 2's own dashboard-view actions
# above (see that block's own docstring for why these are not added to
# ``app.domains.rbac.enums.AuditAction``).
AUDIT_ACTION_ROUTER_ANALYTICS_VIEWED = "router_analytics_viewed"
AUDIT_ACTION_NETWORK_ANALYTICS_VIEWED = "network_analytics_viewed"
AUDIT_ACTION_GUEST_ANALYTICS_VIEWED = "guest_analytics_viewed"
AUDIT_ACTION_AUTHENTICATION_ANALYTICS_VIEWED = "authentication_analytics_viewed"

# ============================================================================
# BE-012 Part 4: Business Analytics + Forecast/Insight Engines
# ============================================================================

# ``audit_log_entries.action`` values this part's new endpoints write --
# same local-string-constant posture as Part 2/3's own dashboard-view
# actions above (see that block's own docstring for why these are not added
# to ``app.domains.rbac.enums.AuditAction``).
AUDIT_ACTION_BUSINESS_ANALYTICS_VIEWED = "business_analytics_viewed"
AUDIT_ACTION_FORECAST_VIEWED = "forecast_viewed"
AUDIT_ACTION_BUSINESS_INSIGHTS_VIEWED = "business_insights_viewed"
AUDIT_ACTION_OPERATIONAL_RECOMMENDATIONS_VIEWED = "operational_recommendations_viewed"

# ============================================================================
# BE-012 Part 5: Report Engine + Export Engine
# ============================================================================


class ReportType(StrEnum):
    """Which of this domain's existing analytics services one
    :class:`~.models.ReportTemplate`/generated report composes -- see
    ``report_service.ReportGenerationService.generate``'s own docstring for
    the exact section(s) each value assembles. Every value reuses an
    already-built Part 2/3/4 service; none recomputes a metric a different
    way.

    * ``DASHBOARD`` -- the platform-wide Super Admin Dashboard
      (``DashboardService.get_super_admin_dashboard``).
    * ``ORGANIZATION`` -- one organization's dashboard
      (``DashboardService.get_organization_dashboard``).
    * ``LOCATION`` -- one location's dashboard
      (``DashboardService.get_location_dashboard``).
    * ``ROUTER`` -- Part 3's Router Analytics
      (``DomainAnalyticsService.get_router_analytics``).
    * ``GUEST`` -- Part 3's Guest Analytics
      (``DomainAnalyticsService.get_guest_analytics``).
    * ``NETWORK`` -- Part 3's Network Analytics
      (``DomainAnalyticsService.get_network_analytics``).
    * ``REVENUE`` -- Part 4's Business Analytics
      (``BusinessAnalyticsService.get_business_analytics``) -- reuses that
      part's honest Revenue/Subscription/Churn/Renewal/License-Utilization
      placeholders verbatim; this part fabricates no new figures for them.
    * ``HEALTH`` -- Part 4's rule-based Insight Engine, both Business
      Insights and Operational Recommendations
      (``InsightService.get_business_insights``/
      ``get_operational_recommendations``), plus -- when an
      ``organization_id`` is supplied -- that organization's Router Failure
      Risk (``ForecastService.get_router_failure_risk``). See
      ``report_service.py``'s module docstring for why this is the
      "platform/organization health" composition rather than re-deriving
      ``dashboard_service.py``'s own ``HealthScoreResponse`` (already
      included whenever ``report_type=ORGANIZATION`` is generated).
    """

    DASHBOARD = "dashboard"
    ORGANIZATION = "organization"
    LOCATION = "location"
    ROUTER = "router"
    GUEST = "guest"
    NETWORK = "network"
    REVENUE = "revenue"
    HEALTH = "health"


class ReportFrequency(StrEnum):
    """How often a :class:`~.models.ScheduledReport` recurs. Mirrors
    ``AnalyticsGranularity``'s plain-``String``-column posture (see that
    enum's own docstring) -- adding a new cadence later never needs an
    ``ALTER TYPE`` migration."""

    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


class ExportFormat(StrEnum):
    """Every format ``export.py`` can render a
    :class:`~.report_service.ReportPayload` into. ``JSON`` is the also the
    standard ``ApiResponse`` envelope's own native shape (see
    ``export.py``'s module docstring)."""

    PDF = "pdf"
    CSV = "csv"
    EXCEL = "excel"
    JSON = "json"


class ReportRunStatus(StrEnum):
    """The outcome of a :class:`~.models.ScheduledReport`'s most recent
    Beat-scheduled run (``report_tasks.run_scheduled_reports``)."""

    SUCCESS = "success"
    FAILED = "failed"


# Celery task name -- same "kept as a constant, never re-derived" posture as
# ``TASK_RUN_DAILY_AGGREGATION_FOR_ALL_ORGANIZATIONS`` above, so
# ``app.core.celery_app``'s ``beat_schedule`` and ``report_tasks.py``'s
# ``@celery_app.task(name=...)`` decorator can never silently drift apart.
TASK_RUN_SCHEDULED_REPORTS = "app.domains.analytics.report_tasks.run_scheduled_reports"

# How often the Beat schedule checks for due ``ScheduledReport`` rows -- see
# ``report_tasks.py``'s module docstring for why hourly (rather than
# ``analytics-rolling-today``'s 15-minute cadence) is the right granularity
# for a task whose own coarsest supported frequency is ``DAILY``.
SCHEDULED_REPORTS_CHECK_INTERVAL_SECONDS = 3600.0

# ``audit_log_entries.action`` value written for **every** report generated
# (manual or scheduled) -- see ``report_service.py``'s module docstring for
# why this one is never throttled (contrast with Part 2's
# ``DASHBOARD_AUDIT_THROTTLE_MINUTES``-gated dashboard-view auditing above).
AUDIT_ACTION_REPORT_GENERATED = "report_generated"
AUDIT_ACTION_REPORT_TEMPLATE_CREATED = "report_template_created"
AUDIT_ACTION_REPORT_TEMPLATE_UPDATED = "report_template_updated"
AUDIT_ACTION_REPORT_TEMPLATE_DELETED = "report_template_deleted"
AUDIT_ACTION_SCHEDULED_REPORT_CREATED = "scheduled_report_created"
AUDIT_ACTION_SCHEDULED_REPORT_UPDATED = "scheduled_report_updated"
AUDIT_ACTION_SCHEDULED_REPORT_DELETED = "scheduled_report_deleted"

__all__ = [
    "AnalyticsSnapshotType",
    "AnalyticsGranularity",
    "DEFAULT_LIST_PAGE",
    "DEFAULT_LIST_PAGE_SIZE",
    "TASK_RUN_DAILY_AGGREGATION_FOR_ALL_ORGANIZATIONS",
    "TASK_RUN_DAILY_AGGREGATION_FOR_ORGANIZATION",
    "DEFAULT_GROWTH_LOOKBACK_DAYS",
    "WEEKLY_WINDOW_DAYS",
    "MONTHLY_WINDOW_DAYS",
    "HEALTH_SCORE_ALERT_LOOKBACK_DAYS",
    "AUDIT_ACTION_DASHBOARD_SUPER_ADMIN_VIEWED",
    "AUDIT_ACTION_DASHBOARD_ORGANIZATION_VIEWED",
    "AUDIT_ACTION_DASHBOARD_LOCATION_VIEWED",
    "DASHBOARD_AUDIT_THROTTLE_MINUTES",
    "DASHBOARD_AUDIT_THROTTLE_KEY_TEMPLATE",
    "DEFAULT_ANALYTICS_WINDOW_DAYS",
    "ROUTER_HEALTH_TREND_WINDOW_DAYS",
    "TOP_N_DEFAULT",
    "TOP_N_MAX",
    "AUDIT_ACTION_ROUTER_ANALYTICS_VIEWED",
    "AUDIT_ACTION_NETWORK_ANALYTICS_VIEWED",
    "AUDIT_ACTION_GUEST_ANALYTICS_VIEWED",
    "AUDIT_ACTION_AUTHENTICATION_ANALYTICS_VIEWED",
    "AUDIT_ACTION_BUSINESS_ANALYTICS_VIEWED",
    "AUDIT_ACTION_FORECAST_VIEWED",
    "AUDIT_ACTION_BUSINESS_INSIGHTS_VIEWED",
    "AUDIT_ACTION_OPERATIONAL_RECOMMENDATIONS_VIEWED",
    "ReportType",
    "ReportFrequency",
    "ExportFormat",
    "ReportRunStatus",
    "TASK_RUN_SCHEDULED_REPORTS",
    "SCHEDULED_REPORTS_CHECK_INTERVAL_SECONDS",
    "AUDIT_ACTION_REPORT_GENERATED",
    "AUDIT_ACTION_REPORT_TEMPLATE_CREATED",
    "AUDIT_ACTION_REPORT_TEMPLATE_UPDATED",
    "AUDIT_ACTION_REPORT_TEMPLATE_DELETED",
    "AUDIT_ACTION_SCHEDULED_REPORT_CREATED",
    "AUDIT_ACTION_SCHEDULED_REPORT_UPDATED",
    "AUDIT_ACTION_SCHEDULED_REPORT_DELETED",
]
