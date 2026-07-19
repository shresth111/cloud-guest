# BE-012: Enterprise Analytics & Reporting

**BE-012 is now complete, across five parts.** This section is a short
table of contents for the whole module; each part's own "In One Paragraph"
section below (and `FLOW.md`'s numbered §§) carries the full detail --
this is deliberately not a rewrite of any of it.

| Part | Name | What it contributed |
|---|---|---|
| 1 | Analytics Core Infrastructure | Real Celery + Celery Beat deployment, the `AnalyticsSnapshot` rollup table, the daily aggregation pipeline (`ORG_DAILY_SUMMARY`/`LOCATION_DAILY_SUMMARY`/`PLATFORM_DAILY_SUMMARY`), `GET /analytics/snapshots` + manual trigger |
| 2 | Super Admin + Organization + Location Dashboards | Three dashboard endpoints, `DashboardScope`/`DashboardScopeResolver` (reused by every later part), peak-concurrent-sessions sweep-line, Organization Health Score, dashboard-view audit throttling |
| 3 | Router + Network + Guest + Authentication Analytics | Four organization-scoped analytics endpoints composing `router_provisioning`/`wireguard`/BE-010's Guest Analytics, honest placeholders for data this codebase genuinely does not have |
| 4 | Business Analytics + Forecast/Insight/Trend Engines | Customer Growth + Plan Distribution, a real OLS linear-regression Forecast Engine, a deterministic rule-based Insight Engine, the shared Trend Engine (`trends.py`) |
| 5 | Report Engine + Export Engine | `ReportTemplate`/`ScheduledReport` persisted models, `ReportGenerationService` (composes Parts 2-4's own services into one report payload), the Export Engine (real JSON/CSV/Excel/PDF rendering, `export.py`), the hourly Beat-scheduled `run_scheduled_reports` task, full (never-throttled) report-generation auditing |

The Analytics domain (`app.domains.analytics`) is planned across five
parts. **Part 1** (Analytics Core Infrastructure) built a real Celery +
Celery Beat deployment, a real aggregation pipeline over existing guest/
router/organization/location data, and a persisted, indexed
`AnalyticsSnapshot` rollup table fast dashboards can query. **Part 2**
(Super Admin + Organization + Location Dashboards) builds three real
dashboard endpoints over that infrastructure, reading mostly from
already-computed snapshots and falling back to live aggregation only where
a snapshot doesn't cover what is needed. **Part 3** (Router + Network +
Guest + Authentication Analytics) builds four more real, organization-scoped
analytics endpoints, composing with `app.domains.router_provisioning`/
`app.domains.wireguard`/BE-010's own Guest Analytics rather than duplicating
any of them, and is honest about the handful of figures no real data source
in this codebase can back. **Part 4** adds Customer Growth + Plan
Distribution (real) alongside honestly-unavailable Revenue/Subscription/
Churn/Renewal/License-Utilization figures, a real ordinary-least-squares
linear-regression Forecast Engine (bandwidth/guest-growth/network-load
projections, a capacity threshold-crossing prediction, and a Router Failure
Risk heuristic -- explicitly not a machine-learning model), and a real,
deterministic rule-based Insight Engine (Business Insights + Operational
Recommendations) -- explicitly not an AI/LLM system, since none exists in
this codebase and none is added. **Part 5** (this update -- Report Engine +
Export Engine) is a pure composition layer over Parts 2-4's own services: it
recomputes nothing, instead assembling their already-real responses into a
`ReportPayload` and rendering that into JSON/CSV/Excel/PDF, on demand or on
an hourly Beat-checked recurring schedule.

See `FLOW.md` for every design decision in detail: §§47-56 cover Part 5
(the manual-vs-scheduled-report modeling decision, the CSV/Excel flattening
convention, the `reportlab` PDF library choice, the hourly Beat-scheduled
task's per-schedule failure-isolation pattern, the full-vs-throttled audit
reasoning, the RBAC scope-inference design `report_router.py` relies on,
and the export-routing design); §§1-12 cover Part 1 (the
async-bridge pattern, the Beat schedule's two cadences, the
Redis-vs-new-table cache decision, exactly what changed in
`check_celery_health` and why, and the per-organization failure-isolation
design); §§13-22 cover Part 2 (the peak-concurrent-sessions sweep-line
algorithm, the device/browser/OS real-capture-and-classify decision, the
Organization Health Score formula and exact weights, the Captive Portal
Usage data-source decision, honest Revenue/ARR/MRR/Country-Statistics
unavailability, `DashboardScope`'s MSP-child-rollup composition, and the
dashboard-view audit-throttling decision); §§23-34 cover Part 3
(bandwidth-from-`GuestSession`, the hotspot-sessions equivalence, the
Internet Availability proxy signal reusing monitoring's own staleness
threshold, the RADIUS success/failure exact-vs-location-proxy scoping, the
Guest Retention and Peak Bandwidth formulas, the `build_auth_method_
breakdown`/`device_breakdown_response` reuse refactor, composing with
BE-010's own Guest Analytics, the Voucher Failure honest-partial-signal
gap, every honest placeholder, and the Accept-Language capture decision);
§§35-46 cover Part 4 (the two honesty investigations this part opens with,
the Trend Engine's de-duplication of Part 2/3's own near-identical trend
code, the exact OLS linear-regression method, forecast endpoint
consolidation, the Router Failure Risk heuristic's exact signal set, the
Capacity Prediction threshold-crossing formula, every Insight Engine rule +
threshold + its home in `Settings`, Business Analytics' honest-placeholder
shape, the GLOBAL-vs-ORGANIZATION scope design, and why no migration was
needed).
See `DATABASE.md` for the `analytics_snapshots` table's full column/index
reference, Part 2's `user_agent`/Part 3's `accept_language` columns on
`guest_sessions`, Part 4's seven new read-only repository queries (no
schema change), and Part 5's two new tables (`report_templates`/
`scheduled_reports`, migration `0021_create_report_tables`).

## Part 5 In One Paragraph

Two new persisted tables (`report_templates`, `scheduled_reports`,
migration `0021_create_report_tables`) and one new API surface
(`/reports*`, RBAC-gated at `reports.read`/`export`/`manage`) that adds
**zero** new metric computation: `report_service.ReportGenerationService
.generate` maps each of eight `ReportType`s onto exactly one existing call
into `DashboardService`/`DomainAnalyticsService`/`BusinessAnalyticsService`/
`ForecastService`/`InsightService` (Parts 2-4's own services, unchanged),
wraps the result's own `.model_dump(mode="json")` into a
`report_types.ReportSection`, and hands the assembled `ReportPayload` to the
Export Engine (`export.py`) for real JSON/CSV/Excel/PDF rendering --
`openpyxl` for a real, valid `.xlsx` workbook (one `Summary` sheet plus one
sheet per genuinely tabular field found anywhere in the payload) and
`reportlab` for a real, valid PDF (headings, a metrics table, and one table
per tabular field, `platypus`-laid-out). A caller either generates a report
on demand (`POST /reports`, a template or ad-hoc params, rendered
immediately) or schedules a recurring one (`POST /reports/schedule`,
DAILY/WEEKLY/MONTHLY) that the Beat-scheduled, hourly
`report_tasks.run_scheduled_reports` task sweeps for and delivers --
generating, rendering, "sending" (via `app.domains.otp`'s existing
`EmailProviderProtocol`, reused verbatim) to every recipient, and updating
`last_run_at`/`last_run_status`/`next_run_at`, with one bad schedule never
blocking the rest of the batch (the same per-item isolation guarantee
Part 1's own daily aggregation batch established). Every single generation
-- manual or scheduled -- writes one unconditional `audit_log_entries` row
(`report_generated`), deliberately never throttled the way Part 2's own
dashboard-view auditing is.

## Part 4 In One Paragraph

Two new figures on `GET /analytics/business` are real: Customer Growth
(platform organization-count trend, from existing `AnalyticsSnapshot`
history) and Plan Distribution (a real `GROUP BY
Organization.subscription_tier`, reporting the true -- if sparse --
distribution); Revenue/Subscription Trends/Churn/Renewal/License
Utilization are honest `available: false` placeholders mirroring Part 2's
`RevenueMetricsResponse` posture. Five new Forecast Engine endpoints
(`GET /analytics/forecast/bandwidth|capacity|router-failure-risk|
guest-growth|network-load`) apply a real, pure ordinary-least-squares linear
regression (`forecast.fit_linear_trend`, ~20 lines of stdlib Python, no
`numpy`/`scipy`) to real `AnalyticsSnapshot` history for bandwidth/guest-
growth/network-load projections and a router-count capacity
threshold-crossing prediction, plus a Router Failure Risk heuristic that
flags a router "at risk" only when a real, cited signal (rising CPU/memory
slope, a high ratio of recent unhealthy health snapshots, or repeated real
`Alert` rows) fires -- explicitly documented as a heuristic risk flag, never
a fabricated failure-probability number. Two new Insight Engine endpoints
(`GET /analytics/insights/business|operational`) run a real, deterministic
rule engine (`insights.py`) -- seven rules total, each with its own
configurable threshold in `app.core.config.Settings` -- producing
human-readable findings from real comparisons against real aggregated data,
explicitly labeled as a rules-based system, not an AI/LLM (none exists in
this codebase, and per this part's own mandate, none is added). A new
`trends.py` Trend Engine consolidates what were, before this part, two
near-identical private trend-building functions in `dashboard_service.py`/
`domain_analytics_service.py` into one shared implementation, reused by
both those existing call sites and every new Part 4 caller.

## Part 3 In One Paragraph

Four new, real endpoints -- `GET /analytics/routers`, `/analytics/network`,
`/analytics/guests`, `/analytics/authentication` -- all gated identically to
Part 2's own Organization Dashboard (`RequirePermission("analytics.read",
scope=ScopeType.ORGANIZATION)` plus `DomainAnalyticsService`'s own
independent `DashboardScope.require_organization` check, the same
`DashboardScopeResolver` Part 2 built). Router Analytics reports real
CPU/RAM (current + trend vs. a trailing average), uptime, connected
clients, and per-router bandwidth/hotspot-sessions/RADIUS success derived
from `GuestSession` (never from `RouterHealthSnapshot`, which has no byte
counter), WireGuard tunnel status (composed with `WireGuardService
.compute_health_status`, never re-derived), and a documented Internet
Availability proxy signal -- disk/temperature/packet-loss/latency are
honestly unavailable (no such column has ever existed on any router health
record in this sandbox). Network Analytics adds org-wide bandwidth
totals/average speed, a Peak Bandwidth figure computed from
`AnalyticsSnapshot` history's busiest bucket, and real Top
Consumers/Locations/Routers rankings -- Top Applications is an honest
placeholder (no DPI exists). Guest Analytics composes directly with
BE-010's own `GuestAnalyticsService` (verified via a spy in the test suite)
rather than re-deriving New/Returning/Unique Guests or Top Devices/
Locations, adds a real Guest Retention formula and Repeat Visits metric,
and reuses Part 2's exact User-Agent classification for device/OS/browser
stats plus a brand-new, identically-narrow `Accept-Language` capture for
Language Statistics -- Country Statistics remains Part 2's honest
placeholder, unchanged. Authentication Analytics reports real OTP/voucher
success and login-history failure/trend/reason breakdowns -- voucher
failure is disclosed as a real but partial signal (only
revoked/exhausted-reuse attempts are durably audited), and PMS/Social Login
are honest placeholders (no PMS integration exists; social login is a
schema-only readiness flag).

## Part 2 In One Paragraph

Three new, real endpoints -- `GET /dashboard/super-admin` (GLOBAL RBAC
scope), `GET /dashboard/organization` (ORGANIZATION scope, with automatic
MSP-child rollup), `GET /dashboard/location` (LOCATION scope) -- each
gated by RBAC's `RequirePermission("analytics.read", scope=...)` *and* a
second, independent `DashboardScope` check
(`app.domains.analytics.dashboard_scope`) resolved from the caller's real,
active RBAC role assignments (composing `RoleResolver`/
`OrganizationService.list_children`/`LocationService.get_location`, never
reimplementing scope resolution). Peak concurrent sessions is computed by a
real interval sweep-line (`peak_concurrency.py`), never a coarse sampling
approximation. The Organization Health Score is a documented, weighted
heuristic (`health_score.py`) over real router-uptime/open-alert/guest-
growth signals -- never presented as more scientific than it is. Revenue/
ARR/MRR and Country Statistics are honestly `available: false` with every
numeric field `null` -- there is no billing domain and no GeoIP data source
anywhere in this codebase. Top Devices/Browsers/OS *is* real: a narrow,
additive `GuestSession.user_agent` column (captured at the two existing
guest-login endpoints) is classified into buckets via real SQL `CASE`/regex
matching at dashboard read time, a small hand-written heuristic rather than
a new parsing-library dependency.

## In One Paragraph

`app.core.celery_app` gives this codebase its first real Celery
application (broker + result backend both pointed at the same
`Settings.redis_url` this codebase already uses for everything else),
with a Beat schedule that runs
`app.domains.analytics.tasks.run_daily_aggregation_for_all_organizations`
every 15 minutes (a rolling "today so far" snapshot) and once daily at
00:10 UTC (a final "yesterday, in full" snapshot). That task iterates every
active organization, computing and persisting an `ORG_DAILY_SUMMARY`
snapshot plus one `LOCATION_DAILY_SUMMARY` snapshot per active location
(guest counts, session counts, router online/offline counts -- all real SQL
aggregate queries, composing with `app.domains.guest`'s existing
`GuestAnalyticsService` rather than re-deriving the same numbers), with one
organization's failure never aborting the batch. It then computes one
platform-wide `PLATFORM_DAILY_SUMMARY` snapshot (total organizations,
locations, routers online/offline, guests today). `AnalyticsService`
also exposes a manual `trigger_aggregation(organization_id)` method (used by
`POST /analytics/snapshots/trigger`) for on-demand recomputation, and
`GET /analytics/snapshots` reads already-computed snapshots back out,
tenant-scoped.

`app.domains.monitoring.service.MonitoringService.check_celery_health`
(BE-011 Part 1's honest `HealthStatus.UNKNOWN` placeholder, documented as
"ready to wire in once one does") is now wired in for real: it performs a
genuine `celery_app.control.inspect().ping()` round trip and reports
`HEALTHY`/`DEGRADED`/`UNHEALTHY` depending on whether a worker actually
responds -- see `FLOW.md` for the exact three-outcome mapping.

## What This Part Does NOT Do

* **It does not build any dashboard endpoint beyond the minimal
  `GET /analytics/snapshots` read path.** Per-domain/forecasting/reporting
  dashboards are later BE-012 parts' job.
* **It does not create a redundant `analytics_cache` SQL table.** Redis
  (the same TTL'd-key pattern `app.domains.rbac.cache.PermissionCache`
  already establishes) is the correct cache layer for this need -- see
  `FLOW.md` for the full write-up.
* **It does not duplicate `app.domains.router_provisioning.models
  .RouterHealthSnapshot`.** That table is a per-router, point-in-time
  metrics reading; `AnalyticsSnapshot` is a higher-level,
  organization/location/platform-scoped rollup across many routers and
  guests.
* **It does not re-implement guest/session aggregate queries.**
  `app.domains.guest.service.GuestAnalyticsService.get_summary` is reused
  directly for every guest/session count this part needs.

## What Part 5 Does NOT Do

* **It does not recompute a single metric a different way.** Every figure
  in every generated report is whatever the composed Part 2-4 service
  already returned, embedded verbatim via `.model_dump(mode="json")`.
* **It does not build a second email abstraction.** Scheduled-report
  delivery reuses `app.domains.otp.service.EmailProviderProtocol`/
  `LoggingEmailProvider` exactly as they already exist -- see `FLOW.md`'s
  Part 5 write-up for the resulting, honest attachment limitation (that
  protocol has no attachment parameter, so the notification email
  describes the generated report rather than attaching its bytes).
* **It does not add a `manual_report_runs`/`dashboard_report_runs` table.**
  A manual (on-demand) report generation is just a `ReportTemplate` render
  with no additional persisted state -- see `FLOW.md`'s manual-vs-scheduled
  modeling write-up.
* **It does not throttle report-generation auditing.** Unlike Part 2's own
  dashboard-view audit throttle, every single report generation writes an
  unconditional `audit_log_entries` row -- see `FLOW.md` for why this
  volume profile is different.
* **It does not edit `app.domains.otp`/`app.domains.rbac`/
  `app.domains.organization` internals.** `PermissionModule.REPORTS` was
  already seeded (since Part 1, in anticipation of exactly this part); no
  RBAC file is touched.

## What Part 3 Does NOT Do

* **It does not add a disk/temperature/packet-loss/latency reading for any
  router.** `RouterHealthSnapshot` has never captured any of the four, and
  none is fabricated.
* **It does not add deep packet inspection or any application-layer
  traffic classification.** "Top Applications" is honestly unavailable.
* **It does not integrate with a Property Management System or a real
  social-login/OAuth provider.** Both remain honest placeholders.
* **It does not re-implement `WireGuardService.compute_health_status`'s
  staleness-threshold arithmetic.** Router Analytics composes with the
  real method directly.
* **It does not add a `router_id` column to `GuestLoginHistory`.** RADIUS
  failure per router is an explicitly-documented location-level proxy
  instead -- see `FLOW.md` §26.
* **It does not re-derive New/Returning/Unique Guests or Top Devices/
  Locations.** `GuestAnalyticsService`'s own existing methods are composed
  directly (verified via a spy in the test suite).

## Folder Structure

```text
backend/
  alembic/
    versions/
      0018_create_analytics_tables.py
      0019_add_user_agent_to_guest_sessions.py   # Part 2: one column on guest_sessions
      0020_add_accept_language_to_guest_sessions.py  # Part 3: one more column
      0021_create_report_tables.py               # Part 5: report_templates, scheduled_reports
  app/
    core/
      celery_app.py             # the real Celery app + Beat schedule
    domains/
      analytics/
        __init__.py
        constants.py             # + Part 2/3/4/5: audit actions, growth/health-score/
                                   #   analytics-window constants, ReportType/
                                   #   ReportFrequency/ExportFormat/ReportRunStatus
        models.py                # AnalyticsSnapshot + Part 5: ReportTemplate,
                                   #   ScheduledReport
        schemas.py                # Pydantic request/response models (Part 1 endpoints)
        dashboard_schemas.py       # Part 2: dashboard response schemas
        domain_analytics_schemas.py  # Part 3: router/network/guest/auth response schemas
        business_schemas.py         # Part 4: Business Analytics response schemas
        forecast_schemas.py          # Part 4: Forecast Engine response schemas
        insight_schemas.py            # Part 4: Insight Engine response schemas
        report_schemas.py              # Part 5: ReportTemplate/ScheduledReport CRUD +
                                        #   GenerateReportRequest/ReportPayloadResponse
        report_types.py                 # Part 5: ReportPayload/ReportSection/
                                         #   TabularBlock + the flatten_scalar_fields/
                                         #   extract_tabular_blocks tree-walkers
        validators.py             # date-range validation, day_bounds_utc
                                   # + Part 5: resolve_analytics_window (shared with
                                   #   report_service.py)
        exceptions.py             # + Part 2: DashboardScopeForbiddenError
                                   # + Part 5: ReportTemplateNotFoundError/
                                   #   ScheduledReportNotFoundError/
                                   #   MissingReportParametersError/
                                   #   UnsupportedExportFormatError
        events.py
        repository.py            # AnalyticsRepositoryProtocol + AnalyticsRepository
                                   # + Part 2/3/4: dashboard + domain-analytics +
                                   #   business/forecast/insight read-model queries
        report_repository.py       # Part 5: ReportRepository/ReportRepositoryProtocol
                                    #   (ReportTemplate/ScheduledReport CRUD + the
                                    #   due-schedules sweep query)
        aggregation.py            # pure computation, testable without Celery (Part 1)
                                   # + Part 3: new_guest_count, shared with Guest Analytics
        dashboard_aggregation.py   # Part 2: growth points, snapshot summation helpers
                                   # + Part 3: retention/peak-bandwidth/avg-speed helpers,
                                   #   plus build_auth_method_breakdown/
                                   #   device_breakdown_response (moved here from
                                   #   dashboard_service.py for reuse -- see FLOW.md §29)
        trends.py                   # Part 4: the Trend Engine -- extract_metric_series/
                                     #   growth_point_response/build_growth_trend (a
                                     #   de-duplication of Part 2/3's own near-identical
                                     #   trend code, see FLOW.md §§36-37)/
                                     #   compute_snapshot_metric_growth/
                                     #   count_trailing_consecutive_increases
        forecast.py                  # Part 4: the Forecast Engine's pure math --
                                      #   fit_linear_trend (real OLS), forecast_linear_series,
                                      #   project_upward_threshold_crossing,
                                      #   assess_router_failure_risk (the heuristic, not ML)
        insights.py                   # Part 4: the Insight Engine's pure rule functions
                                       #   (Business Insights + Operational Recommendations)
        peak_concurrency.py        # Part 2: the peak-concurrent-sessions sweep-line
        router_availability.py      # Part 3: the Internet Availability proxy signal
        health_score.py            # Part 2: the Organization Health Score formula
        dashboard_scope.py          # Part 2: DashboardScope + DashboardScopeResolver
                                     #   (reused as-is by Part 3/4)
        dashboard_audit.py           # Part 2: dashboard-view audit throttling
                                      #   (reused as-is by Part 3/4)
        service.py                 # AnalyticsService: persist + batch pipeline (Part 1)
        dashboard_service.py        # Part 2: DashboardService (the 3 dashboards)
                                     #   + Part 4: refactored to compose trends.py
        domain_analytics_service.py  # Part 3: DomainAnalyticsService (the 4 endpoints)
                                      #   + Part 4: refactored to compose trends.py
        business_service.py           # Part 4: BusinessAnalyticsService
        forecast_service.py            # Part 4: ForecastService
        insight_service.py              # Part 4: InsightService
        report_service.py                # Part 5: ReportGenerationService (composition
                                          #   over the five services above) +
                                          #   ReportTemplateService/ScheduledReportService
                                          #   (CRUD) + compute_next_run_at
        export.py                          # Part 5: the Export Engine -- render_report,
                                            #   one function per JSON/CSV/Excel/PDF format
        tasks.py                   # thin Celery task wrappers (the async bridge)
        report_tasks.py              # Part 5: run_scheduled_reports (hourly Beat task)
                                      #   + run_scheduled_report_batch (the testable,
                                      #   fake-repository per-schedule isolation loop)
        dependencies.py             # + Part 3: get_domain_analytics_service
                                     # + Part 4: get_business_analytics_service/
                                     #   get_forecast_service/get_insight_service
                                     # + Part 5: get_report_generation_service/
                                     #   get_report_template_service/
                                     #   get_scheduled_report_service
        router.py                  # GET /analytics/snapshots, POST .../trigger,
                                   # + Part 2: GET /dashboard/super-admin|organization|location
                                   # + Part 3: GET /analytics/routers|network|guests|authentication
                                   # + Part 4: GET /analytics/business,
                                   #   /analytics/forecast/bandwidth|capacity|
                                   #   router-failure-risk|guest-growth|network-load,
                                   #   /analytics/insights/business|operational
                                   # + Part 5: router.include_router(report_router)
        report_router.py            # Part 5: /reports*, all ten endpoints -- own module
                                     #   docstring covers the RBAC scope-inference design
      guest/
        models.py                # + Part 2: GuestSession.user_agent
                                   # + Part 3: GuestSession.accept_language
        router.py                 # + Part 2/3: capture User-Agent/Accept-Language at
                                   #   the two login endpoints
        service.py                 # + Part 2/3: thread user_agent/accept_language
                                   #   through session creation
    core/
      config.py                  # + Part 4: 22 new Settings fields (every Forecast/
                                   #   Insight Engine threshold -- see FLOW.md §42)
      celery_app.py               # + Part 5: reports-run-scheduled Beat entry (hourly)
  docs/
    analytics/
      README.md                    # this file
      FLOW.md
      DATABASE.md
  tests/
    unit/
      test_analytics.py
      test_analytics_router_network_guest_auth.py  # Part 3
      test_analytics_dashboards.py  # Part 2
      test_analytics_forecast_insights.py  # Part 4
      test_analytics_reports.py  # Part 5
```

## Running a Worker + Beat Locally (for real, once Redis is up)

```bash
# Worker (processes tasks)
celery -A app.core.celery_app worker --loglevel=info

# Beat (schedules the three periodic tasks documented in FLOW.md --
# the two Part 1 aggregation ticks, plus Part 5's hourly
# reports-run-scheduled)
celery -A app.core.celery_app beat --loglevel=info
```

Neither process is started by `app.main.create_app()` or by the test
suite -- this codebase's own health check
(`GET /api/v1/monitoring/health` -> `celery` component) honestly reports
`DEGRADED`/`UNHEALTHY` when neither is running, exactly as designed (see
`FLOW.md`).
