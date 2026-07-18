# BE-012: Enterprise Analytics & Reporting

The Analytics domain (`app.domains.analytics`) is planned across five
parts. **Part 1** (Analytics Core Infrastructure) built a real Celery +
Celery Beat deployment, a real aggregation pipeline over existing guest/
router/organization/location data, and a persisted, indexed
`AnalyticsSnapshot` rollup table fast dashboards can query. **Part 2**
(this update -- Super Admin + Organization + Location Dashboards) builds
three real dashboard endpoints over that infrastructure, reading mostly
from already-computed snapshots and falling back to live aggregation only
where a snapshot doesn't cover what is needed. Later parts (not built
here): per-domain analytics, forecasting, and reporting/export.

See `FLOW.md` for every design decision in detail: §§1-12 cover Part 1 (the
async-bridge pattern, the Beat schedule's two cadences, the
Redis-vs-new-table cache decision, exactly what changed in
`check_celery_health` and why, and the per-organization failure-isolation
design); §§13-22 cover Part 2 (the peak-concurrent-sessions sweep-line
algorithm, the device/browser/OS real-capture-and-classify decision, the
Organization Health Score formula and exact weights, the Captive Portal
Usage data-source decision, honest Revenue/ARR/MRR/Country-Statistics
unavailability, `DashboardScope`'s MSP-child-rollup composition, and the
dashboard-view audit-throttling decision). See `DATABASE.md` for the
`analytics_snapshots` table's full column/index reference plus Part 2's one
narrow, additive column on `guest_sessions`.

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

## Folder Structure

```text
backend/
  alembic/
    versions/
      0018_create_analytics_tables.py
      0019_add_user_agent_to_guest_sessions.py   # Part 2: one column on guest_sessions
  app/
    core/
      celery_app.py             # the real Celery app + Beat schedule
    domains/
      analytics/
        __init__.py
        constants.py             # + Part 2: audit actions, growth/health-score windows
        models.py                # AnalyticsSnapshot
        schemas.py                # Pydantic request/response models (Part 1 endpoints)
        dashboard_schemas.py       # Part 2: dashboard response schemas
        validators.py             # date-range validation, day_bounds_utc
        exceptions.py             # + Part 2: DashboardScopeForbiddenError
        events.py
        repository.py            # AnalyticsRepositoryProtocol + AnalyticsRepository
                                   # + Part 2: dashboard read-model queries
        aggregation.py            # pure computation, testable without Celery (Part 1)
        dashboard_aggregation.py   # Part 2: growth points, snapshot summation helpers
        peak_concurrency.py        # Part 2: the peak-concurrent-sessions sweep-line
        health_score.py            # Part 2: the Organization Health Score formula
        dashboard_scope.py          # Part 2: DashboardScope + DashboardScopeResolver
        dashboard_audit.py           # Part 2: dashboard-view audit throttling
        service.py                 # AnalyticsService: persist + batch pipeline (Part 1)
        dashboard_service.py        # Part 2: DashboardService (the 3 dashboards)
        tasks.py                   # thin Celery task wrappers (the async bridge)
        dependencies.py
        router.py                  # GET /analytics/snapshots, POST .../trigger,
                                   # + Part 2: GET /dashboard/super-admin|organization|location
      guest/
        models.py                # + Part 2: GuestSession.user_agent (one column)
        router.py                 # + Part 2: capture User-Agent at the two login endpoints
        service.py                 # + Part 2: thread user_agent through session creation
  docs/
    analytics/
      README.md                    # this file
      FLOW.md
      DATABASE.md
  tests/
    unit/
      test_analytics.py
      test_analytics_dashboards.py  # Part 2
```

## Running a Worker + Beat Locally (for real, once Redis is up)

```bash
# Worker (processes tasks)
celery -A app.core.celery_app worker --loglevel=info

# Beat (schedules the two periodic tasks documented in FLOW.md)
celery -A app.core.celery_app beat --loglevel=info
```

Neither process is started by `app.main.create_app()` or by the test
suite -- this codebase's own health check
(`GET /api/v1/monitoring/health` -> `celery` component) honestly reports
`DEGRADED`/`UNHEALTHY` when neither is running, exactly as designed (see
`FLOW.md`).
