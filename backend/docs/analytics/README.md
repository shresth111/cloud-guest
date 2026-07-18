# BE-012 Part 1: Analytics Core Infrastructure

The Analytics domain (`app.domains.analytics`) is the first of five planned
parts for BE-012 (Enterprise Analytics & Reporting). This part builds the
**core infrastructure only**: a real Celery + Celery Beat deployment, a
real aggregation pipeline over existing guest/router/organization/location
data, and a persisted, indexed `AnalyticsSnapshot` rollup table fast
dashboards can query. Later parts (not built here) are: per-domain
dashboards, per-domain analytics, forecasting, and reporting/export.

See `FLOW.md` for every design decision in detail (the async-bridge
pattern, the Beat schedule's two cadences, the Redis-vs-new-table cache
decision, exactly what changed in `check_celery_health` and why, and the
per-organization failure-isolation design). See `DATABASE.md` for the one
new table's full column/index reference.

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
  app/
    core/
      celery_app.py             # the real Celery app + Beat schedule
    domains/
      analytics/
        __init__.py
        constants.py             # AnalyticsSnapshotType, AnalyticsGranularity
        models.py                # AnalyticsSnapshot
        schemas.py                # Pydantic request/response models
        validators.py             # date-range validation, day_bounds_utc
        exceptions.py
        events.py
        repository.py            # AnalyticsRepositoryProtocol + AnalyticsRepository
        aggregation.py            # pure computation, testable without Celery
        service.py                 # AnalyticsService: persist + batch pipeline
        tasks.py                   # thin Celery task wrappers (the async bridge)
        dependencies.py
        router.py                  # GET /analytics/snapshots, POST .../trigger
  docs/
    analytics/
      README.md                    # this file
      FLOW.md
      DATABASE.md
  tests/
    unit/
      test_analytics.py
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
