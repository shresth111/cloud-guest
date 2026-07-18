# BE-011 Part 1: Monitoring (Health Engine + Event Engine)

The Monitoring domain (`app.domains.monitoring`) is the first module of
BE-011 (monitoring/alerting). It is deliberately **platform-wide /
cross-domain** -- database/Redis/API/auth/storage health, an honestly
`UNKNOWN` Celery/WebSocket placeholder, FreeRADIUS/WireGuard proxy signals,
and a unified cross-domain event timeline. It never duplicates BE-008's
`Router.health_status`/`last_seen_at` or BE-009's
`RouterHealthSnapshot`/`RouterEvent` -- those stay the single source of
truth for per-router health/history; this module composes with them (or,
for `RouterEvent`, reads them directly for the unified timeline) rather than
re-modeling them.

See `FLOW.md` for every design decision in detail (the `DeviceHealth`
composition-vs-new-table call, `HeartbeatLog`'s relationship to
`router_agent`'s existing heartbeat, the `PlatformEvent`
composition-vs-new-storage call, the honest Celery/WebSocket treatment, and
why FreeRADIUS/WireGuard health are proxy signals). See `DATABASE.md` for
the four new tables.

## Health Engine + Event Engine, In One Paragraph

`MonitoringService.run_all_health_checks` executes nine real (or honestly
non-fabricated) checks -- `database` (real `SELECT 1`), `redis` (real
`PING`), `api` (tautological but useful liveness), `auth` (a real, narrow
call through `AuthRepository`), `storage` (real `shutil.disk_usage` against
`Settings.log_dir`), `celery`/`websocket` (honest `UNKNOWN`, no such
infrastructure exists), `freeradius`/`wireguard` (DB-tracked proxy signals
composing with `app.domains.guest`/`app.domains.wireguard`) -- persists a
`HealthCheck` row and updates a `ServiceHealth` rollup (with
`consecutive_failure_count` tracking) for each, and writes a narrowly-scoped
`PlatformEvent` row whenever a component's status genuinely *transitions*.
`MonitoringService.get_event_timeline` is a read-side aggregation across
that `PlatformEvent` table plus RBAC's `audit_log_entries` and
`router_provisioning`'s `RouterEvent` -- a unified, chronologically-sorted
view with zero duplicate storage.

## What This Module Does NOT Do

* **It does not fabricate Celery/WebSocket health.** No Celery
  worker/broker and no WebSocket support exist anywhere in this codebase --
  `check_celery_health`/`check_websocket_health` return an honest
  `HealthStatus.UNKNOWN` with a documented reason, never `HEALTHY`.
* **It does not ping a real FreeRADIUS daemon or run a live `wg show`.**
  Both are DB-tracked proxy signals composing with existing tables/services
  -- see `FLOW.md` §4/§5.
* **It does not duplicate per-router health/history.** No `DeviceHealth`
  table exists -- `app.domains.router`/`app.domains.router_provisioning`
  already model everything a per-router rollup needs. See `FLOW.md` §1.
* **It does not duplicate RBAC's `audit_log_entries` or
  `router_provisioning`'s `RouterEvent`.** `PlatformEvent` is narrowly
  scoped to this module's own health-transition detections; the unified
  timeline reads the other two tables directly. See `FLOW.md` §3.

## Folder Structure

```text
backend/
  alembic/
    versions/
      0016_create_monitoring_tables.py
  app/
    domains/
      monitoring/
        __init__.py
        constants.py       # HealthComponent, HealthStatus, EventCategory/Severity, ...
        models.py           # HealthCheck, ServiceHealth, HeartbeatLog, PlatformEvent
        exceptions.py         # MonitoringError subclasses (CloudGuestError)
        events.py              # Plain dataclasses, logged synchronously by service.py
        validators.py            # Pure date-range + storage-threshold classification
        repository.py             # MonitoringRepositoryProtocol + repo (incl. cross-domain reads)
        service.py                 # MonitoringService: Health Engine + Event Engine
        schemas.py                  # Pydantic request/response DTOs
        dependencies.py               # FastAPI dependency wiring
        router.py                     # /monitoring/health*, /events
      router_agent/
        router.py                    # additive HeartbeatLog hook in agent_heartbeat
    api/
      v1/
        router.py                    # monitoring router registered
  docs/
    monitoring/
      README.md
      FLOW.md
      DATABASE.md
  tests/
    unit/
      test_monitoring.py
```

## API Surface

All RBAC-gated by `monitoring.*` -- there is no dedicated "events"
permission module, see `FLOW.md` §6 for the reuse decision.

```text
GET  /api/v1/monitoring/health              monitoring.read     dashboard summary + per-component rollup
GET  /api/v1/monitoring/health/{component}  monitoring.read      one component's HealthCheck history (paginated)
POST /api/v1/monitoring/health/run          monitoring.manage    on-demand health-check run (admin-gated)
GET  /api/v1/events                         monitoring.read      unified event timeline (category/severity/org/date filters)
```

## Reused, Not Duplicated

* `app.database.session`/`app.database.redis` -- the real `AsyncSession`/
  Redis client, for real `database`/`redis` checks.
* `app.domains.auth.repository.AuthRepository` -- for the real (if narrow)
  `auth` check.
* `app.domains.wireguard.service.WireGuardService.compute_health_status` --
  reused directly for the `wireguard` proxy signal, never reimplemented.
* `app.domains.guest.models.RadiusNasClient`/`GuestSession` -- read
  directly (no code changes to `guest`) for the `freeradius` proxy signal.
* `app.domains.rbac.models.AuditLogEntry`/`app.domains.router_provisioning
  .models.RouterEvent` -- read directly (no code changes to either domain)
  for the unified event timeline.
* RBAC's already-seeded `monitoring.read`/`monitoring.view`/
  `monitoring.manage` permission keys, reused for both health and event
  endpoints.
* `GenericRepository` (Module 002), `ApiResponse`/`build_response`
  (Module 001), `CloudGuestError` (Module 001).

## New, Not Reused (Genuine Additions)

* `HealthCheck`/`ServiceHealth`/`HeartbeatLog` -- genuinely new,
  platform-wide tables; nothing elsewhere models cross-component health
  history/rollup or a cross-domain heartbeat log.
* `PlatformEvent` -- a genuinely new but **narrowly-scoped** table: only
  this module's own health-transition detections. See `FLOW.md` §3 for
  why this is not a duplicate of existing event tables.
* One small, additive hook in `app.domains.router_agent.router
  .agent_heartbeat` writing a `HeartbeatLog` row alongside its existing
  `Router.last_seen_at` update -- see `FLOW.md` §2.

## Testing

`tests/unit/test_monitoring.py` exercises `MonitoringService` against a
small, hand-rolled in-memory fake repository and fakes for every composed
cross-domain dependency (auth repository, Redis client, WireGuard service)
-- there is no live Postgres/Redis in this environment. Coverage: every
real health check's success and simulated-failure path (database, redis,
auth, storage), the API check's trivial-but-uniform healthy result, the
Celery/WebSocket honest-`UNKNOWN`-not-`HEALTHY` behavior, the FreeRADIUS/
WireGuard proxy signals (no data / healthy / degraded / unhealthy, and
revoked-peer exclusion), `ServiceHealth` rollup creation plus
`consecutive_failure_count` increment-then-reset-on-recovery, status-
transition `PlatformEvent` writes (unhealthy/degraded/recovered, and no
duplicate event on repeated identical failures), dashboard aggregate-status
logic (never-run, all-healthy-excluding-permanently-unknown, one-degraded,
one-unhealthy, unhealthy-takes-priority-over-degraded), heartbeat
recording, and the event timeline's cross-source aggregation/sorting/
category-filtering/date-range validation. All 482 previously-passing tests
continue to pass unmodified, plus 42 new tests here (524 total).
