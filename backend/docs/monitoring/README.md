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

---

# BE-011 Part 2: Alert Engine + Notification Engine + Incident Engine + SLA Monitoring

Extends this same module (no new top-level domain) with four more
sub-engines, all composing with Part 1's Health/Event Engine and other
domains' already-existing data rather than duplicating any of it. See
`FLOW.md` §10-17 for every design decision in detail (the alert
de-duplication key + recovery design, threshold rules composing with
`RouterHealthSnapshot`, health-status-change rules watching either a
platform component or per-router health, the Notification Engine's
composition-vs-real-HTTP-vs-honest-placeholder split, the Incident Engine's
fully-manual grouping decision, the SLA formula, and the RBAC
permission-key-reuse decisions) and `DATABASE.md` for the nine new tables.

## The Four Sub-Engines, In One Paragraph Each

**Alert Engine** (`models.AlertRule`/`Alert`, `service.AlertService`):
`AlertRule` watches one of three conditions
(`constants.AlertTriggerType.HEALTH_STATUS_CHANGE`/`THRESHOLD`/
`EVENT_OCCURRED`) against Part 1's `ServiceHealth`, `app.domains.router`'s
`Router.health_status`, `app.domains.router_provisioning`'s
`RouterHealthSnapshot`, or this module's own `PlatformEvent` table (in that
order, per trigger type). `AlertService.evaluate_alert_rules` re-checks
every active rule against current state on each call, creates a new
`Alert` only if the condition is met and no open `Alert` already exists for
the exact same rule+target (de-duplication), auto-resolves any open `Alert`
whose condition has since cleared (recovery -- no paired "recovery rule"),
and dispatches notifications through every `NotificationChannel` the rule
is wired to.

**Notification Engine** (`models.NotificationChannel`/`NotificationLog`,
`service.NotificationService` + `*Notifier` classes):
`dispatch_notification` picks the right `Notifier` by `channel_type` --
`EmailNotifier`/`SmsNotifier` wrap `app.domains.otp`'s existing provider
protocols; `SlackNotifier`/`TeamsNotifier`/`DiscordNotifier`/
`WebhookNotifier` make REAL `httpx.AsyncClient` POSTs using each
platform's real payload convention; `WhatsAppNotifier` is an honest
logging-only placeholder (no real WhatsApp Business API integration exists
or should be attempted) -- always records a `NotificationLog` row
(`sent`/`failed`), **never** raises, so one bad channel can never crash
alert evaluation.

**Incident Engine** (`models.Incident`/`IncidentAlert`,
`service.IncidentService`): a fully-manual grouping of related `Alert`
rows -- an operator creates an `Incident` and explicitly attaches the
alerts they judge related. No auto-correlation heuristic (deliberately --
see `FLOW.md` §14).

**SLA Monitoring** (`models.SlaTarget`/`SlaReport`, `service.SlaService`):
`generate_report` computes `achieved_percentage = healthy_checks /
total_checks * 100` over a target's window by scanning Part 1's own
`health_checks` table with real SQL aggregates, plus
`average_response_time_ms` from the same rows and, read-only, an average
provisioning duration from `app.domains.router_provisioning`'s
`ProvisioningJob` timestamps.

## Folder Structure (Part 2 additions)

No new files -- every BE-011 Part 2 addition extends the same files listed
above (`constants.py`, `models.py`, `exceptions.py`, `events.py`,
`validators.py`, `repository.py`, `service.py`, `schemas.py`,
`dependencies.py`, `router.py`), plus:

```text
backend/
  alembic/
    versions/
      0017_create_alert_notification_incident_sla_tables.py
  tests/
    unit/
      test_monitoring_alerts.py
```

## API Surface (Part 2 additions)

See `docs/API.md`'s Monitoring section for the full endpoint table and
`FLOW.md` §16 for the RBAC-permission-key-reuse reasoning behind every key
below (no dedicated "incidents"/"sla" permission module exists; neither
`alerts`/`notifications` has a seeded `create` action).

```text
POST/GET/PUT/DELETE /api/v1/alerts/rules[/{id}]        alerts.manage/read/update/delete
GET  /api/v1/alerts                                     alerts.read
GET  /api/v1/alerts/{id}                                alerts.read
POST /api/v1/alerts/{id}/acknowledge                    alerts.update
POST /api/v1/alerts/{id}/resolve                        alerts.update
POST/GET/PUT/DELETE /api/v1/notifications/channels[/{id}]  notifications.manage/read/update/delete
GET  /api/v1/notifications/logs                         notifications.read
POST/GET /api/v1/incidents                              alerts.manage/read
GET  /api/v1/incidents/{id}                             alerts.read
PUT  /api/v1/incidents/{id}                              alerts.update
POST /api/v1/incidents/{id}/alerts                       alerts.update
GET  /api/v1/sla                                         reports.read
POST /api/v1/sla/targets                                 reports.manage
GET  /api/v1/sla/{target_id}/reports                     reports.read
POST /api/v1/sla/{target_id}/generate-report              reports.manage
```

## Testing (Part 2)

`tests/unit/test_monitoring_alerts.py` covers: alert rule evaluation for
all three trigger types (including the de-duplication key and the
auto-recovery design), alert status-transition validation, notification
dispatch to every channel type (real HTTP POSTs faked via
`httpx.MockTransport` -- no real network calls anywhere in this test
suite -- plus the resilience guarantee that a delivery failure never
raises), notification-channel config encryption round-trip and validation,
incident lifecycle transitions and idempotent alert attachment, SLA report
computation (including the "insufficient data" honesty guard), and every
new endpoint's RBAC permission-key reuse (introspected directly off the
registered FastAPI routes). All 524 previously-passing tests continue to
pass unmodified, plus 65 new tests here (589 total).
