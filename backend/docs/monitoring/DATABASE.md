# Monitoring: Database Schema

Migration: `alembic/versions/0016_create_monitoring_tables.py` (revises
`0015_create_guest_tables`). Four new tables, all extending
`app.database.base.BaseModel` (`id`, `created_at`, `updated_at`,
`deleted_at`/`is_deleted`, `created_by`/`updated_by`, `version`) -- no
changes to any existing table's columns.

No `device_health` table is created -- see `FLOW.md` §1 for the full
"why no new table (or even composition method) earns its keep here"
reasoning: `app.domains.router.models.Router.health_status`/`last_seen_at`/
`last_health_check_at` plus `app.domains.router_provisioning.models
.RouterHealthSnapshot`/`RouterEvent` already model everything a per-router
health rollup would need.

## `health_checks`

One row per health-check *execution* for one platform component -- the
time-series history `service_health`'s current-state rollup deliberately
does not keep.

| Column | Type | Notes |
|---|---|---|
| `component` | String(20) | `constants.HealthComponent` -- `database`/`redis`/`api`/`auth`/`storage`/`celery`/`websocket`/`freeradius`/`wireguard` |
| `status` | String(20) | `constants.HealthStatus` -- `healthy`/`degraded`/`unhealthy`/`unknown` |
| `checked_at` | DateTime(tz), not nullable | |
| `response_time_ms` | Float, nullable | `None` for checks with no meaningful latency (e.g. `celery`/`websocket`) |
| `details` | JSONB, nullable | Component-specific diagnostic info (e.g. disk usage percentages, NAS client counts) |
| `error_message` | Text, nullable | Populated on any non-`healthy` result |

No foreign keys -- a pure, self-contained time-series row. Indexes on
`component`, `status`, `checked_at` (history queries filter/sort by all
three).

## `service_health`

One row *per component* (unique on `component`), the current rolled-up
state a dashboard reads without scanning `health_checks` history on every
request.

| Column | Type | Notes |
|---|---|---|
| `component` | String(20), **unique** | `constants.HealthComponent` |
| `status` | String(20) | Latest known status |
| `last_checked_at` | DateTime(tz), nullable | |
| `consecutive_failure_count` | Integer, default `0` | Increments on every non-`healthy` result, resets to `0` the moment a component reports `healthy` again -- see `FLOW.md`/`service.py`'s `_persist_result`. Intended future consumer: BE-011 Part 2's alert-threshold logic. |

## `heartbeat_logs`

A generic, cross-domain heartbeat log -- **not** a replacement for any
existing domain's own heartbeat mechanism. See `FLOW.md` §2 for the full
design write-up and its precise relationship to
`app.domains.router_agent`'s existing device heartbeat.

| Column | Type | Notes |
|---|---|---|
| `component_type` | String(20) | `constants.HeartbeatComponentType` -- `router`/`wireguard_peer`/`service` |
| `component_id` | UUID, **no FK** | Polymorphic reference -- see `FLOW.md` §2 for why this is unconstrained by design (mirrors `AuditLogEntry.entity_id`'s identical tradeoff) |
| `received_at` | DateTime(tz), not nullable | |
| `payload` | JSONB, nullable | Component-specific heartbeat detail (e.g. `routeros_version`, `management_ip_address`) |

## `platform_events`

A narrowly-scoped **new** event table -- populated only by this module's
own Health Engine's status-transition detections. See `FLOW.md` §3 for the
full composition-vs-new-storage write-up and why this is not a duplicate of
`audit_log_entries`/`router_events`.

| Column | Type | Notes |
|---|---|---|
| `category` | String(20) | `constants.EventCategory` -- `system`/`security`/`network`/`authentication`/`provisioning`/`guest`/`audit` |
| `event_type` | String(100) | A free-form namespaced string (e.g. `"monitoring.component_unhealthy"`), not a closed enum -- mirrors `RouterEvent.event_type`'s identical reasoning, since event types grow across every domain over time |
| `severity` | String(20) | `constants.EventSeverity` -- `info`/`warning`/`error`/`critical` |
| `organization_id` | UUID, FK `organizations.id` (`SET NULL`), nullable | `NULL` for this module's own platform-wide events; present for any future domain-scoped writer |
| `location_id` | UUID, FK `locations.id` (`SET NULL`), nullable | Same as above |
| `router_id` | UUID, FK `routers.id` (`SET NULL`), nullable | Same as above |
| `source_domain` | String(50), not nullable | Which module emitted this -- always `"monitoring"` today |
| `message` | Text, not nullable | |
| `metadata` (Python attribute `event_metadata`) | JSONB, nullable | Mirrors `AuditLogEntry`/`RouterEvent`'s identical `metadata`-column/`event_metadata`-attribute convention (`metadata` is reserved by SQLAlchemy's `DeclarativeBase`) |
| `occurred_at` | DateTime(tz), not nullable | |

Indexes on `category`, `event_type`, `severity`, `organization_id`,
`location_id`, `router_id`, `occurred_at` (the unified timeline filters/
sorts by every one of these).

## No RBAC follow-up migration needed

Unlike Modules 005/006/008's own RBAC-scope-column follow-ups, none of
these four tables are referenced by any RBAC scope column (`UserRole`/
`PermissionOverride`) -- monitoring has no notion of a role/permission
assignment scoped *to* a health check or event row.

## Read-only cross-domain reads (no schema impact)

`app.domains.monitoring.repository.MonitoringRepository` also issues
read-only `SELECT`s directly against four *other* domains' existing tables
(no migration needed, since none of these tables are modified):

* `guest_sessions`/`radius_nas_clients` (`app.domains.guest`) -- the
  FreeRADIUS proxy signal.
* `wireguard_peers` (`app.domains.wireguard`) -- the WireGuard proxy
  signal (paired with `WireGuardService.compute_health_status`, reused
  directly).
* `audit_log_entries` (`app.domains.rbac`) -- one of the three sources the
  unified event timeline merges.
* `router_events` (`app.domains.router_provisioning`), joined to `routers`
  when an `organization_id` filter is supplied (since `RouterEvent` itself
  carries no `organization_id` column) -- the other merged source.
