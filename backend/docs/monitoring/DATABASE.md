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

---

# BE-011 Part 2: Alert Engine + Notification Engine + Incident Engine + SLA Monitoring

Migration: `alembic/versions/0017_create_alert_notification_incident_sla_tables.py`
(revises `0016_create_monitoring_tables`). Nine new tables, all extending
`BaseModel`, created in FK-dependency order. See `FLOW.md` §10-16 for the
full design write-up behind every decision below.

## `notification_channels`

A configured delivery destination.

| Column | Type | Notes |
|---|---|---|
| `organization_id` | UUID, FK `organizations.id` (`SET NULL`), nullable | `NULL` = platform-wide default channel |
| `channel_type` | String(20) | `constants.NotificationChannelType` -- `email`/`sms`/`whatsapp`/`slack`/`teams`/`discord`/`webhook` |
| `name` | String(200) | |
| `config_encrypted` | Text | Fernet-encrypted JSON (`app.domains.router.crypto.encrypt_secret`) -- see per-type schema below. Never returned decrypted by the API. |
| `is_active` | Boolean, default `true` | |

**Per-`channel_type` `config` JSON schema** (plaintext shape before
encryption; see `validators.validate_notification_channel_config`):

| `channel_type` | Required keys | Notes |
|---|---|---|
| `email` | `email` | Must contain `@` |
| `sms` | `phone_number` | |
| `whatsapp` | `phone_number` | Same shape as `sms` -- only the notifier (real vs. logging-only) differs |
| `slack` | `webhook_url` | Must start with `https://` |
| `teams` | `webhook_url` | Must start with `https://` |
| `discord` | `webhook_url` | Must start with `https://` |
| `webhook` | `url` (`http://` or `https://`); optional `auth_header_name`/`auth_header_value` (must both be present or both absent) | Generic, operator-defined destination |

## `alert_rules`

A watched condition. See `FLOW.md` §11/§12 for the full
`trigger_type`/`target_component`/`condition_config` write-up.

| Column | Type | Notes |
|---|---|---|
| `name` | String(200) | |
| `description` | Text, nullable | |
| `organization_id` | UUID, FK `organizations.id` (`SET NULL`), nullable | `NULL` = platform-wide system rule |
| `trigger_type` | String(30) | `constants.AlertTriggerType` -- `health_status_change`/`threshold`/`event_occurred` |
| `target_component` | String(50), nullable | A `HealthComponent` value, `"router"` (`ALERT_TARGET_ROUTER`), or `NULL` (threshold/event-occurred rules) |
| `condition_config` | JSONB | Shape depends on `trigger_type` -- see `FLOW.md` §11/§12 and `constants.AlertTriggerType`'s docstring |
| `severity` | String(20) | `constants.AlertSeverity` -- `info`/`warning`/`critical` |
| `is_active` | Boolean, default `true` | |

## `alert_rule_notification_channels`

Join table: which channels a triggered rule notifies. A real association
table (referential integrity), not a JSONB id list on `alert_rules`.

| Column | Type | Notes |
|---|---|---|
| `alert_rule_id` | UUID, FK `alert_rules.id` (`CASCADE`) | |
| `notification_channel_id` | UUID, FK `notification_channels.id` (`CASCADE`) | |

Unique on `(alert_rule_id, notification_channel_id)`.

## `alerts`

One firing/resolved instance of a rule's condition. See `FLOW.md` §10 for
the exact de-duplication key and recovery design.

| Column | Type | Notes |
|---|---|---|
| `rule_id` | UUID, FK `alert_rules.id` (`CASCADE`) | |
| `status` | String(20) | `constants.AlertStatus` -- `triggered`/`acknowledged`/`resolved`; see `ALERT_STATUS_TRANSITIONS` |
| `triggered_at` | DateTime(tz) | |
| `acknowledged_at` / `acknowledged_by_user_id` | DateTime(tz) / UUID, both nullable, no FK | Mirrors `ProvisioningJob.requested_by_user_id`'s "no cross-domain user FK" convention |
| `resolved_at` | DateTime(tz), nullable | Set on both manual and auto-resolution |
| `organization_id` / `location_id` / `router_id` | UUID, FK's (`SET NULL`), all nullable | The specific target this alert fired for |
| `message` | Text | |
| `related_health_check_id` | UUID, FK `health_checks.id` (`SET NULL`), nullable | Set for health-status-change/threshold alerts when a specific check row is the direct cause |
| `related_event_id` | UUID, FK `platform_events.id` (`SET NULL`), nullable | Set for event-occurred alerts -- also this trigger type's de-duplication key (`(rule_id, related_event_id)`) |
| `severity` | String(20) | **Copied from the rule at trigger time**, never referenced live -- the same "copy, don't reference" reasoning `guest`'s voucher-derived session quotas already establish |

## `notification_logs`

A durable delivery record (sent/failed) for every
`NotificationService.dispatch_notification` attempt.

| Column | Type | Notes |
|---|---|---|
| `channel_id` | UUID, FK `notification_channels.id` (`CASCADE`) | |
| `alert_id` | UUID, FK `alerts.id` (`SET NULL`), nullable | A notification can in principle be for something other than an alert |
| `sent_at` | DateTime(tz) | |
| `status` | String(20) | `constants.NotificationStatus` -- `sent`/`failed` |
| `error_message` | Text, nullable | Populated on `failed` |
| `response_summary` | Text, nullable | e.g. `"HTTP 200"` for webhook-style channels, or a short honest note for the WhatsApp placeholder |

## `incidents`

A human-managed grouping of related alerts -- fully manual (`FLOW.md` §14).

| Column | Type | Notes |
|---|---|---|
| `title` | String(200) | |
| `description` | Text, nullable | |
| `status` | String(20) | `constants.IncidentStatus` -- `open`/`investigating`/`resolved`/`closed`; see `INCIDENT_STATUS_TRANSITIONS` |
| `severity` | String(20) | Reuses `constants.AlertSeverity` (no duplicate `IncidentSeverity` enum) |
| `organization_id` | UUID, FK `organizations.id` (`SET NULL`), nullable | |
| `assigned_to_user_id` | UUID, nullable, no FK | |
| `opened_at` | DateTime(tz) | |
| `resolved_at` / `closed_at` | DateTime(tz), nullable | |
| `resolution_notes` | Text, nullable | |

## `incident_alerts`

Join table: which alerts are grouped into an incident.

| Column | Type | Notes |
|---|---|---|
| `incident_id` | UUID, FK `incidents.id` (`CASCADE`) | |
| `alert_id` | UUID, FK `alerts.id` (`CASCADE`) | |

Unique on `(incident_id, alert_id)` -- attaching the same alert twice is
idempotent at the service layer (`IncidentService.attach_alert`).

## `sla_targets`

A committed uptime target.

| Column | Type | Notes |
|---|---|---|
| `organization_id` | UUID, FK `organizations.id` (`SET NULL`), nullable | `NULL` = platform-wide target |
| `component` | String(20), nullable | A `HealthComponent` value, or `NULL` for the platform's overall dashboard status |
| `target_percentage` | Float | e.g. `99.9` |
| `measurement_window_days` | Integer | e.g. `30` |

## `sla_reports`

A computed measurement of a target over a period -- see `FLOW.md` §15 for
the exact formula.

| Column | Type | Notes |
|---|---|---|
| `sla_target_id` | UUID, FK `sla_targets.id` (`CASCADE`) | |
| `period_start` / `period_end` | DateTime(tz) | |
| `achieved_percentage` | Float | `healthy_checks / total_checks * 100` |
| `total_checks` / `healthy_checks` | Integer | Real `COUNT(*)` aggregates against `health_checks` |
| `average_response_time_ms` | Float, nullable | Real `AVG(response_time_ms)` over the same rows/window |
| `generated_at` | DateTime(tz) | |

## No RBAC follow-up migration needed

Same as Part 1: none of these nine tables are referenced by any RBAC scope
column. The RBAC permission-key-reuse decisions (`FLOW.md` §16) are
config-only (which seeded `permission_key` string gates which route) and
have zero schema impact.

# BE-011 Part 3: no new tables, no new columns

Part 3 (Real-Time WebSockets + ZTP Monitoring Dashboard + Analytics)
introduces **zero new persisted state** -- no new table, no new column on
any existing table, and therefore no `backend/alembic/versions/0018_...py`
migration. This was a genuine architectural conclusion, not an oversight:

* The Real-Time Engine's transport is Redis pub/sub
  (`constants.MONITORING_LIVE_CHANNEL`), which is deliberately transient --
  a `PUBLISH` a WebSocket client happens to have missed is simply gone, the
  same disposable-transport posture `app.domains.router_provisioning
  .ProvisioningJob`'s own `PROVISIONING_QUEUE_REDIS_KEY` already documents
  ("Redis is the dispatch transport, Postgres is the durable source of
  truth"). Every fact a client could want to recover after a missed
  broadcast is already durably persisted in an existing table
  (`health_checks`/`service_health`, `alerts`, `guest_sessions`) -- nothing
  needs a new row.
* `RouterLifecycleStage` (see `FLOW.md` §22) is a **pure, computed,
  presentation-layer label**, deliberately never persisted as a column
  anywhere. It is derived on every read from four columns that already
  exist across three other domains
  (`router_enrollment_requests.status`, `routers.status`,
  `provisioning_jobs.status`/`attempts`/`max_attempts`,
  `routers.last_seen_at`). Persisting a tenth, derived copy of that
  composition would create a second source of truth that can drift the
  moment any one of those four columns changes without this label being
  recomputed in lockstep -- see `FLOW.md` §22 for the full argument.
* Every dashboard/analytics aggregate (device counts by status, alert
  counts by severity/status, health-check uptime/downtime counts,
  provisioning success rate/failure breakdown/retry dashboard/activation
  timing) is a real SQL `SELECT`/`GROUP BY`/`AVG`/`COUNT` query against
  `routers`, `alerts`, `health_checks`, and `provisioning_jobs` +
  `router_enrollment_requests` -- all already-existing tables from BE-008/
  BE-009/Part 1/Part 2. Nothing new is stored; everything is computed at
  request time from data that already has an authoritative home.

`backend/alembic/versions/` and `backend/alembic/env.py` are untouched by
this part.
