# Analytics: Database Schema

Migration: `alembic/versions/0018_create_analytics_tables.py` (revises
`0017_create_alert_notification_incident_sla_tables`). One new table,
extending `app.database.base.BaseModel` (`id`, `created_at`, `updated_at`,
`deleted_at`/`is_deleted`, `created_by`/`updated_by`, `version`) -- no
changes to any existing table's columns.

No `analytics_cache` table is created -- see `FLOW.md` §6 for the full
"Redis, not a redundant SQL cache table" reasoning.

## `analytics_snapshots`

A pre-computed rollup over `[period_start, period_end]` for one
`snapshot_type`.

| Column | Type | Notes |
|---|---|---|
| `organization_id` | UUID, FK `organizations.id` (`SET NULL`), nullable | `NULL` means platform-wide |
| `location_id` | UUID, FK `locations.id` (`SET NULL`), nullable | `NULL` means organization-wide or platform-wide |
| `snapshot_type` | String(30) | `constants.AnalyticsSnapshotType` -- `org_daily_summary` / `location_daily_summary` / `platform_daily_summary` |
| `period_start` | DateTime(tz), not nullable | |
| `period_end` | DateTime(tz), not nullable | |
| `granularity` | String(20) | `constants.AnalyticsGranularity` -- this part only ever writes `daily` |
| `metrics` | JSONB, not nullable, default `{}` | Shape varies by `snapshot_type` -- see below |
| `computed_at` | DateTime(tz), not nullable | When this row was actually produced (may lag `period_end` -- see `FLOW.md` §4) |
| `computation_duration_ms` | Float, nullable | How long the real SQL aggregate queries behind this row took to run |

### `organization_id`/`location_id` scoping convention

| `snapshot_type` | `organization_id` | `location_id` |
|---|---|---|
| `platform_daily_summary` | `NULL` | `NULL` |
| `org_daily_summary` | set | `NULL` |
| `location_daily_summary` | set (the location's owning org) | set |

### `metrics` JSONB schema

**`org_daily_summary` / `location_daily_summary`** (identical shape -- the
latter is additionally scoped by `location_id`):

```json
{
  "guest_count_unique": 30,
  "guest_count_new": 18,
  "guest_count_returning": 12,
  "session_count_total": 42,
  "session_count_active": 5,
  "average_session_duration_seconds": 123.45,
  "total_bandwidth_bytes": 999999,
  "router_count_online": 8,
  "router_count_offline": 2,
  "router_count_total": 10
}
```

* `guest_count_unique`/`guest_count_returning`/`session_count_total`/
  `average_session_duration_seconds`/`total_bandwidth_bytes` come directly
  from `app.domains.guest.service.GuestAnalyticsService.get_summary` (reused,
  never re-derived -- see `FLOW.md` §1/`aggregation.py`'s module docstring).
  `guest_count_new = max(unique_guests - returning_guests, 0)`.
* `session_count_active` is a real-time `COUNT` of currently-`ACTIVE`
  `GuestSession` rows scoped to the organization/location (not date-ranged
  -- "active right now", unlike the other, `[period_start, period_end]`
  windowed counts).
* `router_count_online`/`router_count_offline`/`router_count_total` are a
  real `GROUP BY Router.status` `COUNT`, scoped to the organization/
  location.

**`platform_daily_summary`**:

```json
{
  "organization_count_total": 4,
  "location_count_total": 9,
  "router_count_online": 20,
  "router_count_offline": 3,
  "router_count_total": 24,
  "guest_count_unique_today": 55,
  "session_count_total_today": 100
}
```

* `organization_count_total`/`location_count_total` are platform-wide
  `COUNT`s (non-deleted rows).
* `router_count_*` is the same `GROUP BY Router.status` query, unscoped.
* `guest_count_unique_today`/`session_count_total_today` are computed
  directly against `GuestSession` (not through `GuestAnalyticsService`,
  whose `organization_id` parameter is mandatory by design -- guest
  analytics are inherently tenant-scoped upstream; a platform-wide guest
  count genuinely has no single tenant to scope through).

### Indexes -- see `FLOW.md` §8 for the full rationale

| Index | Columns | Purpose |
|---|---|---|
| `ix_analytics_snapshots_org_type_period_start` | `(organization_id, snapshot_type, period_start)` | **Primary query pattern**: "latest/date-ranged snapshots for one org + one type" |
| `ix_analytics_snapshots_location_id` | `(location_id)` | Location-scoped reads without an explicit `organization_id` |
| `ix_analytics_snapshots_snapshot_type` | `(snapshot_type)` | |
| `ix_analytics_snapshots_period_start` | `(period_start)` | Cross-organization date-range queries |
| `ix_analytics_snapshots_period_end` | `(period_end)` | |

Plus the standard `BaseModel` indexes (`created_at`, `deleted_at`,
`is_deleted`, `created_by`, `updated_by`).

### Relationship to other domains' tables (composition, not duplication)

* **Not a duplicate of `app.domains.router_provisioning.models
  .RouterHealthSnapshot`.** That table is a per-router, point-in-time
  metrics reading (CPU/memory/uptime/connected-clients for *one device*).
  `AnalyticsSnapshot` is a higher-level, organization/location/
  platform-scoped rollup *across many routers and guests* for a time
  window. Neither table is read or written by the other.
* **Sources, read-only, from `app.domains.guest.models.GuestSession`/
  `app.domains.router.models.Router`/`app.domains.organization.models
  .Organization`/`app.domains.location.models.Location`.** No file inside
  any of those domains is edited by this part -- see
  `app.domains.analytics.repository`'s own module docstring for the exact
  read-only composition queries, the same "read another domain's model
  directly for an aggregate/dashboard signal" precedent
  `app.domains.monitoring.repository` already established.

## No RBAC schema changes

This domain reuses RBAC's already-seeded `analytics.read`/`reports.manage`
permission keys (see `FLOW.md` §11) -- a config-only decision with no
schema impact, no new `PermissionModule` value, no new migration.

---

# BE-012 Part 2 schema additions

No new table. One narrow, additive column on a different domain's table
(the one conditionally-permitted exception this part's directory rule
allows -- see `FLOW.md` §14 for the full write-up of why this was judged
worth doing for real):

## `guest_sessions.user_agent` (new column)

Migration: `alembic/versions/0019_add_user_agent_to_guest_sessions.py`
(revises `0018_create_analytics_tables`).

| Column | Type | Notes |
|---|---|---|
| `user_agent` | `Text`, nullable | The raw `User-Agent` request header, captured best-effort at `app.domains.guest.service.GuestService.login_via_otp`/`login_via_voucher` (and copied forward by `reconnect`). `NULL` for every session created before this column existed, and for any guest device that omitted the header. No index -- never filtered/joined on, only classified via `CASE`/regex at dashboard read time (see below). |

### Where this column is actually read: `AnalyticsRepository.get_user_agent_breakdown`

This domain's own `repository.py` classifies every non-`NULL`
`GuestSession.user_agent` in scope/window into OS/browser/device-type
buckets via real Postgres `CASE`/`~*` (case-insensitive regex) matching
directly in the `SELECT`, then `GROUP BY`/`COUNT` -- see `FLOW.md` §14 for
the exact classifier and why it is a small, honest, hand-written heuristic
rather than a `user-agents`-style parsing dependency. No other file in
`app.domains.guest` beyond `models.py` (the column)/`router.py` (header
capture)/`service.py` (threading the value through session creation) was
touched to support this.

---

# BE-012 Part 3 schema additions

One narrow, additive column (the same conditionally-permitted exception
Part 2 used for `user_agent` -- see `FLOW.md` §34 for the full "why this
was judged worth doing for real" write-up):

## `guest_sessions.accept_language` (new column)

Migration: `alembic/versions/0020_add_accept_language_to_guest_sessions.py`
(revises `0019_add_user_agent_to_guest_sessions`). No `alembic/env.py`
change was needed -- `app.domains.guest.models` was already imported there
since Part 2.

| Column | Type | Notes |
|---|---|---|
| `accept_language` | `Text`, nullable | The raw `Accept-Language` request header, captured best-effort at `app.domains.guest.service.GuestService.login_via_otp`/`login_via_voucher` (and copied forward by `reconnect`). `NULL` for every session created before this column existed, and for any guest device that omitted the header. No index -- never filtered/joined on, only classified via `split_part`/`GROUP BY` at dashboard read time (see below). |

### Where this column is actually read: `AnalyticsRepository.get_language_breakdown`

Extracts the primary language tag from the RFC 7231 `Accept-Language`
header shape (comma-separated, quality-weighted, most-preferred-first) via
`split_part(split_part(accept_language, ',', 1), ';', 1)`, trimmed, then
`GROUP BY`/`COUNT` -- see `FLOW.md` §34 for the full write-up. No other
file in `app.domains.guest` beyond `models.py`/`router.py`/`service.py` was
touched -- identical scope to `user_agent`'s own Part 2 change.

## No other schema changes

Every other BE-012 Part 3 figure (Router/Network/Guest/Authentication
Analytics) is a real SQL aggregate over already-existing tables
(`GuestSession`, `GuestLoginHistory`, `Router`,
`app.domains.router_provisioning.models.RouterHealthSnapshot`,
`app.domains.wireguard.models.WireGuardPeer`,
`app.domains.voucher.models.Voucher`/`VoucherBatch`,
`app.domains.otp.models.OtpRequest`, `app.domains.rbac.models
.AuditLogEntry`) -- see `AnalyticsRepository`'s own module docstring for
the full "read another domain's table directly for a narrow aggregate"
precedent this part continues, and `FLOW.md` §§23-34 for exactly which
query backs which figure. No table was added, and no other existing
table's columns changed.

---

# BE-012 Part 4 schema additions

**None.** This part is pure read/computation over data that already exists
-- see `FLOW.md` §46 for the explicit statement of why no migration was
needed. Seven new, read-only repository methods were added to
`AnalyticsRepository`, all real SQL over already-existing tables, no new
table and no new column:

| Method | Real query over | Feeds |
|---|---|---|
| `count_organizations_by_subscription_tier` | `GROUP BY Organization.subscription_tier` | Business Analytics' Plan Distribution |
| `list_all_routers_with_organization` | `Router JOIN Organization` (platform-wide, unlike Part 3's own one-organization-at-a-time `list_routers_for_scope`) | Operational Recommendations' offline-router and rising-CPU rules |
| `get_router_health_snapshot_history` | `RouterHealthSnapshot`, bounded by router-id set + date window, ordered `(router_id, recorded_at)` ascending | Forecast Engine's Router Failure Risk heuristic; Operational Recommendations' rising-CPU rule |
| `get_alert_counts_by_router` | `GROUP BY Alert.router_id` (`Alert.router_id` is a real, populated FK) | Router Failure Risk's "repeated Alerts" signal |
| `get_persistent_critical_alert_counts_by_organization` | `GROUP BY Alert.organization_id`, filtered `severity=CRITICAL AND status != RESOLVED AND triggered_at <= older_than` | Operational Recommendations' "persistent_critical_alerts" rule |
| `get_organization_names` | `Organization.id/name`, bulk `IN` lookup | Human-readable insight/recommendation messages |
| `get_location_names` | `Location.id/name`, bulk `IN` lookup | Human-readable insight/recommendation messages |

Every Forecast Engine linear-trend endpoint (Bandwidth/Traffic, Guest
Growth, Network Load, Capacity) reuses `AnalyticsRepository.list_snapshots`
-- a method that already existed since Part 1 -- with no new query needed;
`trends.extract_metric_series`/`forecast.forecast_linear_series` do all the
new work in pure Python over an already-real, already-fetched snapshot list.

---

# BE-012 Part 5 schema additions

Migration: `alembic/versions/0021_create_report_tables.py` (revises
`0020_add_accept_language_to_guest_sessions`). Two new tables, both
extending `BaseModel` the same way `analytics_snapshots` does -- no changes
to any existing table's columns. No RBAC FK follow-up migration needed --
`reports.*` permission keys were already seeded since Part 1 (see
`0018_create_analytics_tables`'s own note on this).

## `report_templates`

A reusable, persisted definition of what a report contains.

| Column | Type | Notes |
|---|---|---|
| `name` | String(200), not nullable | |
| `description` | String(2000), nullable | |
| `organization_id` | UUID, FK `organizations.id` (`SET NULL`), nullable | `NULL` = platform-wide system template |
| `report_type` | String(30), not nullable | `constants.ReportType` -- `dashboard`/`organization`/`location`/`router`/`guest`/`network`/`revenue`/`health` |
| `config` | JSONB, not nullable, default `{}` | Composition defaults: `location_id`, `window_days`, `include_router_failure_risk` -- see `FLOW.md` |
| `is_active` | Boolean, not nullable, default `true` | |
| `created_by_user_id` | UUID, nullable | |

Indexes: `organization_id`, `report_type`, `is_active` (plus the standard
`BaseModel` indexes).

## `scheduled_reports`

A recurring render of one `report_templates` row.

| Column | Type | Notes |
|---|---|---|
| `template_id` | UUID, FK `report_templates.id` (`CASCADE`), not nullable | |
| `organization_id` | UUID, FK `organizations.id` (`CASCADE`), not nullable | Unlike `report_templates.organization_id`, never `NULL` -- see `FLOW.md`'s manual-vs-scheduled write-up |
| `frequency` | String(20), not nullable | `constants.ReportFrequency` -- `daily`/`weekly`/`monthly` |
| `recipient_emails` | JSONB, not nullable, default `[]` | List of email address strings |
| `export_format` | String(10), not nullable | `constants.ExportFormat` -- `pdf`/`csv`/`excel`/`json` |
| `next_run_at` | DateTime(tz), not nullable | Always populated -- computed at creation and after every run |
| `last_run_at` | DateTime(tz), nullable | `NULL` until the first run |
| `last_run_status` | String(10), nullable | `constants.ReportRunStatus` -- `success`/`failed`, `NULL` until the first run |
| `is_active` | Boolean, not nullable, default `true` | |
| `created_by_user_id` | UUID, nullable | |

Indexes: `template_id`, `organization_id`, and a composite
`(is_active, next_run_at)` index -- the primary query pattern for
`report_tasks.run_scheduled_reports`'s hourly "which schedules are due"
sweep (`WHERE is_active = true AND next_run_at <= now()`), the same
equality-then-range composite-index rationale
`analytics_snapshots`' own `(organization_id, snapshot_type, period_start)`
index already establishes.

## No other schema changes

Every figure in a generated report comes from an already-existing
`AnalyticsSnapshot`/`RouterHealthSnapshot`/`Alert`/... query Parts 1-4
already added -- the Report Engine (`report_service.py`) and Export Engine
(`export.py`) are pure composition/rendering layers with no repository
queries of their own beyond `report_templates`/`scheduled_reports` CRUD.
