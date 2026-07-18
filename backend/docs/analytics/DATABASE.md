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
