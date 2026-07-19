# BE-012 Part 1: Analytics Core Infrastructure -- Design Decisions & Flow

## 1. Why Celery, now, for real

No Celery deployment existed anywhere in this codebase before this part --
confirmed absent in BE-011, which correctly left
`app.domains.monitoring.constants.HealthComponent.CELERY`'s health check as
an honest `HealthStatus.UNKNOWN` ("no Celery worker/broker is deployed in
this environment... ready to wire in once one does"). Analytics aggregation
over potentially millions of `GuestSession`/`GuestLoginHistory`/`Router`
rows cannot run synchronously inside a request/response cycle -- this is
the part where a real background task queue stops being optional
infrastructure and becomes genuinely necessary. `app.core.celery_app`
builds a real `Celery` application; nothing about it is a stub or a fake
integration standing in for one.

## 2. Broker/backend: reuse `Settings.redis_url`, no new config knob

Redis is already configured and deployed for this codebase's own async
cache/pub-sub use (`app.database.redis.redis_client`, RBAC's
`PermissionCache`, `app.domains.monitoring`'s real-time pub/sub channel).
Celery's Redis transport (the `celery[redis]` extra, which pulls in
`kombu`'s Redis transport support) needs nothing beyond the `redis` package
this codebase already depends on -- no second Redis client library, no
second connection URL setting. Both Celery's broker *and* its result
backend point at the exact same `Settings.redis_url` the rest of the app
already uses. `app/core/config.py` is untouched by this part.

## 3. Serialization: JSON only, never pickle

Celery's classic default (pickle) can execute arbitrary code on
deserialization if a task payload is ever tampered with or a compromised
producer publishes malicious data -- a real security liability for a task
queue whose broker (Redis) has no built-in message-level authentication.
`app.core.celery_app` configures `task_serializer`/`result_serializer`/
`accept_content` to `json` only -- the standard, secure default Celery's
own security documentation recommends. Every task in
`app.domains.analytics.tasks` only ever passes primitives (`str`/`int`/
`None`) as arguments/results, so JSON is not just safer but sufficient;
there was never a need for anything richer.

## 4. Beat schedule: two cadences for two different needs

* **Every 15 minutes** (`analytics-rolling-today`): recomputes each active
  organization's/location's/the platform's snapshot for *today so far* (a
  partial-day window from UTC midnight to "now" -- see
  `validators.day_bounds_utc`). This is what gives a dashboard near-
  real-time numbers without querying millions of raw rows on every page
  load. A snapshot up to 15 minutes stale is a reasonable freshness bound
  for an operational dashboard (not a stock ticker), and re-running the
  computation on a 15-minute cadence is cheap: it is a bounded set of
  indexed `GROUP BY`/`COUNT`/`AVG`/`SUM` aggregate queries, not a full-table
  scan, and it grows with the number of active organizations/locations, not
  with the number of historical guest sessions.
* **Once daily, 00:10 UTC** (`analytics-finalize-yesterday`): computes the
  *final*, immutable snapshot for the full previous UTC calendar day, once
  that day has definitively closed. Ten minutes past midnight gives any
  slightly-delayed writes for the tail end of the previous day time to
  land before the "final" snapshot is computed -- this is the row later
  parts' historical trend/reporting views should read as "yesterday's
  numbers", distinct from the rolling snapshot's explicitly-partial
  "today so far" row for the same `(organization_id, snapshot_type)` pair
  (they differ by `period_start`/`period_end`, so both coexist without
  conflicting -- there is no "latest wins, overwrite" logic; every run
  simply inserts a new `AnalyticsSnapshot` row).

Both schedule entries call the exact same task
(`run_daily_aggregation_for_all_organizations`), parameterized only by
`target_date_iso`/`days_ago` (see `app.core.celery_app.celery_app.conf
.beat_schedule`).

## 5. The async-in-a-sync-worker bridge

Celery workers execute task bodies as plain, synchronous Python callables
in a worker process with no running `asyncio` event loop by default -- but
this entire codebase's repository/service layer is `AsyncSession`-based.
`app.domains.analytics.tasks` bridges this with the standard, real pattern:

1. Each public task (`run_daily_aggregation_for_all_organizations`,
   `run_daily_aggregation_for_organization`) is a plain, synchronous
   function -- exactly what Celery expects.
2. Each one calls `asyncio.run(...)` around a small, module-level **async**
   function (`_run_all_organizations_async`/`_run_single_organization_async`).
3. That async function opens a fresh `AsyncSession` via
   `app.database.session.SessionLocal` (the same session factory
   `get_db_session` uses for every HTTP request, just without the FastAPI
   dependency-injection wrapper), builds the real `AnalyticsRepository`/
   `GuestRepository`/`GuestAnalyticsService`/`AnalyticsService` objects,
   awaits `AnalyticsService`'s real aggregation call, commits, and returns a
   plain, JSON-serializable result.

`asyncio.run` is safe here specifically because a Celery worker task body
is never itself already running inside an event loop -- unlike calling this
from within an already-async FastAPI request handler, where a nested
`asyncio.run` would raise `RuntimeError`.

**Why the async bridge functions live at module scope, not inlined into
the `@celery_app.task` bodies:** this is what keeps `tasks.py` testable
without a running Celery worker or broker.
`tests/unit/test_analytics.py::test_run_daily_aggregation_for_all_
organizations_task_bridges_into_async` monkeypatches
`tasks._run_all_organizations_async` with a fake coroutine function and
calls the plain task function directly (Celery tasks remain ordinary,
directly callable Python functions/`PromiseProxy` objects when not invoked
through `.delay()`/`.apply_async()`), asserting the bridge resolves the
coroutine and shapes its result correctly.

`aggregation.py` itself never imports Celery at all -- every function in it
is plain `async def`, taking injected, narrow protocol objects
(`GuestAnalyticsLookupProtocol`, `AnalyticsRepositoryProtocol`) rather than
a raw `AsyncSession` or anything Celery-specific, so it is testable as
ordinary async code completely independent of the task queue.

## 6. Redis-vs-new-table cache decision (`analytics_cache`)

The module brief that inspired this part named `analytics_cache` as an
*example* table, not a mandate. This codebase already has an established,
working pattern for exactly the need that name implies -- "cache a
computed result behind a TTL so a hot read path doesn't repeat expensive
work" -- in `app.domains.rbac.cache.PermissionCache`, a Redis-backed cache
with **no** backing SQL table at all. A second, SQL-backed cache table here
would duplicate that pattern for no benefit: Postgres has no native
per-row TTL (eviction would need its own sweep job), a write-heavy cache
table (a busy dashboard re-warming a near-miss on every request) is an
index-maintenance cost a plain Redis key never has, and it would leave two
different "cache expiry" idioms in the same codebase to keep straight.

**Decision: no `analytics_cache` table exists.** `AnalyticsSnapshot` itself
already *is* the durable, query-fast artifact this domain's own read path
needs (see §8's indexing rationale) -- it is not a "cache" of some other,
more-expensive-to-compute source in the request/response sense, it *is*
the source of truth for "what did this rollup look like." Any future
BE-012 part that wants a genuine request-scoped read-through cache in
front of `AnalyticsSnapshot` queries (e.g. memoizing an expensive
cross-snapshot dashboard computation for a few seconds) should reuse Redis
directly, the same TTL'd-key pattern `PermissionCache` already establishes,
not add a redundant table.

## 7. Exactly what changed in `check_celery_health`, and why

**Before (BE-011 Part 1):** `check_celery_health` unconditionally returned
`HealthStatus.UNKNOWN` with a fixed message -- an honest placeholder for
infrastructure that did not exist.

**Now (this part):** the method body performs a real check, three possible
outcomes:

| Condition | `HealthStatus` | Reasoning |
|---|---|---|
| `celery_app.control.inspect().ping()` raises (broker unreachable -- e.g. connection refused) | `UNHEALTHY` | The task queue's own transport is unreachable, the most severe of the three -- not merely idle. |
| The call succeeds but returns nothing (broker reachable, zero workers replied within the timeout) | `DEGRADED` | Background aggregation is stale/paused, but this is **not** a full platform outage -- guest login, RBAC, and every synchronous request/response path are entirely unaffected by a missing worker. |
| At least one worker replies | `HEALTHY` | Recorded in `details` (`workers_responding`, `workers`). |

In this sandbox (no real Redis/Celery deployment running), the honest
result is `UNHEALTHY` -- a `ConnectionError` from attempting to reach
`localhost:6379` (verified: connection is refused immediately, not a slow
timeout, so this check stays fast even with no broker present).

**Where the real check lives, mechanically:** the network round trip
(`celery_app.control.inspect(timeout=...).ping()`) is a **blocking** call,
so it is never awaited directly -- `check_celery_health` runs it via
`asyncio.to_thread(ping_celery_workers, CELERY_HEALTH_CHECK_TIMEOUT_SECONDS)`.
`ping_celery_workers` itself lives in `app.core.celery_app` (not inlined
into `check_celery_health`), specifically so it is a plain, module-level
function this codebase's own test suite can monkeypatch without needing a
live broker or worker (see `tests/unit/test_monitoring.py`'s autouse
`_celery_worker_reachable_by_default` fixture, and
`tests/unit/test_analytics.py`'s direct `ping_celery_workers` tests).

**Directory-rule scope of this edit:** per this part's explicit brief, the
edit to `app/domains/monitoring/service.py` is narrowly scoped to
`check_celery_health`'s own method body (plus the two necessary top-level
imports -- `asyncio`, and `ping_celery_workers`/
`CELERY_HEALTH_CHECK_TIMEOUT_SECONDS` from `app.core.celery_app`). No other
method, class, or file inside `app/domains/monitoring/` was touched. One
consequence of this narrow scope: `MonitoringService.__init__` was **not**
given a new constructor parameter for injecting a fake Celery inspector, so
`tests/unit/test_monitoring.py` makes `check_celery_health` testable the
same way `ping_celery_workers` was itself designed to be -- by
monkeypatching the module-level function in `app.domains.monitoring
.service`'s own namespace (the standard "patch where it's looked up"
pattern), via an autouse fixture that defaults every test in that file to
"a worker is reachable" so none of BE-011 Part 1's pre-existing dashboard/
aggregate-status assertions are affected by Celery's now-real check.

The module docstring of `app/domains/monitoring/service.py` still describes
the *original* BE-011 Part 1 posture ("`check_celery_health`/
`check_websocket_health` never fabricate a `HEALTHY`... they return
`HealthStatus.UNKNOWN`") for `WEBSOCKET`, which remains accurate; the
Celery half of that sentence is now superseded by this document and by
`check_celery_health`'s own updated docstring, but the module docstring
itself was deliberately left untouched to honor this part's narrow
directory rule for that file. Future work that revisits
`app/domains/monitoring/service.py` for any other reason should update that
sentence too.

## 8. `AnalyticsSnapshot` indexing rationale

This table is explicitly the answer to "how do we query analytics fast
across millions of underlying rows" -- so its own query pattern must stay
fast regardless of how large it grows. The read path (this part's own
`GET /analytics/snapshots`, and every later BE-012 part's per-domain
dashboards) is always "give me the latest (or a date-ranged history of)
snapshots for one organization/location and one `snapshot_type`" -- so
`(organization_id, snapshot_type, period_start)` is indexed together as the
primary composite index (a single index scan satisfies an
equality-on-the-first-two-columns, range-on-the-third query, instead of a
full table scan or a bitmap-AND of separate single-column indexes).
`location_id` gets its own index for the location-scoped read path (a
location-only query, with no `organization_id` given, is a legal,
tenant-validated request -- see `router.py`'s `CurrentOrganization`
composition). `period_start`/`period_end` each get their own index too, for
a date-range query spanning every organization (a future platform-wide
historical trend view).

## 9. Per-organization failure isolation in the batch task

`AnalyticsService.run_daily_aggregation_for_all_organizations` iterates
every active organization inside a `try`/`except` per organization: one
organization's aggregation raising (a bad row, a transient DB hiccup scoped
to that tenant's data) is caught, logged
(`analytics_aggregation_failed_for_organization`), and recorded in the
returned `AggregationBatchResult.failed_organizations` list -- it never
aborts the rest of the batch. This mirrors the exact resilience posture
`app.domains.monitoring.service.NotificationService.dispatch_notification`
already establishes for BE-011 Part 2's alert notifications (one channel's
delivery failure is logged, not propagated, and never blocks any other
channel's delivery) -- the identical principle applied to
aggregation-over-many-tenants instead of dispatch-to-many-channels. The
platform-wide `PLATFORM_DAILY_SUMMARY` snapshot is still computed even if
some organizations failed, since it is an independent, whole-table
aggregate query, not a sum of the per-organization results.
`tasks.run_daily_aggregation_for_all_organizations` itself never re-raises
a single organization's failure either -- it reports the batch result
(including a `failed_organizations` list in its return value) and always
completes successfully as a Celery task.

## 10. End-to-end: Beat schedule -> task -> aggregation -> persistence -> API read

```text
app.core.celery_app.celery_app.conf.beat_schedule
  |
  |  (every 15 min, and once daily at 00:10 UTC -- see §4)
  v
app.domains.analytics.tasks.run_daily_aggregation_for_all_organizations
  |  (sync Celery task body)
  |  asyncio.run(...)
  v
app.domains.analytics.tasks._run_all_organizations_async
  |  opens AsyncSession via app.database.session.SessionLocal
  |  builds AnalyticsRepository + GuestRepository + GuestAnalyticsService
  v
app.domains.analytics.service.AnalyticsService
  .run_daily_aggregation_for_all_organizations
  |  for each active organization (per-org try/except, see §9):
  |    .run_daily_aggregation_for_organization
  |      -> .compute_and_store_org_daily_summary
  |           -> aggregation.compute_org_daily_summary  (real SQL aggregates,
  |              composing GuestAnalyticsService.get_summary +
  |              AnalyticsRepository.count_routers_by_status/
  |              count_active_guest_sessions)
  |      -> .compute_and_store_location_daily_summary   (one per active
  |         location -- aggregation.compute_location_daily_summary)
  |  then, regardless of per-org failures:
  |    .compute_and_store_platform_daily_summary
  |      -> aggregation.compute_platform_daily_summary
  v
AnalyticsRepository.create_snapshot -- INSERT into analytics_snapshots
  |
  |  (committed by the task's own async bridge function)
  v
GET /api/v1/analytics/snapshots  (RBAC "analytics.read", tenant-scoped via
  CurrentOrganization)  ->  AnalyticsService.list_snapshots  ->
  AnalyticsRepository.list_snapshots  ->  AnalyticsSnapshotListResponse
```

`POST /api/v1/analytics/snapshots/trigger` (RBAC `reports.manage` -- see
§11) short-circuits the Beat schedule entirely: it calls
`AnalyticsService.trigger_aggregation(organization_id)` directly, in the
same request/response cycle, via the exact same
`run_daily_aggregation_for_organization` method the Celery task uses
underneath -- there is no code duplicated between the on-demand HTTP path
and the scheduled background path, only a different caller.

## 11. RBAC permission-key choices

`GET /analytics/snapshots` uses `analytics.read` --
`app.domains.rbac.enums.PermissionModule.ANALYTICS` is already seeded
(`app.domains.rbac.seed.MODULE_ACTIONS`) with exactly this action, and
`app.domains.guest.router`'s own guest-analytics endpoints already
establish the precedent of gating analytics reads behind this same key.

`POST /analytics/snapshots/trigger` uses `reports.manage` --
`PermissionModule.ANALYTICS` is seeded with only `read`/`export`/`view` (no
`manage`/`create`/`execute` action exists for it), so an admin-gated
*write* action (triggering real, if cheap, aggregation work on demand) has
no dedicated `analytics.*` key to reuse. `PermissionModule.REPORTS` is
seeded with `manage`, and `app.domains.monitoring.router` already
establishes the precedent of reusing `reports.manage` for an
analytics-adjacent admin write action with no dedicated key of its own
(SLA target creation, on-demand SLA report generation) -- this endpoint
follows that exact precedent rather than inventing a new permission module
for one write action.

## 12. Tenant isolation on the snapshot read path

`GET /analytics/snapshots`'s `organization_id` is resolved via RBAC's
`CurrentOrganization` dependency (`X-Organization-Id` header), not a raw,
unchecked query parameter. When the header is present,
`CurrentOrganization` itself validates the organization exists and that the
caller holds an *active* membership in it (raising
`OrganizationMembershipRequiredError` otherwise) -- reused, not
reimplemented, exactly the same guarantee every other domain's own
organization-scoped endpoints already rely on. Omitting the header resolves
to `None` (no DB lookup), which a `GLOBAL`-scoped caller may legitimately do
to see platform-wide/`PLATFORM_DAILY_SUMMARY` rows -- `RequirePermission`'s
own scope inference (`app.domains.rbac.dependencies._infer_scope_type`)
requires `GLOBAL` scope for a request with no scope headers at all, so an
organization-scoped caller cannot simply omit the header to see every
tenant's data.

---

# BE-012 Part 2: Super Admin + Organization + Location Dashboards

Everything below extends this same domain -- no new top-level domain, no
new table besides one narrow, additive column on a different domain's
model (see §14). New modules added to `app.domains.analytics`:
`dashboard_scope.py`, `dashboard_service.py`, `dashboard_schemas.py`,
`dashboard_aggregation.py`, `peak_concurrency.py`, `health_score.py`,
`dashboard_audit.py` -- plus extensions to `repository.py`,
`dependencies.py`, `router.py`, `constants.py`, and `exceptions.py`.

## 13. Peak Concurrent Sessions: a real interval sweep, not a sampling approximation

"Peak concurrent sessions" means: at the single busiest moment within a
window, how many `GuestSession` rows were simultaneously alive? A naive
"sample every N minutes and count active sessions at each sample point"
approach can miss the true peak between samples -- this codebase does not
do that. Instead, `app.domains.analytics.peak_concurrency
.compute_peak_concurrent_sessions` implements a real, correct sweep-line:

1. Every session interval becomes two events: `+1` at its (window-clipped)
   start, `-1` at its (window-clipped) end. A session still `ACTIVE`
   (`ended_at IS NULL`) is treated as alive through the window's own end
   (it cannot be known to have ended before the window closes).
2. Events are sorted chronologically, with **ties broken end-before-start**
   -- a half-open `[start, end)` interval convention, so a session ending
   at exactly `t` and a different session starting at exactly `t` do not
   count as briefly overlapping.
3. Walking the sorted events left to right while keeping a running total,
   the **maximum value that running total ever reaches is the true peak**,
   by definition.

**Why the sweep itself is a plain Python function, not one SQL window-
function query end to end:** the query *could* be expressed in Postgres as
a `SUM(delta) OVER (ORDER BY ts)` window function followed by a `MAX(...)`
of that running sum, but this codebase's own test convention (hand-rolled
fakes, no live Postgres in any unit test -- see `test_analytics.py`'s
module docstring) could not verify that SQL's *correctness* against a
hand-constructed overlapping-intervals fixture without either mocking away
the real logic or introducing a live database into the test suite. The
split chosen keeps both halves honest and testable: **real SQL**
(`AnalyticsRepository.list_session_intervals`) narrows the candidate set to
only sessions whose interval could possibly overlap the requested window (a
bounded, indexed `WHERE` filter -- `started_at <= end AND (ended_at IS NULL
OR ended_at >= start)` -- never every row ever created), and the **pure,
Postgres-independent sweep function** computes the true peak over just the
two datetime columns of that already-filtered result set. This is an
O(n log n) sort-and-scan over interval endpoints, not the kind of
"Python-side loop over bulk-fetched business rows" this codebase's coding
rules warn against -- it operates on exactly two primitive columns per
candidate row, and only over rows a real SQL `WHERE` clause has already
narrowed to "could plausibly matter for this window."

`tests/unit/test_analytics_dashboards.py` verifies this against several
hand-constructed fixtures: no overlap (peak 1), a genuine three-way overlap
(peak 3), the half-open boundary case (a session ending exactly when
another starts is *not* double-counted), a still-`ACTIVE` session treated
as alive through the window's end, and window-clipping of intervals that
extend beyond the requested range.

## 14. The device/browser/OS decision: real capture, not an honest placeholder

Per this part's honesty investigation: `app.domains.guest.router`'s
`guest_login_via_otp`/`guest_login_via_voucher` endpoints already receive a
`Request` object (used today only for `ip_address`) -- so capturing the raw
`User-Agent` header at the exact same call sites is genuinely a small,
narrow, additive change, following the identical discipline BE-011 Part 1's
`HeartbeatLog` hook and BE-011 Part 3's real-time broadcast hook already
established for composing into `app.domains.guest` from elsewhere:

* **One new nullable column**: `GuestSession.user_agent` (`Text`,
  nullable) -- the *raw* header string, never a pre-parsed device/browser/
  OS. Storing it raw means a smarter future classifier never needs a
  backfill migration, only a better read-side query.
* **One line at each of the two login call sites**
  (`app/domains/guest/router.py`): `user_agent =
  request.headers.get("user-agent")`, threaded through
  `GuestService.login_via_otp`/`login_via_voucher` (new, default-`None`
  keyword parameters -- every existing caller/test that does not pass it
  behaves exactly as before) into `_create_session`. `reconnect` also
  carries a prior session's `user_agent` forward onto its derived new
  session, the same "copy forward" discipline it already applies to
  `auth_method`/`device_id`/quota fields.
* **One migration**: `alembic/versions/0019_add_user_agent_to_guest_
  sessions.py` -- a single `ALTER TABLE guest_sessions ADD COLUMN
  user_agent TEXT NULL`, no index (never filtered/joined on, only
  classified via `CASE`/regex and aggregated at read time).

**Files touched inside `app.domains.guest`, exhaustively:** `models.py`
(the one column), `router.py` (two one-line header captures at the two
existing login endpoints), `service.py` (a new, default-`None` keyword
parameter threaded through `login_via_otp`/`login_via_voucher`/
`_create_session`/`reconnect`). Nothing else in that domain was touched --
no schema/response change (`schemas.py` is untouched, so the raw session
response does not expose this field), no new endpoint, no behavior change
for any existing caller.

### Why a regex-based classifier, not a `user-agents`-style dependency

A real, well-known User-Agent parsing library was considered and rejected
for this narrow slice: this dashboard only needs three coarse buckets
(OS/browser/device-type), not a full device model/version-level parse, and
the existing patterns (iPhone/iPad/Android/Windows/Mac/Linux for OS;
Edge/Opera/Chrome/Firefox/Safari for browser, checked most-specific-first
since Edge/Opera/Chrome-on-iOS all also contain the substring `"Chrome"` or
`"Safari"` in their own UA strings) cover the overwhelming majority of real
browser/OS traffic with a handful of `~*` (case-insensitive Postgres regex)
`CASE` branches. Adding a new third-party dependency for three coarse
buckets, for one analytics dashboard slice, was judged unwarranted scope
creep -- this is documented as a **small, honest heuristic classifier, not
a specification-compliant parser**: anything it does not recognize buckets
into `"Other"` rather than guessing, and it is never presented as more
precise than it is.

### Where the classification actually happens: real SQL, not a Python loop

`AnalyticsRepository.get_user_agent_breakdown` classifies every non-`NULL`
`GuestSession.user_agent` in scope/window via Postgres `CASE`/`~*` regex
matching directly in the `SELECT`, then `GROUP BY`/`COUNT` -- never a
Python-side per-row parsing loop. It also reports `sessions_total` and
`sessions_with_user_agent` alongside the breakdown, so
`DeviceBreakdownResponse` can honestly convey coverage: sessions created
before this column existed (or where a guest's device omitted the header)
are real `NULL`s, and the dashboard says so explicitly (`message` field)
rather than silently treating them as zero devices of every kind.

## 15. Organization Health Score: exact formula and weights

`app.domains.analytics.health_score.compute_health_score` implements:

```text
health_score = round(
    0.50 * router_health_component
  + 0.30 * alert_health_component
  + 0.20 * growth_health_component
)
```

Clamped to `[0, 100]`. This is explicitly documented (in the module's own
docstring, and surfaced on the API response itself via
`HealthScoreResponse.formula_note`) as a **heuristic composite score, not a
scientific or statistically-calibrated measure** -- there is no historical
health-score-vs-actual-outcome dataset in this environment to fit weights
against, and this module never claims otherwise.

* **Router health (weight 0.50)**: `online_routers / total_routers * 100`
  for the organization's own, non-deleted routers (`RouterStatus.ONLINE`
  vs. everything else). An organization with zero routers scores `100` on
  this component (nothing to be unhealthy about).
* **Alert health (weight 0.30)**: `100` minus a penalty summed over every
  currently-*open* (non-`RESOLVED`) `Alert` for the organization triggered
  within the last `HEALTH_SCORE_ALERT_LOOKBACK_DAYS` (30) days, weighted by
  severity -- `CRITICAL` costs 25 points each, `WARNING` costs 10, `INFO`
  costs 3 -- capped at a maximum total penalty of 100 (component floors at
  0, never negative).
* **Growth health (weight 0.20)**: `100` if the organization's unique-guest
  count (from `ORG_DAILY_SUMMARY` snapshot history, current period vs. the
  immediately preceding period of equal length) is *increasing*, `70` if
  *flat* (or if there is no prior-period snapshot yet to compare against --
  treated as neutral, not penalized, for a brand-new organization), `40` if
  *declining*. Only the sign is used, never the magnitude.

**Why these three inputs, and why these weights** (see the module's own
docstring for the full write-up): router uptime is weighted highest
because it is the most directly actionable, most objective "is this
organization's deployed infrastructure currently working" signal. Alerts
add everything the platform's monitoring domain has already judged worth
surfacing beyond router connectivity (SLA breaches, provisioning failures,
...), weighted below router health because an alert can be lower-severity/
informational. Growth is weighted lowest since it is the most business/
context-dependent of the three (a seasonal business's low season is not
the same as genuine churn) and the least "healthy infrastructure" flavored.

`tests/unit/test_analytics_dashboards.py::test_health_score_exact_weighted_
formula` verifies the exact arithmetic against known inputs (5/10 routers
online, one critical + one warning alert, a declining trend ->
`25.0 + 19.5 + 8.0 = 52.5 -> round -> 52`).

## 16. Captive Portal Usage: the data-source decision

`app.domains.captive_portal.models.CaptivePortalConfig` has no
view/impression counter, and `GuestSession` carries no direct foreign key
to a specific `CaptivePortalConfig` row -- a portal is resolved at login
time by `(organization_id, location_id)` (most-specific-wins, see that
domain's own `resolve_portal_config`), not referenced per-session
afterward. There is therefore no clean way to attribute "N logins happened
through *this specific* portal config" without adding a new column/FK to
either domain, which this part's directory rule (extend `analytics` only,
compose with `captive_portal`'s existing public interface) does not permit.

**Decision**: "Captive Portal Usage" on the Organization Dashboard is
defined as **guest login volume** (a real `COUNT` of `GuestSession` rows)
**under the organization**, since every guest session that exists is, by
construction, one that passed through *some* active captive portal
resolved for that organization/location -- this is a real, honest, if
coarser-than-per-config-row, usage signal. Alongside it, the dashboard
reports a real, direct count of the organization's `active`/`total`
`CaptivePortalConfig` rows (`AnalyticsRepository
.count_captive_portal_configs`) for context. Both are documented on the
response itself (`captive_portal_note`) so this scoping decision is never
silently implied.

## 17. Honest unavailability: Revenue/ARR/MRR, Trial/Paid, and Country Statistics

**Revenue/Monthly Revenue/ARR/MRR** (`RevenueMetricsResponse`, Super Admin
Dashboard): **always** `available: false`, every numeric field `null`, with
an explanatory `message`. There is no billing/subscription/payment domain
anywhere in this codebase --
`app.domains.organization.models.Organization.subscription_tier` is
explicitly documented (Module 005's own decision) as a lightweight,
unpopulated *label* with no pricing/entitlement logic behind it. Nothing is
guessed or backed into from any other signal.

**Trial Customers / Paid Customers**: the module brief's own instruction
allows approximating these from `subscription_tier`, *if that field is
actually populated anywhere*. It is checked and confirmed **not
populated** in any of this codebase's real data paths (every test factory
and every real `create_organization` call site that does not explicitly
pass it leaves it `NULL`). Rather than report two counts that would always
read `{unknown: N}` off an unpopulated field, this part uses the one
*other* real, always-populated signal this codebase has for exactly this
distinction: `Organization.status` (`app.domains.organization.enums
.OrganizationStatus`), which already has a real `TRIAL` value alongside
`ACTIVE`/`SUSPENDED`/`ARCHIVED`, and every organization's `status` is a
required, non-nullable column with a real, meaningful current value.
`trial_customers = COUNT(status = TRIAL)`, `paid_customers = COUNT(status
IN (ACTIVE, SUSPENDED))` (archived organizations excluded from both). This
is disclosed explicitly on the response (`subscription_note`) as an
**approximation from lifecycle status, not verified billing data** -- "paid"
here means "not currently trialing and not archived," not "has an active,
paid subscription record" (no such record exists anywhere to check).

**Country Statistics** (Location Dashboard): **always**
`available: false`. There is no GeoIP database, no IP-geolocation service,
and no billing/payment data anywhere in this sandbox from which a guest's
country could be honestly derived (an `ip_address` column exists on
`GuestSession`, but resolving an IP to a country requires a real
geolocation data source/service this environment does not have) -- treated
with the exact same honest-unavailable posture as revenue.

## 18. `DashboardScope`: composing RBAC + MSP-children, not reinventing scope resolution

Every dashboard endpoint enforces **two independent layers**, mirroring the
"permission answers *what*, tenant-scoping answers *which tenant's data*"
distinction every other domain in this codebase already draws (e.g.
`app.domains.guest.service.GuestService._enforce_tenant_scope`,
`app.domains.organization.service.OrganizationService
._enforce_tenant_access`):

1. **RBAC's `RequirePermission("analytics.read", scope=...)`**, with an
   explicit, non-inferred `scope=` (`GLOBAL`/`ORGANIZATION`/`LOCATION` per
   endpoint) -- this already verifies the caller holds a role grant whose
   scope covers whatever the request's headers name.
2. **`app.domains.analytics.dashboard_scope.DashboardScope`**, resolved
   from the caller's *real, active RBAC role assignments* (via
   `app.domains.rbac.authorization.RoleResolver`, reused directly) and
   checked independently inside `DashboardService` itself
   (`require_global`/`require_organization`/`require_location`) before any
   data is touched.

Layer 2 exists because layer 1 alone cannot express "an MSP Admin's role
assignment is scoped to their MSP organization, yet they should also see a
rollup across that MSP's child organizations" -- composing a child
organization into a caller's effective dashboard visibility needs a second
step: `DashboardScopeResolver.resolve` expands any `ORGANIZATION`-scoped
grant on an MSP-type organization (`Organization.is_msp()`) into its
children via `app.domains.organization.service.OrganizationService
.list_children` (reused directly, never reimplemented). This one
resolution path handles **both** "Organization Admin -> their own,
non-MSP org" and "MSP Admin -> their MSP org's child organizations" without
special-casing either -- the only difference between the two is whether
`is_msp()` is true for the organization the caller's own grant names.

A `LOCATION`-scoped grant's `UserRole` row is not required to also carry
`organization_id` (see `app.domains.rbac.service.RBACService
._validate_scope_assignment`), so `DashboardScope
Resolver.resolve_location_organization_id` looks up a location's real
owning organization via `app.domains.location.service.LocationService
.get_location` (reused directly) whenever a location-scoped check needs to
compare against an organization id.

**The hierarchy asymmetry is preserved**, mirroring
`app.domains.rbac.authorization.ScopeResolver.satisfies`: a `GLOBAL` scope
allows everything; an `ORGANIZATION`-level scope (already MSP-expanded)
allows every location under any of its organizations (broader covers
narrower); a `LOCATION`-level scope allows *only* its explicit location ids
and can never satisfy an organization-level check (narrower can never
satisfy broader) -- `tests/unit/test_analytics_dashboards.py::test_
dashboard_scope_location_level_cannot_satisfy_organization_check` verifies
this directly.

No file inside `rbac`/`organization`/`location` is edited to make any of
this work -- every composition point is that domain's own already-public
service method or dependency factory.

## 19. Weekly/Monthly visitors: summing daily snapshots, never re-querying raw sessions

The Location Dashboard's weekly/monthly visitor counts are computed by
summing `session_count_total` across already-persisted, already-closed
`LOCATION_DAILY_SUMMARY` snapshots (`app.domains.analytics
.dashboard_aggregation.sum_metric_across_snapshots`, fed by
`AnalyticsRepository.list_snapshots` -- a method that already existed in
Part 1) for the trailing 7/30 days, plus one live, real aggregate call
(`GuestAnalyticsService.get_summary`) for *today's own still-open* window
(a day this early in its own life has no closed snapshot yet). This is the
entire reason the snapshot table exists -- summing seven or thirty
already-computed daily numbers is O(1)-ish regardless of how many
underlying `GuestSession` rows a location has ever accumulated, unlike
re-running a raw aggregate query over the full wider window on every
dashboard request.

## 20. Peak hours/days: real `GROUP BY EXTRACT(...)` queries

`AnalyticsRepository.get_session_counts_by_hour`/
`get_session_counts_by_day_of_week` are real SQL: `EXTRACT(HOUR FROM
started_at)`/`EXTRACT(DOW FROM started_at)` (Postgres `DOW`: `0` = Sunday
.. `6` = Saturday, UTC, matching every other timestamp column in this
codebase), cast to `Integer`, `GROUP BY`, `COUNT`. The service layer then
picks the top result(s) in Python (a trivial `max`/`sort` over at most 24
or 7 already-aggregated rows, not a per-session loop).

## 21. Dashboard-view audit-volume decision

The instruction to "audit every report generation," read completely
literally, would write one `audit_log_entries` row per single dashboard
HTTP request -- exactly the profile this codebase's own OTP/Voucher
audit-volume precedents already warn against for a routine, no-state-
change *read* a real admin UI can reasonably poll/auto-refresh. See
`app.domains.analytics.dashboard_audit`'s own module docstring for the full
write-up; the decision made here is a middle ground:

* **Every** dashboard view is logged via the structured logger,
  unconditionally (`logger.info("dashboard_viewed", ...)`)  -- the cheap,
  high-volume sink this codebase already uses everywhere for exactly this
  kind of signal.
* A durable `audit_log_entries` row is written **at most once per
  `(user_id, dashboard_kind, scope)` per `DASHBOARD_AUDIT_THROTTLE_MINUTES`
  (15) window**, via a real, Redis-backed dedup (`DashboardAuditThrottle`,
  a `SET key value NX EX <window>` -- set-if-absent-with-TTL, the same
  INCR/EXPIRE-adjacent idiom `OtpRateLimiter`/
  `VoucherRedemptionRateLimiter` already establish for a different kind of
  check). This still gives a real, periodic, durable audit trail of who
  viewed which dashboard (the first view of every 15-minute window, per
  user+dashboard+scope, is always recorded) without turning routine
  dashboard polling into unbounded audit-table growth.

**Additive `AuditAction` values, deliberately not added to
`app.domains.rbac.enums.AuditAction`**: this part's directory rule scopes
file changes to `app.domains.analytics` (plus a few named exceptions) --
`app/domains/rbac/enums.py` is explicitly out of scope. `AuditLogEntry
.action` (`app.domains.rbac.models`) is a plain, unconstrained
`String(50)` column, not a native Postgres enum -- a value that is not
also a member of RBAC's own Python-level `AuditAction` registry is stored
and queried identically. `app.domains.analytics.constants` therefore
defines its own local string constants
(`AUDIT_ACTION_DASHBOARD_SUPER_ADMIN_VIEWED`/`_ORGANIZATION_VIEWED`/
`_LOCATION_VIEWED`) written into the exact same shared
`audit_log_entries` table via the same narrow `create_audit_log_entry`
writer protocol every other domain's service already uses -- composition
with RBAC's public storage surface, without editing RBAC's own file.

## 22. Live aggregation vs. snapshot reads -- a quick reference

| Dashboard figure | Source |
|---|---|
| Total organizations/locations/routers, online/offline routers | Live `COUNT`/`GROUP BY` (cheap, small tables) |
| Total/monthly guests, total sessions | Live aggregate (all-time/whole-month figures a daily snapshot alone cannot answer without summing history) |
| Active sessions, peak concurrent sessions | Live -- "right now"/"at this exact moment" has no meaningful snapshot equivalent |
| Organization/location/router/guest/network growth | `AnalyticsSnapshot` history (current vs. N-days-ago snapshot) |
| Organization/Location Summary rollup counts | Latest `ORG_DAILY_SUMMARY`/`LOCATION_DAILY_SUMMARY` snapshot |
| Weekly/monthly visitors | Summed daily snapshots + one live call for today's still-open window (see §19) |
| Auth methods, OTP/voucher stats, captive portal usage, peak hour/day, device/browser/OS, bandwidth/average-session | Live aggregate (none of these are captured in a snapshot's `metrics` shape) |
| Traffic trend (Organization Dashboard) | `ORG_DAILY_SUMMARY` snapshot history, day-over-day |
| Health Score | Live router/alert counts + snapshot-derived growth direction |

---

# BE-012 Part 3: Router + Network + Guest + Authentication Analytics

Everything below extends this same domain -- no new top-level domain, one
new table-column (`guest_sessions.accept_language`, the exact same
conditionally-permitted pattern Part 2 used for `user_agent`). New modules
added to `app.domains.analytics`: `domain_analytics_schemas.py`,
`domain_analytics_service.py`, `router_availability.py` -- plus extensions
to `repository.py`, `dependencies.py`, `router.py`, `constants.py`,
`aggregation.py` (one small shared helper), and `dashboard_aggregation.py`
(new pure computation helpers, plus two functions moved out of
`dashboard_service.py` for reuse -- see §29).

## 23. Bandwidth: from `GuestSession`, never from `RouterHealthSnapshot`

`app.domains.router_provisioning.models.RouterHealthSnapshot` captures only
`health_status`/`cpu_usage_percent`/`memory_usage_percent`/`uptime_seconds`/
`connected_clients_count` -- confirmed by reading the model in full. There
has never been a real MikroTik device in this sandbox to report a byte
counter, and inventing one with no real writer would be exactly the kind of
fabrication this part's honesty mandate forbids.

Every guest session, however, already records which router it connected
through (`GuestSession.router_id`) and how many bytes it moved
(`bytes_uploaded`/`bytes_downloaded`) -- Router Analytics' "Bandwidth" and
Network Analytics' "Download/Upload Usage" are therefore real,
`GROUP BY router_id`/organization-wide `SUM` aggregates over `GuestSession`
(`AnalyticsRepository.get_bandwidth_by_router`/
`get_network_bandwidth_totals`), never a fabricated per-router counter on a
table that has no byte-counter column at all.

## 24. Hotspot Sessions == Guest Sessions (an equivalence, not a new concept)

There is no separate "hotspot session" table or concept anywhere in this
codebase. Every guest WiFi connection *is* a `GuestSession` row -- "Hotspot
Sessions" per router is simply that router's `GuestSession` count within
the window (the same `GROUP BY router_id` query that already produces
bandwidth also produces this count, in one aggregate, not two). This is
documented directly on the response
(`RouterAnalyticsItem.hotspot_sessions_note`) rather than silently implied,
and the same number doubles as "RADIUS Success" per router (see §26).

## 25. Internet Availability: a documented proxy signal, reusing monitoring's own threshold

`Router.status == ONLINE` alone is not a trustworthy "is this router's
internet uplink up right now" signal: nothing in `app.domains.router`
automatically flips an `ONLINE` router to `OFFLINE` purely from a missed
heartbeat -- that only happens the next time `RouterService.heartbeat` (or
an explicit status endpoint) runs. `app.domains.monitoring.constants
.RouterLifecycleStage`'s own module docstring already documents this exact
gap for its own ZTP dashboard, and `app.domains.monitoring.validators
.compute_lifecycle_stage` already resolves it by combining `Router.status`
with `Router.last_seen_at` recency.

`app.domains.analytics.router_availability.compute_internet_availability`
reuses that *exact* resolution, reduced to a plain boolean: `Router.status
== ONLINE` **and** `Router.last_seen_at` is no more than
`app.domains.monitoring.constants.ROUTER_HEARTBEAT_OFFLINE_STALE_MINUTES`
old -- the identical constant `compute_lifecycle_stage` itself already uses
for its own `ONLINE -> OFFLINE` staleness rule, reused directly rather than
re-derived as a second, possibly-inconsistent number. This mirrors
`app.domains.monitoring.service.MonitoringService.check_freeradius_health`/
`check_wireguard_health`'s own documented "proxy signal, not a live daemon
ping" posture -- there is no live internet/uplink probe anywhere in this
sandbox, and none is fabricated here. Network Analytics' "Network
Availability" is a straight platform/org-wide rollup of the same per-router
signal (`available_router_count / total_router_count`).

## 26. Authentication Requests / RADIUS Success / RADIUS Failure: exact scoping

Checked first, per this part's own mandate: does `GuestLoginHistory` carry a
`router_id`? Reading `app.domains.guest.models.GuestLoginHistory` in full
confirms it does **not** -- only `organization_id`/`location_id`. Only
`GuestSession` (created exclusively on a *successful* login or reconnect)
carries `router_id`. This drove an explicit, honest design rather than a
silent approximation:

* **RADIUS Success** (per router) is exact: `GuestSession` count for that
  router within the window (`AnalyticsRepository.get_bandwidth_by_router`'s
  own `session_count` column -- see §24, the same number as "Hotspot
  Sessions", documented as identical rather than coincidental).
* **RADIUS Failure** (per router) is a *location-level proxy*:
  `GuestLoginHistory` failures grouped by `location_id`
  (`AnalyticsRepository.get_login_failure_counts_by_location`), attributed
  to every router at that router's own location. `RouterAnalyticsItem
  .radius_failure_scope_note` states this plainly: at a location with more
  than one router, this number is shared across all of them, not an exact
  per-device figure. This is the precise, honest boundary of what the
  existing schema can answer -- adding a `router_id` column to
  `GuestLoginHistory` would fix this exactly, but this part's directory
  rule (extend `analytics` only, compose with `guest`'s existing public
  interface) does not license that schema change.
* **Authentication Requests Total** (per router) =
  `radius_success_count + radius_failure_count`.

## 27. Guest Retention: exact formula and two-part real/pure split

**Formula**: the percentage of guests seen in the immediately preceding
period (of equal length to the caller's own window) who were *also* seen
again in the current period --

```text
retention_rate_percent = |current_period_guest_ids ∩ previous_period_guest_ids|
                          / |previous_period_guest_ids| * 100
```

`None` (never a fabricated `0.0`) when the previous period had zero guests
-- an undefined ratio, not a real zero, mirroring `compute_growth`'s own
"never divide by zero" discipline.

Mirrors `peak_concurrency.py`'s own "real SQL narrows, pure function
computes" split: `AnalyticsRepository.get_distinct_guest_ids` is a real,
bounded `SELECT DISTINCT GuestSession.guest_id` for one window (two calls,
current and previous period), and `dashboard_aggregation
.compute_guest_retention_rate` is a pure Python set-intersection over those
two already-small id sets -- a mathematical operation over primary keys,
not the "Python-side loop over bulk-fetched business rows" this codebase's
own coding rules warn against.

`tests/unit/test_analytics_router_network_guest_auth.py::test_guest_
analytics_retention_multi_period_fixture` verifies this against a
constructed 4-guest, two-period fixture (3 previous-period guests, 2
retained into the current period plus 1 brand-new guest -> 66.7%
retention).

## 28. Peak Bandwidth: exact formula, and why it is snapshot-bucket-based

**Formula**: the single highest-`total_bandwidth_bytes` bucket among recent
`ORG_DAILY_SUMMARY` `AnalyticsSnapshot` history for the requested window --
one bucket = one already-computed daily rollup's own
`[period_start, period_end)` window and its `total_bandwidth_bytes` value.
`dashboard_aggregation.compute_peak_bandwidth` is a pure `max(..., key=...)`
over already-fetched `(bucket_start, bucket_end, bytes_total)` tuples --
`AnalyticsRepository.list_snapshots` (a method that already existed since
Part 1) supplies the real, bounded SQL fetch, and `domain_analytics_service
.py`'s `_compute_peak_bandwidth_response` reuses the exact same fetched
snapshot list for both Peak Bandwidth *and* Traffic Trend (one query, two
figures).

**This is "bytes transferred within the busiest already-computed bucket,"
never an instantaneous bits-per-second throughput rate.** No such rate
exists anywhere in this codebase's real data -- neither `GuestSession` nor
`RouterHealthSnapshot` records a point-in-time rate, only cumulative byte
counters, so a genuine "peak Mbps" figure cannot be honestly derived from
anything this sandbox has. `PeakBandwidthResponse.formula_note` states this
explicitly on every response. Reported `available: false` (never a
fabricated zero) when no snapshot history exists yet for the window (e.g.
before Celery's aggregation pipeline has ever run for that organization) --
`tests/unit/test_analytics_router_network_guest_auth.py::test_network_
analytics_peak_bandwidth_unavailable_without_snapshots` verifies this.

## 29. Refactor: `build_auth_method_breakdown`/`device_breakdown_response` moved to `dashboard_aggregation.py`

Part 2's `dashboard_service.py` originally defined two private,
underscore-prefixed helpers (`_build_auth_method_breakdown`,
`_device_breakdown_response`) mapping real repository query results into
API response schemas. Part 3's own Guest Analytics (device/browser/OS) and
Authentication Analytics (auth-method breakdown) endpoints needed the
*exact same* mappings -- rather than copy-pasting either function a second
time (this part's explicit "compose, don't duplicate" mandate), both were
promoted to public functions on `dashboard_aggregation.py`
(`build_auth_method_breakdown`/`device_breakdown_response`) and
`dashboard_service.py` was updated to import and call them instead of its
own now-removed private copies. This is a pure, behavior-preserving
refactor -- every one of Part 2's own dashboard tests
(`tests/unit/test_analytics_dashboards.py`) still passes unchanged, since
the two functions' bodies moved verbatim, only their module and visibility
changed.

## 30. Composing with BE-010's own Guest Analytics, not re-deriving it

Checked first, per this part's own "prefer composing" mandate:
`app.domains.guest.service.GuestAnalyticsService` already exposes
`get_summary` (visitors/unique/returning guests, average session duration,
total bandwidth), `get_top_devices`, `get_top_locations`,
`get_otp_success_rate`, and `get_voucher_usage` -- all real, tenant-scoped
SQL aggregates BE-010 Part 4 already built. Guest Analytics
(`GET /analytics/guests`) calls into `get_summary`/`get_top_devices`/
`get_top_locations` directly, through `GuestAnalyticsCompositionProtocol`
(a narrow, duck-typed protocol satisfied by the real service, the identical
composition pattern `aggregation.GuestAnalyticsLookupProtocol` and
`dashboard_service.py`'s own guest-analytics composition already
establish) -- never re-deriving "New Guests"/"Returning Guests"/"Unique
Guests"/"Top Devices"/"Top Locations" with a second, possibly-inconsistent
definition.

`tests/unit/test_analytics_router_network_guest_auth
.py::test_guest_analytics_composes_with_guest_analytics_service` verifies
this with a spy fake (`_FakeGuestAnalyticsService`) that records every call
it receives and asserts `get_summary`/`get_top_devices`/`get_top_locations`
were all actually invoked by `DomainAnalyticsService.get_guest_analytics`.

"New Guests" reuses `aggregation.new_guest_count` -- the exact same
`max(unique_guests - returning_guests, 0)` formula Part 1's own
`compute_org_daily_summary`/`compute_location_daily_summary` already
established for the identical concept, pulled out into its own small,
named, shared function specifically so Part 3 does not re-derive the same
formula inline a second time. "Repeat Visits" is a distinct, real metric
this part adds: `visitors - unique_guests` -- sessions beyond each guest's
*first* visit *within this window* (documented, via
`GuestAnalyticsResponse.repeat_visits_note`, as different from
`returning_guests`, which is guests with a *lifetime*
`total_visit_count > 1`).

"Top Devices"/"OS"/"Browser Statistics" compose with **two** real,
independent sources rather than one: `GuestAnalyticsService.get_top_devices`
(BE-010's own MAC-address-ranked physical device list) for "Top Devices",
and `AnalyticsRepository.get_user_agent_breakdown` -- Part 2's own real
User-Agent classification SQL, extended (see §33) to accept an optional
`location_id` so this organization-scoped endpoint can reuse the identical
classifier organization-wide -- for the OS/browser/device-type breakdown.
Neither is reimplemented a second time.

## 31. Voucher Failure: an honestly partial signal, and why

Checked first, per this part's honesty mandate: is a failed voucher
redemption attempt tracked anywhere queryable? Reading
`app.domains.voucher.service`'s own module docstring ("Audit-volume
judgment call" section) in full confirms: **only** an attempted reuse of an
already-`revoked`/`exhausted` code is written to `audit_log_entries`
(`AuditAction.VOUCHER_REDEMPTION_FAILED`) -- routine failures
(`not_found`/`batch_not_active`/`expired`, a guest presenting an old or
not-yet-live code) are logged via the structured logger only, never
persisted anywhere queryable, by that module's own explicit, pre-existing
design (not something this part changed or could change without touching
`app.domains.voucher`, which this part's directory rule does not permit).

`AnalyticsRepository.get_voucher_redemption_failed_audit_count` therefore
returns a real but **partial** count -- a genuine lower bound on total
voucher failures, not the total. `VoucherAuthStatsResponse
.failure_tracking_note` states this explicitly on every response, mirroring
this part's overall honesty posture: report exactly what is real, and say
so precisely when a real number is known to be incomplete, rather than
implying it is the whole picture. "Voucher Success" (`redeemed_count`), by
contrast, is a complete, real, time-windowed count of `Voucher.redeemed_at`
-- every successful redemption is durably recorded on the `Voucher` row
itself.

## 32. Honest placeholders in this part

Five bullets have no real data source anywhere in this codebase, following
Part 2's exact `available: bool = False` + explanatory `message` shape
(`UnavailableMetricResponse`, this part's one generic, reusable placeholder
schema -- see `domain_analytics_schemas.py`'s own module docstring for why
it is reused instead of four bespoke schemas):

* **Router disk usage/temperature/packet loss/latency** -- confirmed by
  reading `RouterHealthSnapshot` in full: only `health_status`/
  `cpu_usage_percent`/`memory_usage_percent`/`uptime_seconds`/
  `connected_clients_count` exist. No real MikroTik device has ever
  reported anything else in this sandbox.
* **Network "Top Applications"** -- no deep packet inspection /
  application-layer traffic classification exists, or could exist without
  new network infrastructure this part's directory rule does not license
  inventing.
* **Authentication "PMS Login"** -- no Property Management System
  integration exists anywhere in this codebase (confirmed: no `pms`
  domain, no PMS-shaped fields on any existing model).
* **Authentication "Social Login"** -- confirmed by reading
  `app.domains.captive_portal.models.CaptivePortalConfig
  .social_login_enabled`'s own docstring: "a schema-only readiness flag,
  not a working feature." No real OAuth/social-login integration exists or
  is attempted anywhere in this codebase.
* **Country Statistics** (Guest Analytics) -- reuses Part 2's own
  `CountryStatisticsResponse` and exact reasoning verbatim (§17 above): no
  GeoIP database or IP-geolocation service exists anywhere in this sandbox.
  Not re-litigated -- the same honest conclusion Part 2 already reached
  still holds.

## 33. `get_user_agent_breakdown`: `location_id` made optional (additive signature change)

Part 2's original signature required a non-`None` `location_id` (the
Location Dashboard is always location-scoped). Part 3's own organization-
scoped Guest Analytics endpoint needs the *identical* classification query,
organization-wide, with an *optional* `location_id` narrowing filter --
rather than duplicate the entire classifier a second time with a subtly
different signature, `AnalyticsRepositoryProtocol
.get_user_agent_breakdown`'s `location_id` parameter was widened to
`uuid.UUID | None`, and the method body's `GuestSession.location_id ==
location_id` filter became conditional (`if location_id is not None`).
Every existing call site (`dashboard_service.py`'s Location Dashboard)
still always passes a real, non-`None` location, so this is a strictly
additive, backward-compatible widening -- `tests/unit/test_analytics_
dashboards.py`'s existing device-breakdown tests pass unchanged.

## 34. The Accept-Language decision: applying Part 2's exact `user_agent` judgment call

Per this part's explicit brief: apply the *same* judgment call Part 2 made
for `User-Agent` to `Accept-Language` for "Language Statistics", and either
do it for real (if it is an equally narrow, cheap, honest capture) or treat
it as an honest placeholder -- not skip the decision either way.

**Decision: do it for real.** `app.domains.guest.router`'s
`guest_login_via_otp`/`guest_login_via_voucher` endpoints already receive a
`Request` object (used for `ip_address` and, since Part 2, `User-Agent`) --
reading one more header (`Accept-Language`) at the exact same two call
sites is precisely as narrow and cheap as `user_agent` was, and the
identical reasoning applies point-for-point:

* **One new nullable column**: `GuestSession.accept_language` (`Text`,
  nullable) -- the *raw* header value (e.g.
  `"en-US,en;q=0.9,fr;q=0.8"`), never a pre-parsed primary language.
  Storing it raw means a smarter future classifier never needs a backfill
  migration, only a better read-side query -- the exact same "raw value,
  not pre-parsed" reasoning `user_agent` already established.
* **One line at each of the two login call sites**
  (`app/domains/guest/router.py`): `accept_language =
  request.headers.get("accept-language")`, threaded through
  `GuestService.login_via_otp`/`login_via_voucher` (new, default-`None`
  keyword parameters -- every existing caller/test that omits it behaves
  exactly as before) into `_create_session`. `reconnect` also carries a
  prior session's `accept_language` forward onto its derived new session,
  mirroring `user_agent`'s identical "copy forward" discipline.
* **One migration**:
  `alembic/versions/0020_add_accept_language_to_guest_sessions.py` -- a
  single `ALTER TABLE guest_sessions ADD COLUMN accept_language TEXT
  NULL`, no index (same reasoning as `user_agent`'s own migration: never
  filtered/joined on, only classified via SQL at read time). No
  `alembic/env.py` change was needed -- `app.domains.guest.models` was
  already imported there since Part 2.

**Classification, at read time, real SQL**:
`AnalyticsRepository.get_language_breakdown` extracts the primary language
tag from the RFC 7231 `Accept-Language` header shape (a comma-separated,
quality-weighted list, most-preferred-first) via
`split_part(split_part(accept_language, ',', 1), ';', 1)`, trimmed --
`"en-US;q=0.9,fr;q=0.8"` -> `"en-US;q=0.9"` -> `"en-US"` -- then
`GROUP BY`/`COUNT`, mirroring `get_user_agent_breakdown`'s identical
"classify via real SQL at read time, never a Python-side parsing loop"
discipline, and its identical honest-coverage shape
(`sessions_total`/`sessions_with_data`).

**Files touched inside `app.domains.guest`, exhaustively**: `models.py`
(the one column), `router.py` (two one-line header captures at the two
existing login endpoints), `service.py` (a new, default-`None` keyword
parameter threaded through `login_via_otp`/`login_via_voucher`/
`_create_session`/`reconnect`). Nothing else in that domain was touched --
identical scope to `user_agent`'s own Part 2 change.

---

# BE-012 Part 4: Business Analytics + Forecast/Insight/Trend Engines

Everything below extends this same domain -- no new top-level domain, no
schema migration (see §46). New modules: `trends.py` (the Trend Engine),
`forecast.py` (the Forecast Engine's pure math), `insights.py` (the Insight
Engine's pure rule functions), `business_schemas.py`/`business_service.py`
(Business Analytics), `forecast_schemas.py`/`forecast_service.py` (Forecast
Engine composition), `insight_schemas.py`/`insight_service.py` (Insight
Engine composition) -- plus extensions to `repository.py` (7 new read-only
queries), `constants.py` (4 new audit actions), `dependencies.py` (3 new
factories), `router.py` (8 new endpoints), and `app/core/config.py` (22 new
`Settings` fields for every Forecast/Insight threshold), plus a pure,
behavior-preserving de-duplication refactor of two Part 2/3 methods (§40).

## 35. The two honesty investigations this part opens with

Per the module brief's own explicit instruction, two things were confirmed
(not assumed) before writing a line of business logic:

1. **No billing/subscription/payment domain exists.** Confirmed again (the
   same conclusion Parts 2/3 already reached and this part does not
   re-litigate): `app.domains.organization.models.Organization
   .subscription_tier` is a lightweight, nullable `String(50)` label with
   zero pricing/entitlement logic anywhere behind it (its own module
   docstring states this explicitly), and no `billing`/`invoices`/
   `subscriptions` domain exists in this codebase at all --
   `PermissionModule.BILLING`/`INVOICES`/`SUBSCRIPTIONS` are seeded RBAC
   permission keys with **no domain behind them yet** (reserved for a future
   module). Revenue Trends/Subscription Trends/Churn Rate/Renewal
   Rate/License Utilization therefore have zero underlying events (no
   subscription-created/cancelled/renewed timestamp, no invoice amount)
   anywhere to compute from.
2. **No AI/ML/LLM provider exists, and none is added.** Confirmed by
   inspection: no OpenAI/Anthropic/Ollama/any-LLM client library import
   anywhere in `requirements.txt`/`requirements-dev.txt`, no API key
   `Settings` field, no mocked "AI response" anywhere. The module brief's
   own instruction ("Reuse existing AI Platform Services. Do NOT implement
   AI providers") is honored literally: every "AI-Ready Analytics" figure
   (Capacity/Bandwidth/Router-Failure/Guest-Growth/Network-Load Prediction,
   Traffic Forecast, Business Insights, Operational Recommendations) is
   implemented with real, classical, deterministic statistics/rule logic
   over already-real `AnalyticsSnapshot`/`RouterHealthSnapshot`/`Alert`
   history -- ordinary least-squares linear regression and a plain rule
   engine, both pure-stdlib Python, no `numpy`/`scipy`/ML dependency added.

## 36. The Trend Engine: one implementation, not three copies

`trends.py` is this part's answer to the module brief's own instruction:
"expose a general-purpose 'trend for metric X over period Y' query usable by
both the Forecast and Insight engines and by the dashboard endpoints, so
trend computation has one implementation, not three copies across this part
and Parts 2-3." Before writing it, what already existed was checked:
`dashboard_aggregation.py` (Part 2) already owns the two-point comparison
primitive (`compute_growth`) and whole-window summation helpers -- reused
directly, never reimplemented. What was missing, and is new in `trends.py`:

* `extract_metric_series` -- turns a list of `AnalyticsSnapshot`-shaped rows
  into a plain, chronologically-sorted `[TrendPoint(timestamp, value), ...]`
  series for one `metrics` key. Neither Part 2 nor Part 3 ever needed a full
  numeric series before (they only ever compared two points or summed a
  whole window) -- the Forecast Engine's regression fit and the Insight
  Engine's rule inputs both need exactly this shape.
* `growth_point_response` -- the ONE shared `compute_growth` ->
  `GrowthPointResponse` mapping. `dashboard_service.py` (Part 2) and
  `domain_analytics_service.py` (Part 3) each independently defined a
  private, byte-for-byte-identical `_growth_response(metric, current,
  previous)` wrapper. Both were refactored (this part) to import this one
  public function instead of their own private copy -- see §40 for the full
  write-up of why this refactor is safe and behavior-preserving.
* `build_growth_trend` -- the ONE shared day-over-day trend builder.
  `dashboard_service._compute_org_traffic_trend` and
  `domain_analytics_service._compute_traffic_trend` each independently
  looped over an ordered snapshot list building a day-over-day
  `GrowthPointResponse` series for `total_bandwidth_bytes`. Both were
  refactored to call this one function, parameterized by `metric_key` (not
  bandwidth-specific).
* `compute_snapshot_metric_growth` -- a genuinely NEW capability (not a
  refactor): fetches the latest snapshot of one `snapshot_type`/scope plus
  the closest snapshot at least `lookback_days` earlier, and returns a real
  `GrowthPointResponse` for one metric. See §37 for why this is not
  retrofitted into Part 2's own multi-metric-per-fetch methods.
* `count_trailing_consecutive_increases` -- a small, general "has this
  been rising for N readings in a row" numeric-series check, used by the
  Insight Engine's rising-router-CPU rule (§42).

## 37. Why `compute_snapshot_metric_growth` is new code, not a Part 2 refactor

`DashboardService._compute_platform_growth` fetches **one** current/previous
`PLATFORM_DAILY_SUMMARY` snapshot pair and derives **five** growth figures
from it in a single round trip -- an intentional, already-tested
optimization. `compute_snapshot_metric_growth` fetches current/previous for
**one** metric at a time. Refactoring `_compute_platform_growth` (or
`_compute_health_score`'s own single-metric guest-growth fetch) to call this
new function would trade one efficient multi-metric round trip for several
redundant ones, for zero behavior change and non-trivial regression risk to
already-passing Part 2 tests, for no benefit (this part's own callers --
`BusinessAnalyticsService`'s Customer Growth, `InsightService`'s
Customer/Guest Growth insight rules -- each only need one metric's growth at
a time, so the inefficiency the multi-metric fetch avoids does not apply to
them). Part 2's own two call sites are therefore deliberately left
unchanged; only `trends.py`'s own new callers use this new function.

## 38. Forecast Engine: the exact linear-regression method

`forecast.fit_linear_trend` is a real ordinary-least-squares (OLS) fit of
`y = slope * x + intercept` over `(x, y)` pairs, implemented directly (no
`numpy`/`scipy` -- a single-variable OLS closed-form solution is ~20 lines
of pure Python):

```text
slope     = (n * sum(xy) - sum(x) * sum(y)) / (n * sum(x^2) - sum(x)^2)
intercept = (sum(y) - slope * sum(x)) / n
r_squared = 1 - SS_res / SS_tot   (SS_tot == 0 -> r_squared = 1.0)
```

`x` is always a day-offset (`float`, days since the series' first
observation), so `slope` is directly "units per day". `r_squared` is the
REAL coefficient of determination of *this exact fit against this exact
data* -- the ONLY "confidence"-shaped number this module ever reports, and
it is mathematically guaranteed to be within `[0, 1]` for an OLS fit
evaluated against its own training data (never invented, never a fabricated
"N% confidence"). `fit_linear_trend` returns `None` (never a degenerate fit)
for fewer than 2 points, or when every `x` is identical (no time
separation to fit a slope against).

`forecast_linear_series` wraps this over a real `TrendPoint` series (fed by
`ForecastService`'s real `AnalyticsSnapshot` history fetch, via
`trends.extract_metric_series`), projecting `forecast_days` daily points
beyond the last real observation. `available=False` (never a fabricated
projection) when fewer than `Settings.analytics_forecast_min_history_points`
(default 3) real points exist. Verified in
`tests/unit/test_analytics_forecast_insights.py::test_forecast_linear_
series_projects_exactly_for_a_perfectly_linear_series` against a
hand-computed perfectly-linear series (slope=10, intercept=10, R^2=1.0,
projected values computed by hand and asserted exactly).

**Honest limitation, stated on every response** (`LinearFitInfo.note`):
this is a linear projection of a recent trend continuing unchanged; it does
not and cannot account for seasonality, one-off events, or any factor
outside the metric's own recent history. Every forecast response carries
both the real historical points the fit was computed from and the projected
points, so a caller can always see exactly what was extrapolated from --
never a bare number with no traceable basis.

## 39. Forecast endpoint consolidation: five endpoints, not six

The module brief lists six forecast concepts. **Traffic Forecast and
Bandwidth Forecast are folded into one endpoint**
(`GET /analytics/forecast/bandwidth`): this codebase has exactly one real
per-day network-volume metric in `AnalyticsSnapshot` history
(`total_bandwidth_bytes`) -- there is no separate "traffic" metric (packet
count, request count, ...) anywhere in this codebase's real data to
forecast independently, so a second, identically-computed endpoint under a
different name would be pure duplication. Network Load Prediction is kept
as its own, genuinely distinct endpoint
(`GET /analytics/forecast/network-load`, `session_count_total` -- concurrent
guest-session volume) since it answers a materially different operational
question ("how many simultaneous guests" vs. "how much data"). Final five:
`/analytics/forecast/bandwidth`, `/capacity`, `/router-failure-risk`,
`/guest-growth`, `/network-load`.

## 40. Router Failure Risk: an honest heuristic risk FLAG, not a predictive model

**Explicitly NOT machine learning.** No failure-prediction model exists in
this codebase, and none is fabricated here -- a false-precision "87% failure
probability" style number would be exactly the kind of invented confidence
this part's honesty mandate forbids. `forecast.assess_router_failure_risk`
is instead a real, multi-signal heuristic: a router is flagged
`at_risk=True` if and only if at least one of three independently computed,
real, cited signals fires:

1. **Rising CPU/memory usage** -- a real OLS fit (`fit_linear_trend`, the
   exact same function every other forecast in this module uses) over the
   router's own recent `RouterHealthSnapshot.cpu_usage_percent`/
   `memory_usage_percent` history (`Settings.analytics_forecast_router_
   health_lookback_days`, default 14 days). Fires when the fitted slope
   exceeds `Settings.analytics_forecast_router_cpu_rising_slope_threshold`/
   `..._memory_rising_slope_threshold` (default 1.0 percentage-point/day
   each). Requires at least `Settings.analytics_forecast_min_history_points`
   (default 3) real readings -- no signal is computed from too little data.
2. **Degrading health status** -- `RouterHealthSnapshot.health_status` is
   categorical (`"healthy"`/`"unhealthy"`/`None`), not numeric, so a literal
   regression slope cannot be fit to it. "A sustained negative trend" is
   therefore operationalized as the *ratio* of recent readings reporting
   `"unhealthy"` meeting
   `Settings.analytics_forecast_router_unhealthy_ratio_threshold` (default
   0.3) -- an honest, real, categorical-appropriate alternative to a
   numeric slope, documented explicitly as such (never silently presented as
   equivalent to the CPU/memory regression signals).
3. **Repeated Alerts** -- a real `GROUP BY Alert.router_id` count
   (`AnalyticsRepository.get_alert_counts_by_router` -- `Alert.router_id` is
   a real, populated FK, confirmed by reading `app.domains.monitoring.models
   .Alert` in full) within
   `Settings.analytics_forecast_router_alert_lookback_days` (default 7
   days), fired at/above `Settings.analytics_forecast_router_alert_count_
   threshold` (default 2).

Every signal that fires reports the exact real number behind it (the fitted
slope and its own real R^2, the real unhealthy-reading ratio, the real
alert count) on the response itself -- never a synthesized single risk
score. `RouterFailureRiskResponse.heuristic_note` states this posture
explicitly on every response. Verified in
`tests/unit/test_analytics_forecast_insights.py` for each signal firing
independently and for the "everything flat and healthy" no-fire case.

## 41. Capacity Prediction: the exact threshold-crossing formula

`forecast.project_upward_threshold_crossing` answers "when will this metric
first reach/exceed `threshold`, given its current real linear trend" --
deliberately an *upward*-crossing question only (the natural framing for
"when will this resource exceed its capacity ceiling"), which keeps the
math unambiguous:

* `current_value >= threshold` -> already crossed, `days_until_crossing=0`.
* `slope <= 0` (flat or declining) and not already crossed -> `available:
  false` ("will not be reached at the current rate" -- never a fabricated
  future date for a trend moving the wrong direction).
* Otherwise: solve the real OLS line for the `x` where it equals
  `threshold` (`x_star = (threshold - intercept) / slope`), and report
  `ceil(x_star - last_x)` days from the most recent real observation.

Capacity Prediction (`GET /analytics/forecast/capacity`) applies this to an
organization's own `router_count_total` history (from `ORG_DAILY_SUMMARY`/
`LOCATION_DAILY_SUMMARY` snapshots -- a resource every organization already
has real history for) against
`Settings.analytics_forecast_capacity_router_count_threshold` (default 50).
**This threshold is an operator-set planning assumption, not data derived
from any real infrastructure-capacity record** -- no such record exists
anywhere in this codebase, and `ThresholdCrossingInfo.threshold_note` states
this on every response. Verified against a hand-computed series (slope=10,
intercept=10, current value 40, threshold 100 -> exactly 6 days).

## 42. Insight Engine: the exact rule set and every threshold's home in `Settings`

`insights.py` is a real, deterministic RULE ENGINE -- plain Python functions,
real numbers in, either an `Insight` (message + severity) or `None` out. No
LLM call, no generated free text beyond simple, deterministic string
formatting of real numbers against real, configured thresholds. "AI-ready"
only in the sense the module brief itself uses the term: a real LLM
integration could later enhance/replace this text generation -- it does not
claim to already BE one.

**Business Insights** (`GET /analytics/insights/business`):

| Rule | Fires when | Threshold(s) (in `Settings`) |
|---|---|---|
| `customer_growth` | Platform organization-count growth (7-day lookback, `DEFAULT_GROWTH_LOOKBACK_DAYS`) has \|delta_percent\| at/above threshold | `analytics_insight_customer_growth_significant_percent` (10.0) |
| `guest_growth` | Platform unique-guest-count growth (same lookback) has \|delta_percent\| at/above threshold | `analytics_insight_guest_growth_significant_percent` (15.0) |
| `plan_distribution_coverage` | % of organizations with a populated `subscription_tier` is below threshold | `analytics_insight_plan_distribution_min_coverage_percent` (50.0) |

**Operational Recommendations** (`GET /analytics/insights/operational`):

| Rule | Fires when | Threshold(s) (in `Settings`) |
|---|---|---|
| `offline_routers` | An organization has >= N routers with `status=OFFLINE` and a stale heartbeat for over H hours | `analytics_insight_offline_router_count_threshold` (1, WARNING) / `..._critical_count_threshold` (3, escalates to CRITICAL) / `..._offline_router_hours_threshold` (24) |
| `location_guest_volume_drop` | A location's `session_count_total` dropped >= P% vs. the immediately preceding period of equal length | `analytics_insight_location_volume_drop_percent` (20.0), window `analytics_insight_location_volume_lookback_days` (7) |
| `rising_router_cpu` | A router's `cpu_usage_percent` rose on >= N consecutive trailing readings | `analytics_insight_router_cpu_consecutive_threshold` (3), lookback `analytics_insight_router_cpu_lookback_days` (7) |
| `persistent_critical_alerts` | An organization has >= N CRITICAL alerts open (non-`RESOLVED`) for over H hours | `analytics_insight_critical_alert_count_threshold` (2), `analytics_insight_critical_alert_age_hours_threshold` (24) |

Every rule is exercised in
`tests/unit/test_analytics_forecast_insights.py` for BOTH outcomes -- a
constructed input that fires, and one at/below the threshold that does not.

### Why "3 organizations have had 2+ CRITICAL alerts..." becomes N separate insights

The module brief's own illustrative phrasing rolls this rule up into one
platform-wide sentence. This engine instead emits **one insight per
qualifying organization** (`rule_persistent_critical_alerts` called once per
organization meeting the threshold) -- the same one-item-per-qualifying-
entity shape every other Operational Recommendation rule already uses. This
is a deliberate consistency choice: every rule produces one addressable,
per-entity finding, never a mix of aggregate-sentence rules and per-entity
rules that would need different downstream handling.

## 43. Business Analytics: what is real, and the exact honest-placeholder shape

`GET /analytics/business` -- two figures are real:

* **Customer Growth** -- `PLATFORM_DAILY_SUMMARY.organization_count_total`
  history, via `trends.compute_snapshot_metric_growth` (composing Part 2's
  own `compute_growth`, never reimplemented).
* **Plan Distribution** -- a real `GROUP BY Organization.subscription_tier`
  query (`AnalyticsRepository.count_organizations_by_subscription_tier`),
  reporting whatever the actual distribution is, including a real, unmasked
  count of `NULL` (`"unset"`). This part does not skip the query just
  because `subscription_tier` is known (per Module 005's own documented
  decision, and Part 2's own confirmation) to be almost entirely
  unpopulated in this codebase's real data paths -- the real distribution
  (however unimpressive) is still reported honestly, never silently omitted.

Revenue Trends / Subscription Trends / Churn Rate / Renewal Rate / License
Utilization mirror `dashboard_schemas.RevenueMetricsResponse`'s exact
honesty posture (`available: bool`, every numeric field `None`, an
explanatory `message`) but are their OWN schemas, not a verbatim reuse of
`RevenueMetricsResponse`, since the fields genuinely differ in shape:
Revenue Trends/Subscription Trends are inherently **time series**, so they
mirror `CountryStatisticsResponse.by_country`'s "unavailable list" shape
instead (`trend: list[...] = []`); Churn/Renewal/License Utilization are
naturally **scalar** percentages, so they reuse `RevenueMetricsResponse`'s
scalar shape most directly. Every message states plainly why: no billing/
subscription/payment domain, and (for Subscription Trends specifically) no
historical snapshot of `subscription_tier` distribution over time exists
either (`AnalyticsSnapshot` never captured a per-tier breakdown) -- only the
current-moment distribution is real.

## 44. Scope design: GLOBAL for platform-wide views, ORGANIZATION for per-tenant forecasts

Business Analytics and both Insight Engine endpoints are gated
`RequirePermission("analytics.read", scope=ScopeType.GLOBAL)` plus
`DashboardScope.require_global()` -- the same two-layer pattern Part 2's own
Super Admin Dashboard already establishes. This mirrors what each figure
actually IS: Customer Growth/Plan Distribution are platform-wide,
cross-tenant concepts (an organization does not have "customers" of its own
in this codebase's model -- organizations themselves are CloudGuest's
customers), and both Insight Engine rule families are, by design,
platform-wide sweeps (the module brief's own illustrative examples name
multiple organizations/locations at once). Forecast Engine endpoints, by
contrast, are per-organization operational concepts (this organization's own
bandwidth/guest-count/session-count/router-count/router-health trend) --
gated exactly like Part 3's own domain analytics endpoints:
`RequirePermission("analytics.read", scope=ScopeType.ORGANIZATION)` plus
`DashboardScope.require_organization()`.

## 45. Dashboard-view auditing: the same throttle mechanism, reused

Every new endpoint reuses `dashboard_audit.DashboardAuditThrottle` (Part 2's
own Redis-backed, once-per-`(user, dashboard_kind, scope)`-per-15-minutes
dedup) unchanged -- four new local `AUDIT_ACTION_*` string constants
(`constants.py`) are the only addition, following the identical "not added
to `app.domains.rbac.enums.AuditAction`, this part's directory rule scopes
changes to `app.domains.analytics`" posture Parts 2/3 already established.

## 46. Migration: none needed

This part is pure read/computation over already-existing data --
`AnalyticsSnapshot` (Part 1), `RouterHealthSnapshot`/`Alert` (already
existed, only new read-only queries added), `Organization.subscription_tier`
(already existed, unpopulated). No new table, no new column, no schema
change of any kind. `alembic/versions/` is untouched by this part.
