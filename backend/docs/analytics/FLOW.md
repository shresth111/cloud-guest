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
