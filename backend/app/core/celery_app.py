"""The Celery application instance for CloudGuest's background task queue
(BE-012 Part 1: Analytics Core Infrastructure).

No Celery deployment existed anywhere in this codebase before this module --
confirmed absent in BE-011, which correctly left ``HealthComponent.CELERY``'s
health check as an honest ``UNKNOWN`` ("ready to wire in once one does" --
see ``app.domains.monitoring.service.check_celery_health``). Analytics
aggregation over potentially millions of guest sessions/routers cannot run
synchronously inside a request/response cycle, so this is the part where
Celery becomes genuinely necessary, real infrastructure -- not a fake
integration standing in for one.

## Broker/backend: reuse ``Settings.redis_url``, no new config knob

Redis is already configured and deployed for this codebase's own async
cache/pub-sub use (``app.database.redis.redis_client``, RBAC's
``PermissionCache``, the monitoring domain's real-time pub/sub channel).
Celery's Redis transport (the ``celery[redis]`` extra, which pulls in
``kombu``'s Redis transport support) needs nothing beyond the ``redis``
package this codebase already depends on -- no second Redis client library,
no second connection URL setting. Both Celery's broker *and* its result
backend point at the exact same ``Settings.redis_url`` the rest of the app
already uses, via a different logical Redis *database index* is not even
needed: Celery namespaces its own keys/queues distinctly from this
codebase's own cache keys and pub/sub channel, so sharing one Redis
instance (and even one logical DB) is safe. Do not add a
``celery_broker_url``/``celery_result_backend`` setting -- that would be a
second, driftable knob for a single, already-configured piece of
infrastructure.

## Serialization: JSON only, never pickle

Celery's classic default (pickle) can execute arbitrary code on
deserialization if a task payload is ever tampered with or a compromised
producer publishes malicious data -- a real security liability for a task
queue whose broker (Redis) has no built-in message-level authentication.
This app instance is configured for JSON-only serialization
(``task_serializer``/``result_serializer``/``accept_content``), the
standard, secure default recommended by Celery's own security
documentation. Every task in ``app.domains.analytics.tasks`` only ever
passes primitives (str/int/None) as arguments/results, so JSON is not just
safer but sufficient.

## Beat schedule: two cadences for two different needs

* **Every 15 minutes** (``analytics-rolling-today``): recomputes each
  active organization's/location's/the platform's snapshot for *today so
  far* (a partial-day window from UTC midnight to "now"). This is what
  gives a dashboard near-real-time numbers without querying millions of raw
  ``GuestSession``/``Router`` rows on every page load -- a snapshot from up
  to 15 minutes ago is a reasonable near-real-time freshness bound for an
  operational dashboard (not a stock ticker), and re-running the same
  computation on a schedule cadence this short is cheap because it is a set
  of indexed ``GROUP BY``/``COUNT`` aggregate queries, not a full-table
  scan.
* **Once daily, 00:10 UTC** (``analytics-finalize-yesterday``): computes the
  *final*, immutable snapshot for the full previous UTC calendar day, once
  that day has definitively closed. Ten minutes past midnight gives any
  slightly-delayed writes for the tail end of the previous day (e.g. a
  guest session's ``ended_at`` being persisted a few seconds after
  midnight) time to land before the "final" snapshot for that day is
  computed and persisted -- this is the authoritative row later parts'
  historical trend/reporting views should read for "yesterday's numbers",
  distinct from the rolling snapshot's explicitly-partial "today so far"
  row for the same ``(organization_id, snapshot_type)`` pair (they differ
  by ``period_start``/``period_end``, so both can coexist without
  conflicting).

Both schedule entries call the exact same Beat-scheduled task
(``app.domains.analytics.tasks.run_daily_aggregation_for_all_organizations``),
parameterized only by which day to compute -- see that task's own docstring.

**BE-012 Part 5 adds a third cadence, hourly** (``reports-run-scheduled``):
checks for due ``ScheduledReport`` rows and generates/renders/emails each
one. See ``app.domains.analytics.report_tasks``'s own module docstring for
why hourly (not every 15 minutes) is the right granularity for a task whose
own coarsest supported frequency is daily, and for its per-schedule
failure-isolation contract (mirroring this same module's own
per-organization isolation for the two tasks above).

## The async-in-a-sync-worker bridge

Celery workers execute task bodies as plain, synchronous Python callables
(by default, in a worker process/thread with no running ``asyncio`` event
loop) -- but this entire codebase's repository/service layer is
``AsyncSession``-based. Every task in ``app.domains.analytics.tasks`` bridges
this with the standard, real pattern: each task's sync body calls
``asyncio.run(...)`` around a small async function that opens a fresh
``AsyncSession`` (via ``app.database.session.SessionLocal``), builds the
real repository/service objects, awaits the actual aggregation work, and
commits before returning -- exactly as if it were a one-shot async script.
``asyncio.run`` is safe here specifically because a Celery worker task body
is never itself already running inside an event loop (unlike, say, calling
it from within an already-async FastAPI request handler, where nesting
``asyncio.run`` would raise). See ``app.domains.analytics.tasks`` for the
full, concrete implementation and ``docs/analytics/FLOW.md`` for the
end-to-end write-up.
"""

from __future__ import annotations

from typing import Any

from celery import Celery
from celery.schedules import crontab

from app.core.config import get_settings
from app.domains.analytics.constants import (
    SCHEDULED_REPORTS_CHECK_INTERVAL_SECONDS,
    TASK_RUN_DAILY_AGGREGATION_FOR_ALL_ORGANIZATIONS,
    TASK_RUN_SCHEDULED_REPORTS,
)
from app.domains.billing.constants import (
    SUBSCRIPTION_RENEWAL_SWEEP_INTERVAL_SECONDS,
    TASK_RUN_SUBSCRIPTION_RENEWAL_SWEEP,
)

_settings = get_settings()

# Bound on how long `ping_celery_workers` (below) waits for a worker to
# reply to `control.inspect().ping()` before concluding "no worker
# responded" -- mirrors `Settings.redis_health_timeout_seconds`'s identical
# "bounded health-check round trip" reasoning for the existing Redis PING
# health check. Deliberately a plain module constant, not a new `Settings`
# field -- this app instance's own directory rule keeps
# `app/core/config.py` untouched for this part.
CELERY_HEALTH_CHECK_TIMEOUT_SECONDS = 2.0

celery_app = Celery(
    "cloudguest",
    # Same Redis instance/URL every other part of this codebase already
    # uses (app.database.redis, RBAC's PermissionCache) -- see module
    # docstring's "no new config knob" write-up.
    broker=str(_settings.redis_url),
    backend=str(_settings.redis_url),
    # Tasks are defined in app.domains.analytics.tasks/report_tasks;
    # imported eagerly by a real worker process
    # (`celery -A app.core.celery_app worker`) so they are registered
    # without a caller needing to import either module first.
    include=[
        "app.domains.analytics.tasks",
        "app.domains.analytics.report_tasks",
        "app.domains.billing.tasks",
    ],
)

celery_app.conf.update(
    # JSON-only serialization -- see module docstring's security write-up.
    # Never pickle.
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    # Surfaces a task's STARTED state (not just PENDING -> SUCCESS/FAILURE)
    # in the result backend -- useful for a future admin view of long-
    # running aggregation jobs; costs nothing when unused.
    task_track_started=True,
    # A single organization's aggregation should never be allowed to hang
    # indefinitely and block the worker pool from picking up the next
    # scheduled run -- a generous, but finite, ceiling.
    task_time_limit=600,
    task_soft_time_limit=540,
    beat_schedule={
        "analytics-rolling-today": {
            "task": TASK_RUN_DAILY_AGGREGATION_FOR_ALL_ORGANIZATIONS,
            "schedule": 900.0,  # every 15 minutes, in seconds
            "kwargs": {"target_date_iso": None},
        },
        "analytics-finalize-yesterday": {
            "task": TASK_RUN_DAILY_AGGREGATION_FOR_ALL_ORGANIZATIONS,
            "schedule": crontab(hour=0, minute=10),
            "kwargs": {"days_ago": 1},
        },
        # BE-012 Part 5: Report Engine scheduler -- hourly, not every 15
        # minutes like the rolling aggregation tick above. See
        # ``app.domains.analytics.report_tasks``'s own module docstring for
        # why hourly is the right granularity for a task whose own
        # coarsest supported ``ScheduledReport.frequency`` is `daily`, and
        # for the per-schedule failure-isolation contract mirroring
        # ``run_daily_aggregation_for_all_organizations``'s own
        # per-organization isolation.
        "reports-run-scheduled": {
            "task": TASK_RUN_SCHEDULED_REPORTS,
            "schedule": SCHEDULED_REPORTS_CHECK_INTERVAL_SECONDS,
        },
        # BE-013 Part 2: Renewal Engine sweep -- hourly, not every 15
        # minutes like the analytics rolling tick above. See
        # ``app.domains.billing.constants
        # .SUBSCRIPTION_RENEWAL_SWEEP_INTERVAL_SECONDS``'s own docstring for
        # why hourly is the right granularity for a domain whose billing
        # periods are day/month/year granularity, and
        # ``app.domains.billing.renewal_service.RenewalService
        # .run_renewal_sweep``'s own docstring for its per-phase and
        # per-subscription failure-isolation contract, mirroring
        # ``run_daily_aggregation_for_all_organizations``'s own
        # per-organization isolation.
        "billing-subscription-renewal-sweep": {
            "task": TASK_RUN_SUBSCRIPTION_RENEWAL_SWEEP,
            "schedule": SUBSCRIPTION_RENEWAL_SWEEP_INTERVAL_SECONDS,
        },
    },
)


def ping_celery_workers(
    timeout: float = CELERY_HEALTH_CHECK_TIMEOUT_SECONDS,
) -> dict[str, Any] | None:
    """A real, synchronous, bounded ``control.inspect().ping()`` against
    whatever real Celery worker(s) may be listening on this app's broker --
    the mechanism ``app.domains.monitoring.service.check_celery_health``
    (BE-011 Part 1's honest ``UNKNOWN`` health check, wired for real by this
    part) calls through ``asyncio.to_thread`` (this is a blocking network
    call, never awaited directly). Returns a ``{worker_name: {"ok": "pong"}}``
    mapping when at least one worker replies within ``timeout``, or
    ``None`` when the broker was reachable but zero workers responded in
    time. Raises (e.g. a broker connection error) when the broker itself
    could not be reached at all -- the caller distinguishes "broker
    unreachable" (raises) from "broker reachable, no workers" (returns
    ``None``) as two different severities; see ``check_celery_health``'s own
    docstring for exactly how each maps to a ``HealthStatus``.

    Kept here, not inlined into ``check_celery_health``, so it is a plain,
    module-level function callers -- including this codebase's own test
    suite -- can monkeypatch/replace without needing a live broker or
    worker, mirroring how ``app.domains.monitoring.service``'s own
    ``check_database_health``/``check_redis_health`` are exercised against
    fakes rather than a real Postgres/Redis in every unit test.
    """
    return celery_app.control.inspect(timeout=timeout).ping()


__all__ = ["celery_app", "ping_celery_workers", "CELERY_HEALTH_CHECK_TIMEOUT_SECONDS"]
