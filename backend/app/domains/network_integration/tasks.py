"""Celery Beat task for the Network Integration domain's controller sync sweep.

Bridges the async ``service.run_network_integration_sync_sweep`` into a
sync Celery task body exactly the way
``app.domains.isp.tasks.run_isp_health_check_sweep`` and
``app.domains.guest.tasks.run_session_timeout_sweep`` do: a fresh
``AsyncSession`` (via ``app.database.session.SessionLocal``, never the
FastAPI ``Depends`` machinery, which has no meaning inside a Celery
worker), the real repository/service objects built by hand, the sweep
awaited via this codebase's own ``run_celery_task`` bridge, then
committed.

## There is no webhook, and there never will be for this

Stating it rather than leaving a ``TODO``, because "poll every five
minutes" invites the reasonable question "why not just subscribe".

Omada's controller API -- both generations -- offers no outbound
notification of any kind that this platform could subscribe to. Not for
device state, not for client association, not for portal authorization
expiry. The controller's own alerting emails a human or writes a syslog
line; neither is a machine-consumable event stream, and neither can be
pointed at a per-tenant HTTPS endpoint. There is no callback URL to
register.

So polling is not a first pass to be replaced later. It is the only
mechanism the vendor exposes, and the design consequences are permanent:
every number this domain caches is as fresh as the last successful poll
and no fresher, which is why ``last_sync_at`` is returned alongside every
count instead of being left for a reader to assume.

## Why the Beat cadence is not the sync interval

Beat fires this every 60 seconds
(``NETWORK_INTEGRATION_SYNC_SWEEP_INTERVAL_SECONDS``). That is the *tick*,
not the period. Each integration carries its own
``sync_interval_seconds``, and a single Beat entry cannot express "each
row has its own period" -- so the tick is the greatest common divisor of
the allowed intervals (which is the 60s floor) and the per-row decision is
made in SQL plus one Python re-check. Same arrangement
``app.domains.notification.tasks`` already uses.

The re-check exists because the backoff multiplier lives in
``provider_metadata`` (JSONB), which Postgres cannot index usefully for
this comparison. ``repository.list_due_for_sync`` therefore selects on the
*base* interval and ``service.is_sync_due`` filters the rest. That means
the sweep can fetch rows it then skips -- bounded by
``SYNC_SWEEP_MAX_INTEGRATIONS_PER_RUN`` and cheap -- and the summary's
``skipped_backoff`` counter is where that shows up. The alternative, a
denormalized ``next_sync_due_at`` column, is a value that can go stale
against the row it describes; a slightly over-eager query cannot.

## Failure isolation is per integration, and the task does not raise

One tenant's unreachable controller must not abort the sweep for every
other tenant, so each integration is wrapped individually inside
``run_network_integration_sync_sweep``. The task returns counts; a
failure surfaces as an ``error`` in the summary, a ``last_error_*`` on the
row and an event row in the tenant's own feed -- not as a Celery
traceback, which nobody reads per-tenant.

Backoff on consecutive failures is capped
(``SYNC_BACKOFF_CAP_MULTIPLIER``, 32x) rather than unbounded, so a
controller that comes back after a long outage is noticed within hours.
An uncapped exponential eventually means "we stopped checking", which is
indistinguishable from a bug.

## Queue placement

Registered on ``DEVICE_IO_QUEUE_NAME`` in ``app.core.celery_app``. Every
tick issues real HTTPS round trips to customer-owned hardware over the
public internet, which is exactly what that queue exists to keep off the
default queue shared by the cheap pure-DB sweeps -- see
``TASK_RUN_ISP_HEALTH_CHECK_SWEEP``'s own note there.

## Never polls a disabled or soft-deleted integration

Enforced in the SQL (``repository.list_due_for_sync`` puts
``is_enabled = true`` and ``is_deleted = false`` in the WHERE clause, not
in a Python filter afterwards) and re-asserted in
``service.is_sync_due``. This is the one code path in the domain that runs
with no user in the request, so there is nothing else standing between it
and a tenant's controller -- a disabled integration must be unreachable
here by construction, not by a caller remembering to check.
"""

from __future__ import annotations

import logging

from app.core.async_task_bridge import run_celery_task
from app.core.celery_app import celery_app
from app.database.redis import redis_client
from app.database.session import SessionLocal
from app.domains.rbac.repository import RBACRepository

from .constants import (
    SYNC_SWEEP_MAX_INTEGRATIONS_PER_RUN,
    TASK_RUN_NETWORK_INTEGRATION_SYNC_SWEEP,
)
from .repository import NetworkIntegrationRepository
from .service import (
    NetworkIntegrationService,
    SyncSweepSummary,
    run_network_integration_sync_sweep,
)

logger = logging.getLogger(__name__)

__all__ = ["run_network_integration_sync_sweep_task"]


async def _run_sweep_async() -> SyncSweepSummary:
    async with SessionLocal() as session:
        try:
            service = NetworkIntegrationService(
                NetworkIntegrationRepository(session),
                # The sweep writes no audit entries of its own -- see
                # below -- but the writer is supplied anyway so that a
                # service constructed here behaves identically to one
                # built by the FastAPI DI path. A service whose
                # collaborators differ between the request path and the
                # worker path is a service whose behaviour differs, and
                # that difference is invisible until it matters.
                audit_writer=RBACRepository(session),
                # No guest_session_lookup: the sweep never authorizes
                # anyone, so it must not carry the collaborator that
                # would let it. Passing None means the portal path is
                # structurally unavailable from a worker.
                guest_session_lookup=None,
                redis=redis_client,
                caller_location_scope=None,
            )
            summary = await run_network_integration_sync_sweep(
                service, limit=SYNC_SWEEP_MAX_INTEGRATIONS_PER_RUN
            )
            await session.commit()
            return summary
        except Exception:
            await session.rollback()
            raise


@celery_app.task(name=TASK_RUN_NETWORK_INTEGRATION_SYNC_SWEEP)
def run_network_integration_sync_sweep_task() -> dict[str, int]:
    """Poll every integration whose own interval has elapsed.

    ``caller_location_scope=None`` above is correct and is not an
    oversight: this runs as the platform, with no caller whose grants
    could confine it. It is safe because the sweep never resolves a row
    from a caller-supplied id -- the only rows it can reach are the ones
    ``list_due_for_sync`` returns, and it acts on each strictly within
    that row's own tenant's controller. It therefore cannot cross a
    tenancy boundary, because it never crosses a *request* boundary.

    Writes no audit entry for the sweep itself. ``audit_log_entries``
    answers "which human did this"; a scheduled poll has no actor, and one
    row per integration per five minutes would bury the entries that do
    name a person. The per-integration event feed
    (``network_integration_events``) is where a sync outcome is recorded,
    which is the read that actually wants it.
    """
    summary = run_celery_task(_run_sweep_async())
    result = {
        "considered": summary.considered,
        "synced": summary.synced,
        "skipped_backoff": summary.skipped_backoff,
        "errors": summary.errors,
    }
    logger.info(
        "network_integration_task_run_sync_sweep_completed", extra=result
    )
    return result
