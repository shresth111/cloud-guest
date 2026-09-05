"""Celery Beat task for the Network Diagnostics domain: the
``diagnostic_runs`` retention sweep.

## Why this file exists

``diagnostic_runs`` is append-only -- no update, no delete, no soft-delete
anywhere in this domain's repository -- and until this task it had no TTL,
no purge job and no rate limit either. Any authenticated caller holding
``network_diagnostics.execute`` could grow the table without bound, one
JSONB ``result`` blob per row, and nothing would ever remove any of it.
The abuse controls in ``service.py`` bound the rate; this bounds the
total.

See ``constants.DIAGNOSTIC_RUN_RETENTION_DAYS`` for why ninety days
specifically, and ``repository.delete_runs_older_than`` for why the
deletion is batched rather than one unbounded statement.

## The async bridge, concretely

Mirrors ``app.domains.guest.tasks``'s identical bridge pattern:
``run_diagnostic_run_retention_sweep`` is a plain synchronous function
(what Celery's worker expects), delegating immediately to a module-level
**async** function via ``app.core.async_task_bridge.run_celery_task`` --
never ``asyncio.run`` directly, for the asyncpg-connection-pool reason
that module's own docstring documents at length.

That async function opens a fresh ``AsyncSession`` per run and builds a
bare ``NetworkDiagnosticsRepository``, **not** a
``NetworkDiagnosticsService``: the sweep needs a repository and nothing
else, while the service additionally requires a real ``RouterService``
(itself composing ``LocationService`` and ``OrganizationService``) it
would never call. ``service.purge_expired_runs`` is a module-level
function specifically so this task can skip that construction, exactly as
``guest.service.enforce_session_timeouts`` is.

Keeping the bridge function at module scope (rather than inlining it into
the ``@celery_app.task`` body) is what keeps this testable without a
running Celery worker or broker -- the same "monkeypatch the bridge, call
the plain task function directly" contract every other domain's task
tests use.

## Queue

Deliberately **not** on ``DEVICE_IO_QUEUE_NAME``. This sweep touches this
platform's own database and never opens a RouterOS connection, so it
belongs on the default queue with every other pure-DB sweep -- see
``app.core.celery_app``'s own ``task_routes`` write-up for why that
separation exists.
"""

from __future__ import annotations

import logging

from app.core.async_task_bridge import run_celery_task
from app.core.celery_app import celery_app
from app.database.session import SessionLocal

from .constants import TASK_RUN_DIAGNOSTIC_RUN_RETENTION_SWEEP
from .repository import NetworkDiagnosticsRepository
from .service import purge_expired_runs

logger = logging.getLogger(__name__)


async def _run_diagnostic_run_retention_sweep_async() -> dict[str, object]:
    """The actual async work behind
    ``run_diagnostic_run_retention_sweep`` -- a fresh ``AsyncSession`` per
    task run, never one shared across invocations, mirroring every other
    domain's identical per-run session discipline."""
    async with SessionLocal() as session:
        try:
            repository = NetworkDiagnosticsRepository(session)
            summary = await purge_expired_runs(repository)
            await session.commit()
            return summary
        except Exception:
            await session.rollback()
            raise


@celery_app.task(name=TASK_RUN_DIAGNOSTIC_RUN_RETENTION_SWEEP)
def run_diagnostic_run_retention_sweep() -> dict[str, object]:
    """Beat-scheduled daily task (see ``app.core.celery_app``'s
    ``beat_schedule``). Hard-deletes ``DiagnosticRun`` rows older than
    ``constants.DIAGNOSTIC_RUN_RETENTION_DAYS``."""
    summary = run_celery_task(_run_diagnostic_run_retention_sweep_async())
    logger.info(
        "network_diagnostics_task_retention_sweep_completed",
        extra={
            "deleted": summary.get("deleted"),
            "batches": summary.get("batches"),
            "cutoff": summary.get("cutoff"),
            # True means a backlog remains and the next nightly run will
            # continue it -- surfaced rather than silent, so "the sweep is
            # keeping up" is an observable fact.
            "hit_batch_cap": summary.get("hit_batch_cap"),
        },
    )
    return summary


__all__ = [
    "run_diagnostic_run_retention_sweep",
    "_run_diagnostic_run_retention_sweep_async",
]
