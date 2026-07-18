"""Celery task definitions for the Analytics domain (BE-012 Part 1).

Thin wrappers around ``service.AnalyticsService``'s real aggregation
methods (which themselves compose ``aggregation.py``'s pure computation
functions) -- no aggregation logic lives in this file itself, only the
bridge between a synchronous Celery task body and this codebase's
``AsyncSession``-based repository/service layer.

## The async bridge, concretely

Each public task (``run_daily_aggregation_for_all_organizations``,
``run_daily_aggregation_for_organization``) is a plain, synchronous
function -- exactly what Celery's worker process expects to call. Each one
delegates immediately to a small, module-level **async** function
(``_run_all_organizations_async``/``_run_single_organization_async``) via
``asyncio.run(...)``. That async function is where the real work happens:
it opens a fresh ``AsyncSession`` (``app.database.session.SessionLocal``,
the exact same session factory ``app.database.session.get_db_session``
uses for every HTTP request, just without the FastAPI dependency-injection
wrapper around it), builds the real ``AnalyticsRepository``/
``GuestRepository``/``GuestAnalyticsService``/``AnalyticsService`` objects,
awaits ``AnalyticsService``'s actual aggregation call, commits the session,
and returns a plain, JSON-serializable result (a task's return value must
survive JSON serialization -- see ``app.core.celery_app``'s serialization
security write-up). ``asyncio.run`` is safe here because a Celery worker
never itself has a running event loop underneath a task body (unlike
calling this from inside an already-async FastAPI route handler, where a
nested ``asyncio.run`` would raise ``RuntimeError``).

Keeping the async bridge functions at module scope (rather than inlining
them into the ``@celery_app.task`` bodies) is what keeps this file
testable without a running Celery worker or broker:
``tests/unit/test_analytics.py`` monkeypatches
``tasks._run_all_organizations_async``/``tasks._run_single_organization_async``
with a fake coroutine function and calls the plain task function directly
(Celery tasks remain ordinary, directly callable Python functions when not
invoked through ``.delay()``/``.apply_async()``), asserting the bridge
resolves the coroutine and returns its result -- exactly the "mock the
async bridge, verify it calls the aggregation function correctly" contract
this part's test suite requires.
"""

from __future__ import annotations

import asyncio
import uuid

from app.core.celery_app import celery_app
from app.core.logging import get_logger
from app.database.session import SessionLocal
from app.domains.guest.repository import GuestRepository
from app.domains.guest.service import GuestAnalyticsService

from .constants import (
    TASK_RUN_DAILY_AGGREGATION_FOR_ALL_ORGANIZATIONS,
    TASK_RUN_DAILY_AGGREGATION_FOR_ORGANIZATION,
)
from .repository import AnalyticsRepository
from .service import AggregationBatchResult, AnalyticsService

logger = get_logger(__name__)


async def _run_all_organizations_async(
    *, target_date_iso: str | None, days_ago: int
) -> AggregationBatchResult:
    """The actual async work behind ``run_daily_aggregation_for_all_
    organizations`` -- a fresh session per task run (never a session
    shared across separate task invocations/worker ticks)."""
    async with SessionLocal() as session:
        try:
            repository = AnalyticsRepository(session)
            guest_analytics = GuestAnalyticsService(GuestRepository(session))
            service = AnalyticsService(repository, guest_analytics)
            result = await service.run_daily_aggregation_for_all_organizations(
                target_date_iso=target_date_iso, days_ago=days_ago
            )
            await session.commit()
            return result
        except Exception:
            await session.rollback()
            raise


async def _run_single_organization_async(
    organization_id: uuid.UUID, *, target_date_iso: str | None, days_ago: int
) -> int:
    """The actual async work behind ``run_daily_aggregation_for_
    organization`` -- returns the number of snapshots persisted (an
    org-level snapshot plus one per active location)."""
    async with SessionLocal() as session:
        try:
            repository = AnalyticsRepository(session)
            guest_analytics = GuestAnalyticsService(GuestRepository(session))
            service = AnalyticsService(repository, guest_analytics)
            snapshots = await service.run_daily_aggregation_for_organization(
                organization_id, target_date_iso=target_date_iso, days_ago=days_ago
            )
            await session.commit()
            return len(snapshots)
        except Exception:
            await session.rollback()
            raise


@celery_app.task(name=TASK_RUN_DAILY_AGGREGATION_FOR_ALL_ORGANIZATIONS)
def run_daily_aggregation_for_all_organizations(
    target_date_iso: str | None = None, days_ago: int = 0
) -> dict[str, object]:
    """Beat-scheduled periodic task (see ``app.core.celery_app``'s
    ``beat_schedule`` -- both the 15-minute "today so far" tick and the
    daily "finalize yesterday" tick call this exact task, parameterized
    only by ``target_date_iso``/``days_ago``, see ``validators
    .day_bounds_utc``). Iterates every active organization; one
    organization's aggregation failing never aborts the batch (see
    ``AnalyticsService.run_daily_aggregation_for_all_organizations``'s own
    docstring for the full per-organization isolation write-up) -- this
    task simply reports the batch result, it never re-raises a single
    organization's failure.
    """
    result = asyncio.run(
        _run_all_organizations_async(target_date_iso=target_date_iso, days_ago=days_ago)
    )
    logger.info(
        "analytics_task_run_daily_aggregation_for_all_organizations_completed",
        extra={
            "total_organizations": result.total_organizations,
            "succeeded_organizations": result.succeeded_organizations,
            "failed_organization_count": len(result.failed_organizations),
        },
    )
    return {
        "total_organizations": result.total_organizations,
        "succeeded_organizations": result.succeeded_organizations,
        "failed_organizations": [
            {"organization_id": str(org_id), "error": error}
            for org_id, error in result.failed_organizations
        ],
    }


@celery_app.task(name=TASK_RUN_DAILY_AGGREGATION_FOR_ORGANIZATION)
def run_daily_aggregation_for_organization(
    organization_id: str, target_date_iso: str | None = None, days_ago: int = 0
) -> dict[str, object]:
    """Callable individually for a single organization -- useful for
    on-demand/manual triggering outside the Beat schedule, and for tests.
    ``organization_id`` is a plain ``str`` (JSON-serializable task argument,
    per ``app.core.celery_app``'s JSON-only serialization) parsed into a
    ``uuid.UUID`` here."""
    org_id = uuid.UUID(organization_id)
    snapshot_count = asyncio.run(
        _run_single_organization_async(
            org_id, target_date_iso=target_date_iso, days_ago=days_ago
        )
    )
    logger.info(
        "analytics_task_run_daily_aggregation_for_organization_completed",
        extra={"organization_id": organization_id, "snapshot_count": snapshot_count},
    )
    return {"organization_id": organization_id, "snapshot_count": snapshot_count}


__all__ = [
    "run_daily_aggregation_for_all_organizations",
    "run_daily_aggregation_for_organization",
]
