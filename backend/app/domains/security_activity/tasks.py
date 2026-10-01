"""Celery tasks: the hourly, read-only security counter sweep.

Same shape as ``app.domains.dhcp.tasks``'s rogue-DHCP detector, whose module
docstring carries the full reasoning: a Beat-scheduled coordinator takes a
Redis overlap lock, lists the routers, and dispatches one leaf task per
router, so one unreachable router only ever delays its own leaf. Leaves run
on ``DEVICE_IO_QUEUE_NAME``.

## Load

* **One connection per router per hour.** The leaf opens one RouterOS API
  session (``ReadOnlyDeviceReader.read_all``), reads two sections, closes.
* **Staggered.** Leaves are dispatched with a ``countdown`` of
  ``SECURITY_COUNTER_STAGGER_SECONDS`` apart, wrapping inside
  ``SECURITY_COUNTER_STAGGER_WINDOW_SECONDS``, so the fleet is never dialled
  at once and the hub's tunnel sees a trickle, not a burst.
* **Never a write.** The reader cannot express one; see
  ``service``'s module docstring.
* **Never a retry storm.** An unreachable router is recorded as a gap (no
  sample for that hour) and the leaf returns; there is no retry.
"""

from __future__ import annotations

import uuid

from app.core.async_task_bridge import run_celery_task
from app.core.celery_app import celery_app
from app.core.logging import get_logger
from app.database.redis import create_redis_client
from app.database.session import SessionLocal

from .constants import (
    SECURITY_COUNTER_STAGGER_SECONDS,
    SECURITY_COUNTER_STAGGER_WINDOW_SECONDS,
    SECURITY_COUNTER_SWEEP_LOCK_REDIS_KEY,
    SECURITY_COUNTER_SWEEP_LOCK_TTL_SECONDS,
    TASK_COLLECT_SECURITY_COUNTERS_FOR_ROUTER,
    TASK_RUN_SECURITY_COUNTER_SWEEP,
)
from .repository import SecurityActivityRepository
from .service import SecurityCounterCollector

logger = get_logger(__name__)


def stagger_countdown(index: int) -> int:
    """Seconds to delay the ``index``-th router's leaf."""
    return (
        index * SECURITY_COUNTER_STAGGER_SECONDS
    ) % SECURITY_COUNTER_STAGGER_WINDOW_SECONDS


async def _dispatch_security_counter_sweep_async() -> dict[str, object]:
    redis = create_redis_client()
    try:
        acquired = await redis.set(
            SECURITY_COUNTER_SWEEP_LOCK_REDIS_KEY,
            "1",
            nx=True,
            ex=SECURITY_COUNTER_SWEEP_LOCK_TTL_SECONDS,
        )
        if not acquired:
            logger.warning(
                "security_counter_sweep_skipped_locked",
                extra={"lock_key": SECURITY_COUNTER_SWEEP_LOCK_REDIS_KEY},
            )
            return {"dispatched": 0, "skipped_locked": True}
        try:
            async with SessionLocal() as session:
                router_ids = await SecurityActivityRepository(
                    session
                ).list_collection_router_ids()
            for index, router_id in enumerate(router_ids):
                collect_security_counters_for_router.apply_async(
                    args=[str(router_id)], countdown=stagger_countdown(index)
                )
            return {"dispatched": len(router_ids), "skipped_locked": False}
        finally:
            await redis.delete(SECURITY_COUNTER_SWEEP_LOCK_REDIS_KEY)
    finally:
        await redis.aclose()


@celery_app.task(name=TASK_RUN_SECURITY_COUNTER_SWEEP)
def run_security_counter_sweep() -> dict[str, object]:
    """Beat-scheduled coordinator: one DB query and N ``apply_async`` calls,
    no device I/O, so it stays on the default queue."""
    result = run_celery_task(_dispatch_security_counter_sweep_async())
    logger.info("security_counter_sweep_dispatched", extra=result)
    return result


async def collect_security_counters_once(router_id: uuid.UUID) -> dict[str, object]:
    """One collection for one router, committed. Shared by the leaf task and
    the ops script (``~/wyfy-ops/cftest/logstest.py``)."""
    async with SessionLocal() as session:
        try:
            collector = SecurityCounterCollector(SecurityActivityRepository(session))
            summary = await collector.collect_for_router(router_id)
            await session.commit()
        except Exception:
            await session.rollback()
            raise
    result = summary.as_dict()
    result["readings"] = summary.readings
    return result


@celery_app.task(name=TASK_COLLECT_SECURITY_COUNTERS_FOR_ROUTER)
def collect_security_counters_for_router(router_id: str) -> dict[str, object]:
    """The per-router leaf -- a real, read-only RouterOS round trip, routed
    to ``DEVICE_IO_QUEUE_NAME``."""
    result = run_celery_task(collect_security_counters_once(uuid.UUID(router_id)))
    result.pop("readings", None)
    logger.info("security_counters_router_completed", extra=result)
    return result


__all__ = [
    "collect_security_counters_for_router",
    "collect_security_counters_once",
    "run_security_counter_sweep",
    "stagger_countdown",
]
