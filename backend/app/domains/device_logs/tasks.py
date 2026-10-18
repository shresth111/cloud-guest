"""Celery Beat task: ``device_log_events`` partition maintenance (nightly).

Creates the coming months' partitions and drops the ones past
``Settings.device_logs_retention_months`` -- see ``partitions`` for the
rules. Same async bridge and per-run session discipline as
``app.domains.network_diagnostics.tasks``: a plain sync task delegating to
``run_celery_task``, which keeps it testable without a worker. Default queue:
pure database work, no router I/O.

Runs whether or not ``device_logs_enabled`` is on: the table exists either
way, and RADIUS/portal rows land in it independently of syslog ingest once
the flag is on -- a missing partition must never be the reason a row goes
to DEFAULT.
"""

from __future__ import annotations

import logging
from typing import Any

from app.core.async_task_bridge import run_celery_task
from app.core.celery_app import celery_app
from app.core.config import get_settings
from app.database.session import SessionLocal

from .constants import TASK_DEVICE_LOGS_PARTITION_MAINTENANCE
from .partitions import maintain_partitions

logger = logging.getLogger(__name__)


async def _run_partition_maintenance_async() -> dict[str, Any]:
    settings = get_settings()
    async with SessionLocal() as session:
        try:
            summary = await maintain_partitions(
                session,
                retention_months=settings.device_logs_retention_months,
                ahead=settings.device_logs_partitions_ahead,
            )
            await session.commit()
            return summary
        except Exception:
            await session.rollback()
            raise


@celery_app.task(name=TASK_DEVICE_LOGS_PARTITION_MAINTENANCE)
def run_partition_maintenance() -> dict[str, Any]:
    summary = run_celery_task(_run_partition_maintenance_async())
    logger.info(
        "device_logs_partition_maintenance_completed",
        extra={
            "partitions_created": summary.get("created"),
            "partitions_dropped": summary.get("dropped"),
            "moved_from_default": summary.get("moved_from_default"),
            "default_rows_pruned": summary.get("default_rows_pruned"),
            "retention_cutoff": summary.get("cutoff"),
            "skipped_locked": summary.get("locked"),
        },
    )
    return summary


__all__ = ["run_partition_maintenance", "_run_partition_maintenance_async"]
