"""Celery Beat task: archive closed IST days of IPDR (nightly, 01:10 IST).

Runs only when ``ipdr_enabled``. Each day file is committed on its own, so
one failing location does not lose the others; a failed day is retried by
the next run while its flow records are still retained.
"""

from __future__ import annotations

import logging
from typing import Any

from app.core.async_task_bridge import run_celery_task
from app.core.celery_app import celery_app
from app.core.config import get_settings
from app.database.session import SessionLocal

from .builder import IpdrBuilder
from .constants import TASK_IPDR_DAILY_BUILD
from .dependencies import archive_for
from .repository import IpdrRepository

logger = logging.getLogger(__name__)


async def _run_daily_build_async() -> dict[str, Any]:
    settings = get_settings()
    if not settings.ipdr_enabled:
        return {"enabled": False}
    async with SessionLocal() as session:
        builder = IpdrBuilder(IpdrRepository(session), settings, archive_for(settings))
        summary = await builder.run_closed_days(
            commit=session.commit, rollback=session.rollback
        )
        return {"enabled": True, **summary}


@celery_app.task(name=TASK_IPDR_DAILY_BUILD)
def run_daily_build() -> dict[str, Any]:
    summary = run_celery_task(_run_daily_build_async())
    logger.info("ipdr_daily_build_completed", extra={"ipdr": summary})
    return summary


__all__ = ["run_daily_build", "_run_daily_build_async"]
