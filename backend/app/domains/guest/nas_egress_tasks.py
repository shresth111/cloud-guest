"""Celery Beat task: the daily prune of expired auto-learned NAS addresses.

See ``app.domains.guest.nas_egress``. A learned egress address unseen for
``nas_egress_ttl_days`` is removed from the database and its NAS's address
set re-pushed to the hub (one FreeRADIUS restart per NAS whose set actually
changed, none when nothing expired). The most recently seen learned address
of a NAS is never pruned by age. A no-op when learning is disabled.
"""

from __future__ import annotations

import logging
from typing import Any

from app.core.async_task_bridge import run_celery_task
from app.core.celery_app import celery_app
from app.core.config import get_settings
from app.database.session import SessionLocal

from .nas_egress import learner_for_session

logger = logging.getLogger(__name__)

TASK_PRUNE_LEARNED_NAS_ADDRESSES = "guest.nas_egress.prune_learned_addresses"


async def _prune_async() -> dict[str, Any]:
    settings = get_settings()
    if not settings.nas_egress_learning_enabled:
        return {"skipped": "disabled"}
    async with SessionLocal() as session:
        result = await learner_for_session(session, settings).prune_all()
        await session.commit()
    return result


@celery_app.task(name=TASK_PRUNE_LEARNED_NAS_ADDRESSES)
def prune_learned_nas_addresses() -> dict[str, Any]:
    result = run_celery_task(_prune_async())
    logger.info("nas_egress_prune_completed", extra=result)
    return result


__all__ = ["TASK_PRUNE_LEARNED_NAS_ADDRESSES", "prune_learned_nas_addresses"]
