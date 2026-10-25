"""Celery tasks for the SMS delivery log.

* ``sms_delivery.poll_dlrs`` -- Beat, every 5 min, default queue: asks
  Ping4SMS for the delivery status of recent Wyfy-sent rows still at
  ``sent``. A no-op unless ``sms_delivery_provider == 'ping4sms'``,
  ``sms_dlr_poll_enabled`` and an API key are all set.
* ``sms_delivery.prune_logs`` -- Beat, daily: deletes rows older than
  ``sms_delivery_log_retention_days``.
"""

from __future__ import annotations

from app.core.async_task_bridge import run_celery_task
from app.core.celery_app import celery_app
from app.core.config import get_settings
from app.core.logging import get_logger
from app.database.session import SessionLocal

from .constants import TASK_POLL_SMS_DLRS, TASK_PRUNE_SMS_DELIVERY_LOGS
from .service import (
    delivery_reports_state,
    poll_ping4sms_dlrs,
    prune_logs,
    silence_url_logging,
)

logger = get_logger(__name__)


async def _poll_async() -> dict[str, int]:
    settings = get_settings()
    if "poll" not in delivery_reports_state(settings)["mechanisms"]:
        return {"polled": 0, "skipped": 1}
    silence_url_logging()
    async with SessionLocal() as session:
        return await poll_ping4sms_dlrs(session, api_key=settings.ping4sms_api_key)


async def _prune_async() -> dict[str, int]:
    settings = get_settings()
    async with SessionLocal() as session:
        deleted = await prune_logs(
            session, retention_days=settings.sms_delivery_log_retention_days
        )
    return {"deleted": deleted}


@celery_app.task(name=TASK_POLL_SMS_DLRS)
def poll_sms_dlrs() -> dict[str, int]:
    result = run_celery_task(_poll_async())
    logger.info("sms_dlr_poll_completed", extra=result)
    return result


@celery_app.task(name=TASK_PRUNE_SMS_DELIVERY_LOGS)
def prune_sms_delivery_logs() -> dict[str, int]:
    result = run_celery_task(_prune_async())
    logger.info("sms_delivery_prune_completed", extra=result)
    return result


__all__ = ["poll_sms_dlrs", "prune_sms_delivery_logs"]
