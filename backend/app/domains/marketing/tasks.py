"""Celery tasks for Guest Marketing (spec §9).

* ``marketing.dispatch_due_campaigns`` -- Beat, every 60 s, default queue
  (pure DB): starts due campaigns, re-checking entitlement and channel
  config first, and fails campaigns whose first batch never ran
  (``last_error="no_worker"``).
* ``marketing.send_campaign_batch`` -- the ``marketing`` queue,
  ``acks_late``: sends one batch and re-enqueues itself while work remains.
* ``marketing.reap_stuck_recipients`` -- Beat, every 5 min: rows left in
  ``sending`` for 15+ min become ``failed/worker_lost``. Never re-sent
  (at-most-once: a duplicate promo is worse than a missing one).
* ``marketing.prune_recipient_addresses`` -- Beat, daily: nulls recipient
  addresses and previews after 180 days. Consent events are never pruned.

## Deploy trap

The prod worker must consume the ``marketing`` queue (``-Q celery,device_io,
marketing``) or send batches queue forever and campaigns sit in
``sending`` until the dispatcher fails them with ``no_worker``.
"""

from __future__ import annotations

import uuid

from app.core.async_task_bridge import run_celery_task
from app.core.celery_app import celery_app
from app.core.config import get_settings
from app.core.logging import get_logger
from app.database.redis import redis_client
from app.database.session import SessionLocal

from .constants import (
    MARKETING_QUEUE_NAME,
    TASK_DISPATCH_DUE_CAMPAIGNS,
    TASK_PRUNE_RECIPIENT_ADDRESSES,
    TASK_REAP_STUCK_RECIPIENTS,
    TASK_SEND_CAMPAIGN_BATCH,
)
from .repository import MarketingRepository
from .senders import resolve_marketing_senders
from .service import MarketingService

logger = get_logger(__name__)


def enqueue_send_batch(campaign_id: uuid.UUID, countdown: int = 0) -> None:
    send_campaign_batch.apply_async(
        args=[str(campaign_id)],
        countdown=max(int(countdown), 0),
        queue=MARKETING_QUEUE_NAME,
    )


def _service(session) -> MarketingService:  # noqa: ANN001
    from .dependencies import build_entitlement_check

    settings = get_settings()
    return MarketingService(
        MarketingRepository(session),
        settings=settings,
        senders=resolve_marketing_senders(settings),
        redis=redis_client,
        entitlement_check=build_entitlement_check(session, redis_client),
        enqueue_batch=enqueue_send_batch,
    )


async def _dispatch_async() -> dict[str, int]:
    async with SessionLocal() as session:
        return await _service(session).dispatch_due()


async def _send_batch_async(campaign_id: str) -> dict[str, object]:
    async with SessionLocal() as session:
        return await _service(session).send_batch(uuid.UUID(campaign_id))


async def _reap_async() -> dict[str, int]:
    async with SessionLocal() as session:
        return await _service(session).reap_stuck()


async def _prune_async() -> dict[str, int]:
    async with SessionLocal() as session:
        return {"pruned": await _service(session).prune_recipient_pii()}


@celery_app.task(name=TASK_DISPATCH_DUE_CAMPAIGNS)
def dispatch_due_campaigns() -> dict[str, int]:
    result = run_celery_task(_dispatch_async())
    logger.info("marketing_dispatch_completed", extra=result)
    return result


@celery_app.task(
    name=TASK_SEND_CAMPAIGN_BATCH, acks_late=True, time_limit=300, soft_time_limit=280
)
def send_campaign_batch(campaign_id: str) -> dict[str, object]:
    result = run_celery_task(_send_batch_async(campaign_id))
    requeue = result.get("requeue")
    if requeue is not None:
        enqueue_send_batch(uuid.UUID(campaign_id), int(requeue))
    logger.info(
        "marketing_send_batch_completed",
        extra={
            "campaign_id": campaign_id,
            **{k: v for k, v in result.items() if k != "reason"},
        },
    )
    return result


@celery_app.task(name=TASK_REAP_STUCK_RECIPIENTS)
def reap_stuck_recipients() -> dict[str, int]:
    result = run_celery_task(_reap_async())
    logger.info("marketing_reap_completed", extra=result)
    return result


@celery_app.task(name=TASK_PRUNE_RECIPIENT_ADDRESSES)
def prune_recipient_addresses() -> dict[str, int]:
    result = run_celery_task(_prune_async())
    logger.info("marketing_prune_completed", extra=result)
    return result


__all__ = [
    "dispatch_due_campaigns",
    "enqueue_send_batch",
    "prune_recipient_addresses",
    "reap_stuck_recipients",
    "send_campaign_batch",
]
