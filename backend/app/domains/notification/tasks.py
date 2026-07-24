"""Celery task definitions for the notification domain.

``run_notification_dispatch_sweep`` is the Beat-scheduled task (see
``app.core.celery_app``'s own ``beat_schedule``) that drains due
``PENDING``/``RETRYING`` ``NotificationDelivery`` rows -- see
``service.py``'s module docstring for the full outbox/dispatch design.

## The async bridge, concretely

Mirrors ``app.domains.campaigns.tasks``/``app.domains.queue_management
.tasks``'s identical bridge pattern: a plain, synchronous
``@celery_app.task`` body delegating immediately to a module-level
``async def`` via ``asyncio.run``, which opens a fresh ``AsyncSession``,
builds the real repository/service graph, does the actual work, commits,
and returns a plain, JSON-serializable result.
"""

from __future__ import annotations

import dataclasses

from app.core.async_task_bridge import run_celery_task
from app.core.celery_app import celery_app
from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.storage import get_object_storage
from app.database.session import SessionLocal
from app.domains.otp.service import (
    get_configured_email_provider,
    get_configured_sms_provider,
)

from .constants import DISPATCH_SWEEP_BATCH_SIZE, TASK_RUN_NOTIFICATION_DISPATCH_SWEEP
from .repository import NotificationRepository
from .service import NotificationService

logger = get_logger(__name__)


async def _run_notification_dispatch_sweep_async() -> dict[str, int]:
    """The actual async work behind ``run_notification_dispatch_sweep`` --
    a fresh session per task run, never shared across separate task
    invocations/worker ticks, mirroring ``campaigns.tasks``'s identical
    per-run session discipline."""
    settings = get_settings()
    async with SessionLocal() as session:
        service = NotificationService(
            NotificationRepository(session),
            object_storage=get_object_storage(),
            email_provider=get_configured_email_provider(settings),
            sms_provider=get_configured_sms_provider(settings),
            max_attempts=settings.notification_max_delivery_attempts,
            retry_backoff_seconds=settings.notification_retry_backoff_seconds,
        )
        summary = await service.dispatch_pending(batch_size=DISPATCH_SWEEP_BATCH_SIZE)
        await session.commit()
        return dataclasses.asdict(summary)


@celery_app.task(name=TASK_RUN_NOTIFICATION_DISPATCH_SWEEP)
def run_notification_dispatch_sweep() -> dict[str, int]:
    """Beat-scheduled periodic task (see ``app.core.celery_app``'s
    ``beat_schedule`` -- runs every
    ``Settings.notification_dispatch_sweep_interval_seconds``)."""
    result = run_celery_task(_run_notification_dispatch_sweep_async())
    logger.info("notification_task_dispatch_sweep_completed", extra=result)
    return result


__all__ = ["run_notification_dispatch_sweep"]
