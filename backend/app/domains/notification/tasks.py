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
import uuid
from collections.abc import Sequence

from app.core.async_task_bridge import run_celery_task
from app.core.celery_app import celery_app
from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.core.storage import get_object_storage
from app.database.session import SessionLocal
from app.domains.otp.service import (
    get_configured_email_provider,
    get_configured_email_providers_by_identity,
    get_configured_sms_provider,
)

from .constants import (
    DISPATCH_SWEEP_BATCH_SIZE,
    SLACK_ONBOARDING_RECIPIENT,
    TASK_RECORD_ONBOARDING_FAILURE,
    TASK_RUN_NOTIFICATION_DISPATCH_SWEEP,
    NotificationChannelType,
)
from .onboarding_slack import (
    build_context,
    build_slack_text,
    notice_from_context,
    onboarding_failed_notice,
    resolve_master_console_base_url,
)
from .repository import NotificationRepository
from .service import NotificationService
from .slack import get_configured_slack_sender

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
            # This sweep is where outbox mail is actually sent, so this is
            # the wiring that decides which mailbox each row leaves from --
            # see `constants.MAIL_IDENTITY_BY_EVENT_TYPE`.
            email_providers_by_identity=get_configured_email_providers_by_identity(
                settings
            ),
            sms_provider=get_configured_sms_provider(settings),
            slack_sender=get_configured_slack_sender(settings),
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


async def _record_onboarding_failure_async(
    payload: dict[str, object],
) -> dict[str, object]:
    """Write the ``ONBOARDING_FAILED`` outbox row in a session of this
    worker's own.

    This is the whole reason the failure path is a task. The request that
    failed is, by the time this runs, rolled back by
    ``app.database.session.get_db_session`` -- a row written there would
    be rolled back along with the half-built customer, which is exactly
    the case an ops channel exists to catch. A fresh session in another
    process is the only place the row survives.

    Enqueue only: the actual POST is left to
    ``run_notification_dispatch_sweep``, so both the success and failure
    paths have precisely one sending implementation and one retry policy
    between them.
    """
    settings = get_settings()
    if not settings.slack_onboarding_webhook_url.strip():
        # Unconfigured is inert, here as everywhere. The router's `.delay`
        # is itself guarded by the same check, so reaching this branch
        # means the webhook was removed between the two -- worth a line,
        # not worth a row.
        logger.info("onboarding_failure_slack_disabled")
        return {"enqueued": 0}

    notice = notice_from_context(payload)
    async with SessionLocal() as session:
        service = NotificationService(
            NotificationRepository(session),
            max_attempts=settings.notification_max_delivery_attempts,
            retry_backoff_seconds=settings.notification_retry_backoff_seconds,
        )
        await service.enqueue(
            event_type=notice.event_type,
            channel=NotificationChannelType.SLACK,
            recipient=SLACK_ONBOARDING_RECIPIENT,
            subject=None,
            body=build_slack_text(
                notice,
                master_base_url=resolve_master_console_base_url(settings),
            ),
            # NULL, like every other onboarding row -- see
            # `onboarding_slack.py`'s Scope section.
            organization_id=None,
            context=build_context(notice),
        )
        await session.commit()
    return {"enqueued": 1}


@celery_app.task(name=TASK_RECORD_ONBOARDING_FAILURE)
def record_onboarding_failure(payload: dict[str, object]) -> dict[str, object]:
    """Fired (never awaited) by the Master onboarding routes when an
    onboarding raises. ``payload`` is the JSON-safe dict built by
    ``onboarding_slack.build_context``; it is re-read field-by-field by
    ``notice_from_context``, so the payload allowlist still holds on this
    side of the broker.

    Never raises: a broken announcement must not turn into a dead-letter
    storm behind an onboarding that already failed for its own reasons.
    """
    try:
        result = run_celery_task(_record_onboarding_failure_async(payload))
    except Exception:  # noqa: BLE001 -- see docstring
        logger.exception("onboarding_failure_notice_task_failed")
        return {"enqueued": 0}
    logger.info("onboarding_failure_notice_recorded", extra=result)
    return result


def dispatch_onboarding_failure(
    *,
    settings: Settings,
    stage: str,
    organization_name: str,
    organization_id: uuid.UUID | None,
    error: BaseException,
    actor_user_id: uuid.UUID | None,
    request_id: str | None,
    details: Sequence[tuple[str, object | None]] = (),
) -> None:
    """Hand a failed onboarding to ``record_onboarding_failure`` and return.

    Called from the ``except`` block of a Master onboarding route, on the
    way to re-raising. Everything about it is shaped by "the onboarding
    has already failed; do not make it worse":

    * It is synchronous and does no I/O of its own beyond one broker
      publish. ``.delay()`` is Kombu's synchronous publish -- a single
      small message, no device or HTTP work (the same reasoning
      ``app.domains.guest.tasks`` writes out for its own fan-out).
    * It **never raises**, including when the broker is unreachable. An
      unavailable Celery broker must not replace the caller's real
      exception with a different one on the way out of the handler.
    * It is inert with no webhook configured, checked here so that no
      message is even published in the common unconfigured case.

    Only ``type(error).__name__`` and, when present, ``error.status_code``
    are read off ``error``. ``str(error)`` is deliberately never touched
    -- see ``onboarding_slack.py``'s exclusion list.
    """
    if not settings.slack_onboarding_webhook_url.strip():
        return
    status_code = getattr(error, "status_code", None)
    notice = onboarding_failed_notice(
        stage=stage,
        organization_name=organization_name,
        organization_id=organization_id,
        error_type=type(error).__name__,
        status_code=status_code if isinstance(status_code, int) else None,
        actor_user_id=actor_user_id,
        request_id=request_id,
        details=details,
    )
    try:
        record_onboarding_failure.delay(build_context(notice))
    except Exception:  # noqa: BLE001 -- see docstring
        logger.exception(
            "onboarding_failure_notice_dispatch_failed",
            extra={"stage": stage},
        )


__all__ = [
    "run_notification_dispatch_sweep",
    "record_onboarding_failure",
    "dispatch_onboarding_failure",
]
