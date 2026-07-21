"""Notification domain business logic: template CRUD and the outbox/
dispatch pattern the ADD (§12) calls out as the one deliberate exception to
this codebase's "synchronous, in-process, no bus" event-handling default.

## Why an outbox here, and nowhere else

Every other domain's events are constructed and logged synchronously,
in-process -- fine, because nothing downstream is I/O-bound or needs
retry. Email/SMS delivery is different: it is a third-party network call
that can fail transiently, and several of this domain's callers (a
password-reset email, a renewal reminder) need at-least-once delivery
without blocking the triggering request on that network call. So:

1. ``NotificationService.enqueue`` writes a ``NotificationDelivery`` row
   with ``status=PENDING`` **synchronously** -- fast, local, durable. This
   is the only part any caller's own request/service call ever waits on.
2. ``app.domains.notification.tasks.run_notification_dispatch_sweep`` (a
   Celery Beat task, registered in ``app.core.celery_app`` following the
   exact convention ``billing.tasks``/``analytics.tasks`` already
   establish) drains due ``PENDING``/``RETRYING`` rows and calls the real
   provider.
3. A send failure never raises out of the sweep -- exactly the same
   resilience contract ``app.domains.monitoring.service.NotificationService
   .dispatch_notification`` already documents for the identical reason
   (one bad row must never block every other row in the batch). It
   transitions to ``RETRYING`` (with a flat
   ``Settings.notification_retry_backoff_seconds`` backoff) until
   ``Settings.notification_max_delivery_attempts`` is exhausted, at which
   point it becomes terminal ``FAILED`` and is only re-attempted via an
   explicit ``retry_delivery`` call.

## What this domain does NOT do

It does not replace ``app.domains.monitoring``'s own Notification Engine
(``NotificationChannel``/``NotificationLog``/``NotificationService`` there)
-- that domain's alert dispatch is deliberately synchronous/immediate (a
Slack/email alert delayed behind a retry-backoff queue defeats its
purpose), and already has its own delivery record. This domain is a
generic, **recipient-addressed** outbox (a literal email address/phone
number the caller already has -- a guest, a user, an organization contact),
not an ops-configured alert-routing channel.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from app.core.storage import ObjectStorageProtocol
from app.domains.otp.service import (
    EmailProviderProtocol,
    LoggingEmailProvider,
    LoggingSmsProvider,
    SmsProviderProtocol,
)
from app.domains.router_provisioning.service import render_template

from .constants import (
    DISPATCH_SWEEP_BATCH_SIZE,
    NotificationChannelType,
    NotificationDeliveryStatus,
    NotificationEventType,
)
from .events import (
    NotificationDelivered,
    NotificationDeliveryFailed,
    NotificationEnqueued,
)
from .exceptions import (
    CrossOrganizationNotificationAccessError,
    NotificationDeliveryNotFoundError,
    NotificationDeliveryNotRetryableError,
    NotificationTemplateNotFoundError,
    NotificationTemplateNotFoundForEventError,
)
from .models import NotificationDelivery, NotificationTemplate
from .repository import NotificationRepositoryProtocol
from .validators import validate_recipient

logger = logging.getLogger(__name__)


@dataclass
class DispatchSummary:
    attempted: int = 0
    sent: int = 0
    retrying: int = 0
    failed: int = 0


class NotificationService:
    """Core notification business logic: template CRUD, ``enqueue``/
    ``render_and_enqueue`` (the outbox write), and ``dispatch_pending``
    (the sweep's real send + status transition). See module docstring for
    the full design."""

    def __init__(
        self,
        repository: NotificationRepositoryProtocol,
        *,
        object_storage: ObjectStorageProtocol | None = None,
        email_provider: EmailProviderProtocol | None = None,
        sms_provider: SmsProviderProtocol | None = None,
        max_attempts: int = 5,
        retry_backoff_seconds: int = 300,
    ) -> None:
        self.repository = repository
        self.object_storage = object_storage
        self.email_provider: EmailProviderProtocol = (
            email_provider or LoggingEmailProvider()
        )
        self.sms_provider: SmsProviderProtocol = sms_provider or LoggingSmsProvider()
        self.max_attempts = max_attempts
        self.retry_backoff_seconds = retry_backoff_seconds

    # ========================================================================
    # Templates
    # ========================================================================

    async def create_template(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        event_type: str,
        channel: str,
        body_template: str,
        subject_template: str | None = None,
        is_active: bool = True,
    ) -> NotificationTemplate:
        return await self.repository.create_template(
            organization_id=requesting_organization_id,
            event_type=event_type,
            channel=channel,
            subject_template=subject_template,
            body_template=body_template,
            is_active=is_active,
            created_by=actor_user_id,
        )

    async def get_template(
        self,
        template_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> NotificationTemplate:
        template = await self.repository.get_template_by_id(template_id)
        if template is None:
            raise NotificationTemplateNotFoundError(template_id)
        self._enforce_scope(template.organization_id, requesting_organization_id)
        return template

    async def update_template(
        self,
        template_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
        data: dict[str, object],
    ) -> NotificationTemplate:
        template = await self.get_template(
            template_id, requesting_organization_id=requesting_organization_id
        )
        return await self.repository.update_template(template, data)

    async def list_templates(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
    ):
        return await self.repository.list_templates(
            requesting_organization_id=requesting_organization_id,
            page=page,
            page_size=page_size,
        )

    # ========================================================================
    # Outbox write (synchronous, fast, local)
    # ========================================================================

    async def enqueue(
        self,
        *,
        event_type: NotificationEventType,
        channel: NotificationChannelType,
        recipient: str,
        body: str,
        organization_id: uuid.UUID | None,
        subject: str | None = None,
        template_id: uuid.UUID | None = None,
        attachment_storage_key: str | None = None,
        attachment_filename: str | None = None,
        context: dict[str, object] | None = None,
    ) -> NotificationDelivery:
        validate_recipient(recipient, channel)
        delivery = await self.repository.create_delivery(
            organization_id=organization_id,
            template_id=template_id,
            event_type=event_type.value,
            channel=channel.value,
            recipient=recipient,
            subject=subject,
            body=body,
            status=NotificationDeliveryStatus.PENDING.value,
            attempt_count=0,
            max_attempts=self.max_attempts,
            next_attempt_at=None,
            sent_at=None,
            error_message=None,
            attachment_storage_key=attachment_storage_key,
            attachment_filename=attachment_filename,
            context=context,
        )
        event = NotificationEnqueued(
            delivery_id=delivery.id, event_type=event_type.value, channel=channel.value
        )
        logger.info("notification_enqueued", extra=vars(event))
        return delivery

    async def render_and_enqueue(
        self,
        *,
        event_type: NotificationEventType,
        channel: NotificationChannelType,
        recipient: str,
        organization_id: uuid.UUID | None,
        variables: Mapping[str, str],
        attachment_storage_key: str | None = None,
        attachment_filename: str | None = None,
    ) -> NotificationDelivery:
        """Same as :meth:`enqueue`, but renders subject/body from the
        active ``NotificationTemplate`` for ``(event_type, channel)``
        (org-specific if one exists, else the platform default) instead of
        the caller building the strings itself. Raises
        ``NotificationTemplateNotFoundForEventError`` if neither exists --
        no silent fallback to a fabricated message."""
        template = await self.repository.find_active_template(
            organization_id=organization_id,
            event_type=event_type.value,
            channel=channel.value,
        )
        if template is None:
            raise NotificationTemplateNotFoundForEventError(
                event_type.value, channel.value
            )
        body = render_template(template.body_template, variables)
        subject = (
            render_template(template.subject_template, variables)
            if template.subject_template
            else None
        )
        return await self.enqueue(
            event_type=event_type,
            channel=channel,
            recipient=recipient,
            subject=subject,
            body=body,
            organization_id=organization_id,
            template_id=template.id,
            attachment_storage_key=attachment_storage_key,
            attachment_filename=attachment_filename,
        )

    # ========================================================================
    # Deliveries (query/retry)
    # ========================================================================

    async def get_delivery(
        self,
        delivery_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> NotificationDelivery:
        delivery = await self.repository.get_delivery_by_id(delivery_id)
        if delivery is None:
            raise NotificationDeliveryNotFoundError(delivery_id)
        self._enforce_scope(delivery.organization_id, requesting_organization_id)
        return delivery

    async def list_deliveries(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        status: str | None = None,
        event_type: str | None = None,
        page: int = 1,
        page_size: int = 25,
    ):
        return await self.repository.list_deliveries(
            requesting_organization_id=requesting_organization_id,
            status=status,
            event_type=event_type,
            page=page,
            page_size=page_size,
        )

    async def retry_delivery(
        self,
        delivery_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
    ) -> NotificationDelivery:
        delivery = await self.get_delivery(
            delivery_id, requesting_organization_id=requesting_organization_id
        )
        if delivery.status != NotificationDeliveryStatus.FAILED.value:
            raise NotificationDeliveryNotRetryableError(delivery_id)
        return await self.repository.update_delivery(
            delivery,
            {
                "status": NotificationDeliveryStatus.PENDING.value,
                "next_attempt_at": None,
                "error_message": None,
            },
        )

    # ========================================================================
    # Dispatch sweep (app.domains.notification.tasks
    # .run_notification_dispatch_sweep)
    # ========================================================================

    async def dispatch_pending(
        self, *, batch_size: int = DISPATCH_SWEEP_BATCH_SIZE
    ) -> DispatchSummary:
        due = await self.repository.list_due_deliveries(
            statuses=[
                NotificationDeliveryStatus.PENDING.value,
                NotificationDeliveryStatus.RETRYING.value,
            ],
            now=datetime.now(UTC),
            limit=batch_size,
        )
        summary = DispatchSummary()
        for delivery in due:
            summary.attempted += 1
            outcome_status = await self._attempt_delivery(delivery)
            if outcome_status == NotificationDeliveryStatus.SENT:
                summary.sent += 1
            elif outcome_status == NotificationDeliveryStatus.RETRYING:
                summary.retrying += 1
            else:
                summary.failed += 1
        return summary

    async def _attempt_delivery(
        self, delivery: NotificationDelivery
    ) -> NotificationDeliveryStatus:
        try:
            if delivery.channel == NotificationChannelType.EMAIL.value:
                await self.email_provider.send(
                    delivery.recipient, delivery.subject or "", delivery.body
                )
            else:
                await self.sms_provider.send(delivery.recipient, delivery.body)
        except Exception as exc:  # noqa: BLE001 -- a real provider failure must
            # never crash the sweep; see NotificationDeliveryFailed's own
            # module docstring cross-reference to
            # app.domains.monitoring.service.NotificationService's
            # identical resilience contract.
            return await self._record_failure(delivery, exc)

        attempt_count = delivery.attempt_count + 1
        await self.repository.update_delivery(
            delivery,
            {
                "status": NotificationDeliveryStatus.SENT.value,
                "sent_at": datetime.now(UTC),
                "attempt_count": attempt_count,
            },
        )
        event = NotificationDelivered(
            delivery_id=delivery.id,
            event_type=delivery.event_type,
            channel=delivery.channel,
            attempt_count=attempt_count,
        )
        logger.info("notification_delivered", extra=vars(event))
        return NotificationDeliveryStatus.SENT

    async def _record_failure(
        self, delivery: NotificationDelivery, exc: Exception
    ) -> NotificationDeliveryStatus:
        attempt_count = delivery.attempt_count + 1
        is_terminal = attempt_count >= delivery.max_attempts
        next_status = (
            NotificationDeliveryStatus.FAILED
            if is_terminal
            else NotificationDeliveryStatus.RETRYING
        )
        await self.repository.update_delivery(
            delivery,
            {
                "attempt_count": attempt_count,
                "error_message": str(exc),
                "status": next_status.value,
                "next_attempt_at": (
                    None
                    if is_terminal
                    else datetime.now(UTC)
                    + timedelta(seconds=self.retry_backoff_seconds)
                ),
            },
        )
        event = NotificationDeliveryFailed(
            delivery_id=delivery.id,
            event_type=delivery.event_type,
            channel=delivery.channel,
            attempt_count=attempt_count,
            error_message=str(exc),
            is_terminal=is_terminal,
        )
        logger.warning("notification_delivery_failed", extra=vars(event))
        return next_status

    # ========================================================================
    # Internal
    # ========================================================================

    def _enforce_scope(
        self,
        resource_organization_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> None:
        if requesting_organization_id is None:
            return
        if resource_organization_id not in (None, requesting_organization_id):
            raise CrossOrganizationNotificationAccessError()


__all__ = ["NotificationService", "DispatchSummary"]
