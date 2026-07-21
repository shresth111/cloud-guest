"""Shared enums/constants for the notification domain.

See ``service.py``'s module docstring for the full outbox/dispatch design.
"""

from __future__ import annotations

from enum import StrEnum


class NotificationEventType(StrEnum):
    """What triggered a notification -- one value per real call site wired
    in this part (``app.domains.auth``, ``app.domains.voucher``,
    ``app.domains.billing``, ``app.domains.analytics``). Not exhaustive of
    every possible future event; extend additively as new callers adopt
    this domain."""

    EMAIL_VERIFICATION = "email_verification"
    PASSWORD_RESET = "password_reset"
    VOUCHER_BATCH_EXPORT = "voucher_batch_export"
    SUBSCRIPTION_RENEWAL_REMINDER = "subscription_renewal_reminder"
    SUBSCRIPTION_EXPIRY_REMINDER = "subscription_expiry_reminder"
    SCHEDULED_REPORT = "scheduled_report"
    USER_INVITED = "user_invited"


class NotificationChannelType(StrEnum):
    """Delivery channel for one ``NotificationDelivery`` row. Deliberately
    narrower than ``app.domains.monitoring.constants.NotificationChannelType``
    (EMAIL/SMS/WHATSAPP/SLACK/TEAMS/DISCORD/WEBHOOK) -- this domain is a
    recipient-addressed outbox (a literal email/phone number), not an
    ops-configured alert-routing channel, so Slack/Teams/Discord/Webhook/
    WhatsApp don't apply here. See module docstring."""

    EMAIL = "email"
    SMS = "sms"


class NotificationDeliveryStatus(StrEnum):
    """Lifecycle of one ``NotificationDelivery`` row: ``PENDING`` (written
    synchronously by ``NotificationService.enqueue``) -> ``SENT`` or, on a
    real send failure, ``RETRYING`` (until ``max_attempts`` is exhausted,
    at which point it becomes terminal ``FAILED``)."""

    PENDING = "pending"
    RETRYING = "retrying"
    SENT = "sent"
    FAILED = "failed"


# Celery task name registered in app.core.celery_app -- mirrors every other
# domain's own TASK_* constant naming convention (e.g.
# app.domains.billing.constants.TASK_RUN_INVOICE_OVERDUE_SWEEP).
TASK_RUN_NOTIFICATION_DISPATCH_SWEEP = "notification.run_notification_dispatch_sweep"

# How many PENDING/RETRYING rows one dispatch sweep tick drains at most --
# a plain module constant (not a Settings field), mirroring
# app.core.celery_app.CELERY_HEALTH_CHECK_TIMEOUT_SECONDS's own "narrow,
# single-purpose constant, not a new Settings knob" precedent.
DISPATCH_SWEEP_BATCH_SIZE = 200
