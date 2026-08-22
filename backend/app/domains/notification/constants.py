"""Shared enums/constants for the notification domain.

See ``service.py``'s module docstring for the full outbox/dispatch design.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType

from app.domains.otp.service import MailIdentity


class NotificationEventType(StrEnum):
    """What triggered a notification -- one value per real call site wired
    in this part (``app.domains.auth``, ``app.domains.voucher``,
    ``app.domains.billing``, ``app.domains.analytics``,
    ``app.domains.location``). Not exhaustive of every possible future
    event; extend additively as new callers adopt this domain."""

    EMAIL_VERIFICATION = "email_verification"
    PASSWORD_RESET = "password_reset"
    VOUCHER_BATCH_EXPORT = "voucher_batch_export"
    SUBSCRIPTION_RENEWAL_REMINDER = "subscription_renewal_reminder"
    SUBSCRIPTION_EXPIRY_REMINDER = "subscription_expiry_reminder"
    SCHEDULED_REPORT = "scheduled_report"
    USER_INVITED = "user_invited"
    DEMO_REQUEST_RECEIVED = "demo_request_received"
    LOCATION_WELCOME_EMAIL = "location_welcome_email"
    # app.domains.demo_booking -- the calendar behind "Book a Demo".
    # DEMO_BOOKING_CONFIRMED is addressed to the *visitor*; the other two
    # are addressed to the internal sales inbox
    # (Settings.demo_request_notify_email).
    DEMO_BOOKING_CONFIRMED = "demo_booking_confirmed"
    DEMO_BOOKING_TEAM_NOTIFICATION = "demo_booking_team_notification"
    DEMO_BOOKING_CANCELLED = "demo_booking_cancelled"


# ============================================================================
# Which mailbox each outbox event is sent FROM
# ============================================================================
# This is the answer to "which mailbox does a password reset come from?" --
# one table, no tracing. Read it with app.domains.otp.service.MailIdentity,
# which documents what each identity resolves to.
#
#   MailIdentity.ADMIN   -> Settings.admin_smtp_* -> admin@wyfyguest.com
#   MailIdentity.DEFAULT -> Settings.smtp_*       -> sales@wyfyguest.com
#
# Only events that are deliberately routed appear here. Anything absent
# uses MailIdentity.DEFAULT, i.e. exactly the identity it used before this
# table existed -- adding an event to this table is the *only* way to move
# it, so nothing moves by accident.
#
# The ADMIN entries below are the two outbox halves of the three-flow admin@
# split; the third (guest OTP) is not an outbox event at all and names its
# identity directly in app.domains.otp.dependencies.get_otp_service.
MAIL_IDENTITY_BY_EVENT_TYPE: Mapping[NotificationEventType, MailIdentity] = (
    MappingProxyType(
        {
            # admin@wyfyguest.com -- account security and onboarding mail
            # addressed to a person using the product.
            NotificationEventType.PASSWORD_RESET: MailIdentity.ADMIN,
            NotificationEventType.LOCATION_WELCOME_EMAIL: MailIdentity.ADMIN,
            # sales@wyfyguest.com -- a commercial lead landing in the
            # mailbox that should reply to it. This is the identity it
            # already used; it is listed explicitly so the sales half of
            # the split is visible here rather than being an absence.
            NotificationEventType.DEMO_REQUEST_RECEIVED: MailIdentity.DEFAULT,
            # A demo booking is the same commercial conversation as the
            # demo request above -- the visitor's confirmation should come
            # from, and be replyable to, the mailbox that will actually run
            # the call. Listed explicitly for the same reason
            # DEMO_REQUEST_RECEIVED is: the sales half of the split stays
            # visible as a presence rather than an absence.
            NotificationEventType.DEMO_BOOKING_CONFIRMED: MailIdentity.DEFAULT,
            NotificationEventType.DEMO_BOOKING_TEAM_NOTIFICATION: (
                MailIdentity.DEFAULT
            ),
            NotificationEventType.DEMO_BOOKING_CANCELLED: MailIdentity.DEFAULT,
        }
    )
)


def mail_identity_for_event(event_type: str) -> MailIdentity:
    """Which mailbox ``event_type`` is sent from. Unknown/unrouted event
    types get ``MailIdentity.DEFAULT`` -- the identity every outbox event
    used before this table existed.

    Takes a plain ``str`` because ``NotificationDelivery.event_type`` is a
    persisted string column, and a row written before an enum member
    existed (or after one was removed) must route somewhere sane instead of
    raising inside the dispatch sweep.
    """
    try:
        known = NotificationEventType(event_type)
    except ValueError:
        return MailIdentity.DEFAULT
    return MAIL_IDENTITY_BY_EVENT_TYPE.get(known, MailIdentity.DEFAULT)


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
