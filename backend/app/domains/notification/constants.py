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
    # app.domains.customer_provisioning / app.domains.location
    # (provisioning_service) / app.domains.network_integration -- the three
    # requests the Master console's customer-onboarding flow actually makes,
    # plus the one failure event. These are the only members delivered over
    # NotificationChannelType.SLACK; see `onboarding_slack.py` for why these
    # four and not a finer-grained set.
    ONBOARDING_CUSTOMER_CREATED = "onboarding_customer_created"
    ONBOARDING_LOCATION_PROVISIONED = "onboarding_location_provisioned"
    ONBOARDING_CONTROLLER_ONBOARDED = "onboarding_controller_onboarded"
    ONBOARDING_FAILED = "onboarding_failed"


# Every event above that is delivered to Slack rather than to a person.
# Used by `validators.validate_recipient` (a Slack row's recipient is a
# channel label, not an email address) and by the router/service wiring
# that must never accidentally address one of these to a customer.
ONBOARDING_SLACK_EVENT_TYPES: frozenset[NotificationEventType] = frozenset(
    {
        NotificationEventType.ONBOARDING_CUSTOMER_CREATED,
        NotificationEventType.ONBOARDING_LOCATION_PROVISIONED,
        NotificationEventType.ONBOARDING_CONTROLLER_ONBOARDED,
        NotificationEventType.ONBOARDING_FAILED,
    }
)


# ============================================================================
# Which mailbox each outbox event is sent FROM
# ============================================================================
# This is the answer to "which mailbox does a password reset come from?" --
# one table, no tracing. Read it with app.domains.otp.service.MailIdentity,
# which documents what each identity resolves to.
#
#   MailIdentity.ADMIN   -> Settings.admin_smtp_*   -> admin@wyfyguest.com
#   MailIdentity.DEMO    -> Settings.demo_smtp_*    -> demo@wyfyguest.com
#   MailIdentity.DEFAULT -> Settings.smtp_*         -> sales@wyfyguest.com
#
# Only events that are deliberately routed appear here. Anything absent
# uses MailIdentity.DEFAULT, i.e. exactly the identity it used before this
# table existed -- adding an event to this table is the *only* way to move
# it, so nothing moves by accident.
#
# The ADMIN entries below are the two outbox halves of the three-flow admin@
# split; the third (guest OTP) is not an outbox event at all and names its
# identity directly in app.domains.otp.dependencies.get_otp_service.
#
# The DEMO entries were DEFAULT (sales@) until the demo mailbox was given
# its own credentials. They are listed explicitly for the reason every row
# here is: the routing is a presence, never an absence, so the next person
# asking "which mailbox does a demo confirmation come from?" reads it here
# instead of inferring it from what is missing.
MAIL_IDENTITY_BY_EVENT_TYPE: Mapping[NotificationEventType, MailIdentity] = (
    MappingProxyType(
        {
            # admin@wyfyguest.com -- account security and onboarding mail
            # addressed to a person using the product.
            NotificationEventType.PASSWORD_RESET: MailIdentity.ADMIN,
            NotificationEventType.LOCATION_WELCOME_EMAIL: MailIdentity.ADMIN,
            # demo@wyfyguest.com -- one commercial conversation with its own
            # mailbox: the enquiry, the confirmation, the internal heads-up
            # and the cancellation all belong in the same thread, and none of
            # them belongs in the sales mailbox that also carries quotations.
            NotificationEventType.DEMO_REQUEST_RECEIVED: MailIdentity.DEMO,
            NotificationEventType.DEMO_BOOKING_CONFIRMED: MailIdentity.DEMO,
            NotificationEventType.DEMO_BOOKING_TEAM_NOTIFICATION: (
                MailIdentity.DEMO
            ),
            NotificationEventType.DEMO_BOOKING_CANCELLED: MailIdentity.DEMO,
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
    ops-configured alert-routing channel, so Teams/Discord/Webhook/
    WhatsApp don't apply here. See module docstring.

    ``SLACK`` is the one deliberate widening of that rule, and it is
    narrow on purpose. It carries exactly the four
    ``ONBOARDING_SLACK_EVENT_TYPES`` above: Master-console onboarding
    status, which has one fixed internal destination for the whole
    platform rather than a per-tenant configuration. Its ``recipient`` is
    therefore a constant, non-secret channel label
    (``SLACK_ONBOARDING_RECIPIENT``) and never a URL -- the webhook is a
    bearer credential and is resolved from ``Settings`` at dispatch time,
    so it never reaches this table. See ``onboarding_slack.py``.

    It is still not ``app.domains.monitoring``'s Notification Engine and
    does not replace it: that domain routes *alerts* through per-
    organization ``NotificationChannel`` rows with their own encrypted
    config, immediately and without retry. This one rides the outbox, so
    an onboarding announcement survives a Slack outage and is retried,
    which is the property that matters for a record of work."""

    EMAIL = "email"
    SMS = "sms"
    SLACK = "slack"


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

# Celery task name for the ONE onboarding Slack notice that cannot be
# enqueued inside the request's own transaction -- the failure notice. See
# `app.domains.notification.tasks.record_onboarding_failure` and
# `onboarding_slack.py`'s "Why failures go through Celery" section.
TASK_RECORD_ONBOARDING_FAILURE = "notification.record_onboarding_failure"

# The `recipient` written on every Slack onboarding outbox row. A stable,
# non-secret label for a human reading `notification_deliveries` back --
# deliberately NOT the webhook URL, which is a bearer credential and is
# resolved from Settings at dispatch time instead.
SLACK_ONBOARDING_RECIPIENT = "slack:master-onboarding"
