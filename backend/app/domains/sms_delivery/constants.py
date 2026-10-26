"""Constants for the SMS delivery log."""

from __future__ import annotations

from enum import StrEnum


class SmsDeliveryStatus(StrEnum):
    """Lifecycle of one send attempt.

    * ``sent`` -- the provider accepted the message (returned success, usually
      with a message id). Not proof of delivery.
    * ``failed`` -- the provider refused it, or the call itself failed
      (timeout, HTTP error). Nothing left the provider.
    * ``delivered`` / ``undelivered`` -- the provider's delivery report said
      so. Only ever reached from ``sent``, and only from a real DLR.
    """

    SENT = "sent"
    FAILED = "failed"
    DELIVERED = "delivered"
    UNDELIVERED = "undelivered"


FINAL_DLR_STATUSES = frozenset(
    {SmsDeliveryStatus.DELIVERED.value, SmsDeliveryStatus.UNDELIVERED.value}
)


class SmsPurpose(StrEnum):
    """Why the SMS was sent -- one value per real send site."""

    GUEST_OTP = "guest_otp"
    ACCOUNT_OTP = "account_otp"
    MARKETING = "marketing"
    MARKETING_TEST = "marketing_test"
    ALERT = "alert"
    NOTIFICATION = "notification"
    PARTNER_WELCOME = "partner_welcome"


class ProviderSource(StrEnum):
    """Whose provider account sent it. Only ``wyfy`` rows can be polled with
    Wyfy's own API key or matched by Wyfy's own DLR callback -- a venue's own
    (BYO) account has its own message-id space."""

    WYFY = "wyfy"
    OWN = "own"


class DlrSource(StrEnum):
    POLL = "poll"
    WEBHOOK = "webhook"


# Providers whose SMS never leave the platform. A send through one of these
# writes no row: the report counts real SMS only.
NON_SENDING_PROVIDERS = frozenset({"logging"})

# Providers this platform knows how to poll for a DLR.
POLLABLE_PROVIDERS = frozenset({"ping4sms"})

# Providers accepted on the inbound DLR callback path.
WEBHOOK_PROVIDERS = frozenset({"ping4sms", "twilio", "exotel"})

PING4SMS_DLR_URL = "https://site.ping4sms.com/api/dlrapi"

# Poller pacing: only rows sent in the last DLR_POLL_WINDOW_HOURS, at least
# DLR_POLL_MIN_AGE_SECONDS old, re-polled no more often than every
# DLR_POLL_INTERVAL_SECONDS, at most DLR_POLL_MAX_ATTEMPTS times.
DLR_POLL_WINDOW_HOURS = 72
DLR_POLL_MIN_AGE_SECONDS = 60
DLR_POLL_INTERVAL_SECONDS = 600
DLR_POLL_MAX_ATTEMPTS = 30
DLR_POLL_BATCH_SIZE = 200
DLR_POLL_SWEEP_INTERVAL_SECONDS = 300.0

RETENTION_SWEEP_INTERVAL_SECONDS = 86_400.0
RETENTION_DELETE_BATCH = 5_000

REPORT_MAX_RANGE_DAYS = 92
REPORT_DEFAULT_TIMEZONE = "Asia/Kolkata"

TASK_POLL_SMS_DLRS = "sms_delivery.poll_dlrs"
TASK_PRUNE_SMS_DELIVERY_LOGS = "sms_delivery.prune_logs"

DLR_WEBHOOK_TOKEN_HEADER = "X-Wyfy-Dlr-Token"
