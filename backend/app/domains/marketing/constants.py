"""Constants for the Guest Marketing domain.

Every enum is stored as a plain ``String`` column (house convention: no
native PostgreSQL enums), so each ``StrEnum`` below is the closed set of
legal values for the column of the same name.
"""

from __future__ import annotations

from enum import StrEnum


class Channel(StrEnum):
    SMS = "sms"
    WHATSAPP = "whatsapp"
    EMAIL = "email"


# The order the status endpoint reports channels in (contract §5.1).
CHANNEL_ORDER: tuple[Channel, ...] = (Channel.SMS, Channel.WHATSAPP, Channel.EMAIL)


class ConsentStatus(StrEnum):
    OPTED_IN = "opted_in"
    OPTED_OUT = "opted_out"


# ``none`` is a read-side value only (no consent row exists); never stored.
CONSENT_STATUS_NONE = "none"


class ConsentSource(StrEnum):
    CAPTIVE_PORTAL = "captive_portal"
    UNSUBSCRIBE_LINK = "unsubscribe_link"
    STAFF_RECORDED = "staff_recorded"
    INBOUND_STOP = "inbound_stop"


class ConsentAction(StrEnum):
    OPT_IN = "opt_in"
    OPT_OUT = "opt_out"


class SuppressionReason(StrEnum):
    UNSUBSCRIBED = "unsubscribed"
    STAFF_RECORDED = "staff_recorded"
    HARD_BOUNCE = "hard_bounce"
    INVALID_NUMBER = "invalid_number"
    INBOUND_STOP = "inbound_stop"


class TemplateCategory(StrEnum):
    WELCOME = "welcome"
    OFFER = "offer"
    FEEDBACK = "feedback"
    FESTIVAL = "festival"
    LOYALTY = "loyalty"
    EVENT = "event"
    WINBACK = "winback"
    ANNOUNCEMENT = "announcement"
    BIRTHDAY = "birthday"
    CUSTOM = "custom"


class WhatsAppApprovalStatus(StrEnum):
    NOT_SUBMITTED = "not_submitted"
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class CampaignStatus(StrEnum):
    DRAFT = "draft"
    SCHEDULED = "scheduled"
    SENDING = "sending"
    SENT = "sent"
    FAILED = "failed"
    CANCELLED = "cancelled"


ACTIVE_CAMPAIGN_STATUSES: tuple[CampaignStatus, ...] = (
    CampaignStatus.SCHEDULED,
    CampaignStatus.SENDING,
)


class CancelReason(StrEnum):
    USER = "user"
    ADDON_LOCKED = "addon_locked"
    CHANNEL_UNCONFIGURED = "channel_unconfigured"


class RecipientStatus(StrEnum):
    PENDING = "pending"
    SENDING = "sending"
    SUBMITTED = "submitted"
    DELIVERED = "delivered"
    FAILED = "failed"
    SKIPPED = "skipped"


class SkipReason(StrEnum):
    OPTED_OUT = "opted_out"
    SUPPRESSED = "suppressed"
    NO_CONSENT = "no_consent"
    INVALID_ADDRESS = "invalid_address"
    BLOCKED = "blocked"
    ADDON_LOCKED = "addon_locked"
    CANCELLED = "cancelled"


class SendableReason(StrEnum):
    CHANNEL_NOT_CONFIGURED = "channel_not_configured"
    CHANNEL_MISSING_IN_TEMPLATE = "channel_missing_in_template"
    DLT_TEMPLATE_ID_MISSING = "dlt_template_id_missing"
    WHATSAPP_NOT_APPROVED = "whatsapp_not_approved"
    UNSUBSCRIBE_LINK_MISSING = "unsubscribe_link_missing"


class ChannelMode(StrEnum):
    LIVE = "live"
    LOGGING = "logging"
    UNCONFIGURED = "unconfigured"


# The closed set of template variables (contract §5.0 ``TemplateVariable``).
TEMPLATE_VARIABLES: frozenset[str] = frozenset(
    {
        "guest_name",
        "venue_name",
        "location_name",
        "offer_code",
        "offer_expiry",
        "event_name",
        "event_date",
        "booking_link",
        "review_link",
        "unsubscribe_link",
    }
)

# The campaign-level ``variables`` a caller may supply, with the maximum
# length of each (TRAI DLT caps a variable at 30 characters; the booking
# link is the one exception).
CAMPAIGN_VARIABLE_MAX_LENGTHS: dict[str, int] = {
    "offer_code": 30,
    "offer_expiry": 30,
    "event_name": 30,
    "event_date": 30,
    "booking_link": 200,
}

# Worst-case rendered lengths used by the SMS ``sms_too_long`` check.
WORST_CASE_VARIABLE_LENGTHS: dict[str, int] = {
    "guest_name": 20,
    "venue_name": 30,
    "location_name": 30,
    "unsubscribe_link": 30,
    "review_link": 30,
    **CAMPAIGN_VARIABLE_MAX_LENGTHS,
}

GUEST_NAME_FALLBACK = "there"
SAMPLE_GUEST_NAME = "Riya"
SAMPLE_UNSUBSCRIBE_TOKEN = "SAMPLE"

SMS_MAX_RAW_LENGTH = 1000
SMS_MAX_SEGMENTS = 3
EMAIL_MAX_BODY_BYTES = 100 * 1024
TEMPLATE_NAME_MAX_LENGTH = 120

MAX_RECIPIENTS_PER_CAMPAIGN = 5000
TEST_SENDS_PER_DAY = 20
MAX_TEST_ADDRESSES = 3

QUIET_HOURS_START = "21:00"
QUIET_HOURS_END = "09:00"
QUIET_HOURS_CHANNELS: tuple[Channel, ...] = (Channel.SMS, Channel.WHATSAPP)
DEFAULT_TIMEZONE = "Asia/Kolkata"

SCHEDULE_MIN_LEAD_MINUTES = 5
SCHEDULE_MAX_LEAD_DAYS = 60
SCHEDULE_IDEMPOTENCY_WINDOW_HOURS = 24

AUDIENCE_SAMPLE_SIZE = 10
NOT_SEEN_FOR_DAYS_MAX = 730

DEFAULT_CONSENT_TEXT = (
    "Send me offers and updates from {venue_name} by SMS, WhatsApp and email. "
    "I can unsubscribe any time."
)
DEFAULT_CONSENT_TEXT_VERSION = "v1"

# Delivery worker.
SEND_BATCH_SIZE = 50
SEND_MAX_ATTEMPTS = 3
SEND_RETRY_BACKOFF_SECONDS = 60
# Per-channel pacing inside one batch (messages per second). Conservative
# defaults well below every provider's documented account limits.
SEND_RATE_PER_SECOND: dict[Channel, float] = {
    Channel.SMS: 10.0,
    Channel.WHATSAPP: 10.0,
    Channel.EMAIL: 5.0,
}
# A recipient stuck in ``sending`` longer than this was claimed by a worker
# that died mid-send. It is NOT retried automatically: the provider may have
# accepted it, and a second send would be a duplicate message to a guest.
STALE_SENDING_MINUTES = 15

DISPATCH_SWEEP_INTERVAL_SECONDS = 60
RECIPIENT_ADDRESS_RETENTION_DAYS = 180

PUBLIC_RATE_LIMIT_PER_MINUTE = 30
PUBLIC_RATE_LIMIT_KEY_TEMPLATE = "marketing:public:rl:{ip}"
TEST_SEND_COUNTER_KEY_TEMPLATE = "marketing:testsend:{organization_id}:{day}"

TASK_DISPATCH_DUE_CAMPAIGNS = "marketing.dispatch_due_campaigns"
TASK_SEND_CAMPAIGN_BATCH = "marketing.send_campaign_batch"
TASK_PRUNE_RECIPIENT_ADDRESSES = "marketing.prune_recipient_addresses"
TASK_REAP_STUCK_RECIPIENTS = "marketing.reap_stuck_recipients"
REAP_SWEEP_INTERVAL_SECONDS = 300
PRUNE_SWEEP_INTERVAL_SECONDS = 24 * 60 * 60
MARKETING_QUEUE_NAME = "marketing"
