"""Enumerations and fixed branding constants for the Channel Partner domain.

``ChannelPartnerStatus`` is stored as a plain ``String`` column, never a
native PostgreSQL enum type -- the same reason every other domain in this
codebase documents (see e.g. ``app.domains.quotation.constants``): adding a
new status never requires an ``ALTER TYPE`` migration, only a code change.
"""

from __future__ import annotations

from enum import StrEnum

CHANNEL_PARTNER_PRODUCT_NAME = "Wyfy Guest"

# The text `ChannelPartnerService` records on a channel when this
# deployment has no real provider wired for it (a bare `Logging*Provider`).
#
# Constants rather than inline literals because two things now depend on
# the exact wording: the service that writes it, and
# `welcome_delivery_status` below, which reads it back to tell "this
# server cannot send SMS at all" apart from "this partner's SMS failed".
# Those are different facts and the console must not present them the same
# way -- see that function's docstring.
SMS_PROVIDER_NOT_CONFIGURED = (
    "No real SMS delivery provider is configured on this server."
)
EMAIL_PROVIDER_NOT_CONFIGURED = (
    "No real email delivery provider is configured on this server."
)


class ChannelPartnerStatus(StrEnum):
    ACTIVE = "active"
    INACTIVE = "inactive"


class WelcomeDeliveryStatus(StrEnum):
    """One welcome channel's outcome, as something other than free text.

    The row stores only ``*_sent_at`` and a free-text ``*_error``, and the
    console was reading "is there any error text?" as "delivery failed".
    That conflated two unrelated facts, and on the live fleet it made every
    one of five partners show a red *Welcome failed* badge while three of
    them had had their welcome email delivered successfully -- the whole
    alarm came from SMS, which this deployment has no provider for at all.

    ``NOT_CONFIGURED`` is a property of the *server*, identical for every
    partner and unchanged by any per-partner follow-up. ``FAILED`` is a
    property of the *partner* and is worth chasing. An operator needs to
    tell them apart, so the API says which it is rather than leaving the
    console to pattern-match on a sentence.
    """

    SENT = "sent"
    NOT_CONFIGURED = "not_configured"
    FAILED = "failed"
    NOT_ATTEMPTED = "not_attempted"


def welcome_delivery_status(
    *, sent_at: object, error: str | None, not_configured_message: str
) -> WelcomeDeliveryStatus:
    """Classify one channel from the two columns the row actually stores.

    ``sent_at`` wins: a channel that recorded a send is ``SENT`` whatever
    stale error text sits beside it, because ``_send_welcome_sms``/
    ``_send_welcome_email`` clear the error on success and a resend can
    succeed after an earlier failure.
    """
    if sent_at is not None:
        return WelcomeDeliveryStatus.SENT
    if error is None:
        return WelcomeDeliveryStatus.NOT_ATTEMPTED
    if error == not_configured_message:
        return WelcomeDeliveryStatus.NOT_CONFIGURED
    return WelcomeDeliveryStatus.FAILED


__all__ = [
    "CHANNEL_PARTNER_PRODUCT_NAME",
    "EMAIL_PROVIDER_NOT_CONFIGURED",
    "SMS_PROVIDER_NOT_CONFIGURED",
    "ChannelPartnerStatus",
    "WelcomeDeliveryStatus",
    "welcome_delivery_status",
]
