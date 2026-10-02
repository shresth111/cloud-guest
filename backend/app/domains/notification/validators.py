"""Pure, side-effect-free validation for the notification domain.

Mirrors ``app.domains.otp.validators``/``app.domains.wireguard.validators``'s
identical discipline: no I/O, just "is this a legal input" checks the
service layer can call before writing a row.
"""

from __future__ import annotations

from app.domains.otp.constants import OtpChannel
from app.domains.otp.exceptions import InvalidOtpIdentifierError
from app.domains.otp.validators import validate_identifier

from .constants import SLACK_ONBOARDING_RECIPIENT, NotificationChannelType
from .exceptions import InvalidNotificationRecipientError


def validate_recipient(recipient: str, channel: NotificationChannelType) -> None:
    """Raises ``InvalidNotificationRecipientError`` if ``recipient`` is not
    a plausible email address (``EMAIL``) or phone number (``SMS``) for
    ``channel``. Reuses ``app.domains.otp.validators.validate_identifier``
    as-is -- ``NotificationChannelType``/``OtpChannel`` share the identical
    ``"email"``/``"sms"`` string values, so no second regex is needed.

    ``SLACK`` is not a person and has no identifier to validate: its
    recipient is the fixed, non-secret channel label
    ``SLACK_ONBOARDING_RECIPIENT`` (see ``constants.py``). The check is an
    equality against that constant rather than "anything goes", and that
    is the point of writing it at all -- it is what makes it impossible
    for a caller to smuggle a webhook URL, an email address or anything
    else tenant-derived into a column that ends up on a Master ops
    screen. The webhook itself is resolved from ``Settings`` at dispatch
    time and never travels through this table."""
    if channel is NotificationChannelType.SLACK:
        if recipient != SLACK_ONBOARDING_RECIPIENT:
            raise InvalidNotificationRecipientError(recipient, channel.value)
        return
    try:
        validate_identifier(recipient, OtpChannel(channel.value))
    except InvalidOtpIdentifierError as exc:
        raise InvalidNotificationRecipientError(recipient, channel.value) from exc


__all__ = ["validate_recipient"]
