"""Pure, side-effect-free validation for the OTP domain.

Mirrors ``app.domains.wireguard.validators``/``app.domains.router_provisioning
.validators``'s identical discipline: no I/O, just "is this a legal input"
checks the service layer can call before touching the database or Redis.

A simple regex is used for both channels rather than adding a new
dependency (e.g. ``phonenumbers``, ``email-validator``) -- this module only
needs to catch obviously-malformed input before generating and "sending" a
code, not perform carrier-grade phone number validation or full RFC 5322
email parsing. Neither is available anywhere else in this codebase either.
"""

from __future__ import annotations

import re

from .constants import OtpChannel
from .exceptions import InvalidOtpIdentifierError

# E.164-ish: optional leading '+', 8-15 digits, first digit non-zero. Loose
# on purpose -- real-world phone formatting varies far more than a single
# regex could ever fully capture; this only rejects obviously-malformed
# input (empty, letters, too short/long).
_PHONE_RE = re.compile(r"^\+?[1-9]\d{7,14}$")

# Loose "local@domain.tld" shape -- intentionally not a full RFC 5322
# parser (no dependency in this codebase does that), just enough to reject
# obviously-malformed input.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def validate_identifier(identifier: str, channel: OtpChannel) -> None:
    """Raises ``InvalidOtpIdentifierError`` if ``identifier`` is not a
    plausible phone number (``SMS``) or email address (``EMAIL``) for the
    given channel."""
    if channel == OtpChannel.SMS:
        if not _PHONE_RE.match(identifier):
            raise InvalidOtpIdentifierError(channel.value, identifier)
    else:
        if not _EMAIL_RE.match(identifier):
            raise InvalidOtpIdentifierError(channel.value, identifier)


__all__ = ["validate_identifier"]
