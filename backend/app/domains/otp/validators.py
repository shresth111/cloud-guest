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


def normalize_otp_identifier(identifier: str) -> str:
    """Strips whitespace and lower-cases an email address (anything
    containing ``@``); phone numbers are only stripped.

    Applied by ``OtpService.request_otp`` *and* ``verify_otp`` so the
    ``otp_requests`` row, the per-identifier Redis rate-limit key and the
    verify lookup all use one spelling: a code requested as
    ``Guest@Gmail.com`` verifies as ``guest@gmail.com``, and case variants
    of one inbox share one rate-limit window instead of each getting their
    own. Kept identical to ``app.domains.guest.validators
    .normalize_identifier`` (the guest identity key the login step stores)
    without importing it -- the guest domain depends on this one, not the
    reverse."""
    stripped = identifier.strip()
    if "@" in stripped:
        return stripped.lower()
    return stripped


def validate_identifier(identifier: str, channel: OtpChannel) -> None:
    """Raises ``InvalidOtpIdentifierError`` if ``identifier`` is not a
    plausible phone number (``SMS``/``WHATSAPP``) or email address
    (``EMAIL``) for the given channel. ``WHATSAPP`` shares ``SMS``'s
    phone-number shape -- a WhatsApp message is always addressed to a real
    phone number (``whatsapp:+1415...`` at the provider layer), never an
    email-shaped identifier."""
    if channel in (OtpChannel.SMS, OtpChannel.WHATSAPP):
        if not _PHONE_RE.match(identifier):
            raise InvalidOtpIdentifierError(channel.value, identifier)
    else:
        if not _EMAIL_RE.match(identifier):
            raise InvalidOtpIdentifierError(channel.value, identifier)


__all__ = ["normalize_otp_identifier", "validate_identifier"]
