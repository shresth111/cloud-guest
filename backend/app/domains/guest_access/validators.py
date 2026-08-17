"""Pure, side-effect-free validation for the Guest Access Control domain.

Mirrors ``app.domains.guest.validators``'s identical discipline: no I/O,
just "is this a legal input" checks the service layer calls before
touching the database. Reuses ``app.domains.guest.validators
.normalize_mac_address``/``normalize_identifier`` directly rather than
duplicating them -- both are pure, stateless functions with no
``guest``-specific dependency, the same "import a pure validator from
another domain" precedent ``app.domains.router_agent.service`` already
establishes for ``app.domains.router_provisioning.validators
.validate_job_belongs_to_router``.
"""

from __future__ import annotations

import re
from datetime import datetime

from app.domains.guest.validators import normalize_identifier, normalize_mac_address

from .constants import AccessRuleType
from .exceptions import (
    InvalidGuestIdentifierError,
    InvalidRuleExpiryError,
    TemporaryRuleRequiresExpiryError,
)

__all__ = [
    "normalize_identifier",
    "normalize_mac_address",
    "validate_rule_expiry",
    "validate_identifier_shape",
    "is_rule_expired",
]

# Same loose, deliberately-not-RFC-5322/E.164 shapes ``app.domains.otp
# .validators`` already validates OTP identifiers against -- duplicated
# rather than imported (those two constants are module-private there),
# mirroring this module's own ``normalize_mac_address`` precedent of
# re-declaring a small pure check per domain rather than reaching into
# another domain's private internals. A ``GuestAccessRule.identifier`` is,
# per ``models.py``'s own docstring, "the same string ``Guest.identifier``
# already holds" -- a phone number (SMS/WhatsApp OTP) or an email address
# (email OTP) -- so this domain accepts exactly those two shapes, the same
# two ``app.domains.otp.constants.OtpChannel`` supports today.
_PHONE_RE = re.compile(r"^\+?[1-9]\d{7,14}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def validate_identifier_shape(identifier: str) -> None:
    """Raises ``InvalidGuestIdentifierError`` unless ``identifier`` is a
    plausible phone number or email address. Which of the two is checked
    is auto-detected from the identifier's own shape (an "@" makes it an
    email candidate) rather than requiring a separate, redundant
    "identifier_type" field -- the customer dashboard's Block/Whitelist
    forms already know which one they're submitting (a mode toggle chooses
    the input's own shape), so this only needs to catch the
    obviously-malformed case, not disambiguate intent."""
    candidate = "@" in identifier
    if candidate:
        if not _EMAIL_RE.match(identifier):
            raise InvalidGuestIdentifierError(identifier)
    elif not _PHONE_RE.match(identifier):
        raise InvalidGuestIdentifierError(identifier)


def validate_rule_expiry(
    *, rule_type: AccessRuleType, expires_at: datetime | None, now: datetime
) -> None:
    """Raises if ``expires_at`` is missing for a ``TEMPORARY`` rule, or is
    not in the future for any rule type that supplies one. A
    ``WHITELIST``/``BLOCKLIST``/``VIP`` rule may still carry an
    ``expires_at`` (e.g. a time-bound blocklist entry) -- only ``TEMPORARY``
    *requires* one."""
    if rule_type == AccessRuleType.TEMPORARY and expires_at is None:
        raise TemporaryRuleRequiresExpiryError()
    if expires_at is not None and expires_at <= now:
        raise InvalidRuleExpiryError()


def is_rule_expired(expires_at: datetime | None, *, now: datetime) -> bool:
    """Whether a rule's own ``expires_at`` has already passed ``now``.
    Returns ``False`` for a permanent rule (``expires_at is None``)."""
    if expires_at is None:
        return False
    return expires_at <= now
