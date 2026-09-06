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
from dataclasses import dataclass
from datetime import datetime

from app.domains.guest.validators import normalize_identifier, normalize_mac_address

from .constants import AccessRuleType
from .exceptions import (
    CountryCodeRequiredError,
    InvalidGuestIdentifierError,
    InvalidRuleExpiryError,
    TemporaryRuleRequiresExpiryError,
)

__all__ = [
    "MAX_COUNTRY_CODE_DIGITS",
    "MIN_NATIONAL_DIGITS",
    "IdentifierMatchTerms",
    "normalize_identifier",
    "normalize_mac_address",
    "canonicalize_rule_identifier",
    "identifier_match_terms",
    "identifiers_match",
    "validate_rule_expiry",
    "validate_identifier_shape",
    "is_rule_expired",
]

# A ``GuestAccessRule.identifier`` is, per ``models.py``'s own docstring,
# "the same string ``Guest.identifier`` already holds" -- a phone number
# (SMS/WhatsApp OTP) or an email address (email OTP) -- so this domain
# accepts exactly those two shapes, the same two
# ``app.domains.otp.constants.OtpChannel`` supports today.
#
# The phone shape is E.164 and the leading "+" is **required**, which is
# where this deliberately stops mirroring ``app.domains.otp.validators``
# (whose ``_PHONE_RE`` this was copied from, "+" optional and all). That
# optional "+" is the whole reason the 2026-09 "Always Allowed matches
# nobody" defect stayed invisible for as long as it did: the customer
# dashboard's forms submitted bare national digits ("9876543210") while
# every guest signs in as E.164 ("+919876543210"), rules are resolved by
# string comparison (``repository.list_matching_guest_rules``), and *both*
# spellings validated. A bare-digit write returned 201, listed correctly,
# read back correctly, and matched nobody -- no error anywhere to point
# at. An optional "+" buys this table nothing and costs it a silently
# inert rule, so it is now mandatory and a bare number is refused with
# ``CountryCodeRequiredError``.
#
# ``app.domains.otp.validators`` keeps the looser shape on purpose and
# must not be tightened to match. It validates what a *guest* typed into a
# portal field before a code is sent, where a rejection strands a real
# person on a captive portal with no internet; this module validates what
# a venue admin typed into a back-office form, where a rejection is a
# field error they can fix in five seconds. Same regex, opposite cost of
# being strict.
_PHONE_RE = re.compile(r"^\+[1-9]\d{7,14}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# The country-code-less spelling every pre-fix row is in, and the one
# shape this module refuses rather than guesses at -- see
# ``validate_identifier_shape``.
_BARE_PHONE_RE = re.compile(r"^[1-9][0-9]{7,14}$")

# ASCII digits only. ``str.isdigit()``/``\d`` would also accept
# Arabic-Indic and other Unicode digit forms, which no E.164 number,
# RADIUS username or SQL LIKE pattern built below is ever meant to carry.
_DIGITS_RE = re.compile(r"^[0-9]+$")

# Separators a human puts in a phone number and no storage layer should
# keep: spaces (``\s`` covers NBSP), parentheses, hyphens, dots. Stripped
# before validation so "+91 98765 43210" is accepted as the E.164 number
# it plainly is rather than bounced as malformed -- an admin who is
# bounced for punctuation retypes it without the "+" next, which is the
# shape this module exists to keep out of the table.
_PHONE_NOISE_RE = re.compile(r"[\s()\-.]")

# An E.164 country calling code is 1-3 digits (ITU-T E.164 §6.2.1), and a
# national significant number worth matching on is at least 7. Together
# they bound the "same number, different spelling" search in
# ``identifier_match_terms`` -- see that function for why the search has
# to exist at all.
MAX_COUNTRY_CODE_DIGITS = 3
MIN_NATIONAL_DIGITS = 7


def canonicalize_rule_identifier(identifier: str) -> str:
    """The single spelling a rule identifier is stored in.

    Strips the surrounding whitespace ``normalize_identifier`` already
    strips, then -- for anything that is not email-shaped -- removes human
    phone formatting, leaving ``+`` and digits. It does **not** invent a
    country code for a bare number; ``validate_identifier_shape`` refuses
    that case outright, and ``CountryCodeRequiredError``'s docstring
    covers why guessing is worse than refusing.

    Email addresses are returned exactly as ``normalize_identifier`` left
    them (stripped, case preserved). Case-folding them would be a separate,
    unrelated behaviour change to a column ``Guest.identifier`` compares
    case-sensitively everywhere else.

    Deliberately *not* pushed down into
    ``app.domains.guest.validators.normalize_identifier``: that function is
    also the RADIUS ``authorize``/Accounting-Stop username normalizer
    (``GuestService._find_active_session_for_identifier``) and the guest
    identity key for every login path. Changing what it returns changes
    who a live session belongs to, fleet-wide, which is not a change that
    belongs in a fix to one back-office form.
    """
    stripped = normalize_identifier(identifier)
    if "@" in stripped:
        return stripped
    return _PHONE_NOISE_RE.sub("", stripped)


def validate_identifier_shape(identifier: str) -> None:
    """Raises unless ``identifier`` is a plausible E.164 phone number or
    email address. Which of the two is checked is auto-detected from the
    identifier's own shape (an "@" makes it an email candidate) rather
    than requiring a separate, redundant "identifier_type" field -- the
    customer dashboard's Block/Whitelist forms already know which one
    they're submitting (a mode toggle chooses the input's own shape), so
    this only needs to catch the obviously-malformed case, not
    disambiguate intent.

    Two different rejections, because they are two different problems:
    ``InvalidGuestIdentifierError`` for input that is not a phone number
    or email address at all, and ``CountryCodeRequiredError`` for a
    perfectly plausible number written without one. Only the second is
    the 2026-09 defect, and only the second has an answer the admin can
    act on ("add +91").

    Expects ``canonicalize_rule_identifier`` to have run first -- it is
    the caller's job (``GuestAccessService.create_guest_rule``) to
    normalize before validating, mirroring every other domain's
    normalize-then-validate ordering.
    """
    if "@" in identifier:
        if not _EMAIL_RE.match(identifier):
            raise InvalidGuestIdentifierError(identifier)
        return
    if _PHONE_RE.match(identifier):
        return
    if _BARE_PHONE_RE.match(identifier):
        raise CountryCodeRequiredError(identifier)
    raise InvalidGuestIdentifierError(identifier)


@dataclass(frozen=True)
class IdentifierMatchTerms:
    """Every stored spelling of one identifier that must be treated as the
    same person.

    ``exact`` holds literal values (an ``IN`` list in SQL, a membership
    test in Python). ``prefix_patterns`` holds SQL ``LIKE`` patterns in
    which ``_`` means exactly one character and ``%`` never appears --
    they cover the stored-value-is-longer direction, which no finite list
    of literals could enumerate (the country code prepended to a bare
    number could be any of a thousand digit strings).
    """

    exact: tuple[str, ...]
    prefix_patterns: tuple[str, ...]


def identifier_match_terms(identifier: str) -> IdentifierMatchTerms:
    """Every spelling of ``identifier`` that ``guest_access_rules`` may be
    holding for the same human.

    **This is the half of the 2026-09 fix that matters most.** Canonical
    writes only help rows written from now on; every row already in the
    table was written by a form that sent bare national digits, and there
    is no safe migration for them -- filling in a country code needs a
    country nobody recorded (see ``CountryCodeRequiredError``). So the
    comparison widens instead of the data being rewritten: a rule stored
    as "9876543210" matches a guest signing in as "+919876543210", and the
    reverse, without either value being guessed at or touched.

    The equivalence is "same digits, ignoring a leading + and up to
    ``MAX_COUNTRY_CODE_DIGITS`` leading digits on either side", floored at
    ``MIN_NATIONAL_DIGITS`` so short strings can never collapse into each
    other. That is looser than exact equality and it is *meant* to be, but
    the looseness has a real cost worth naming: two numbers in the same
    organization could in principle collide (one being the other minus a
    1-3 digit prefix), which on a whitelist admits a stranger and on a
    blocklist blocks the wrong person. Weighed against the alternative --
    every pre-fix rule dead, which under the per-property "whitelist-only"
    mode means the venue's own staff locked out at their own front desk --
    the bounded, per-organization false-match risk is the cheaper failure.
    It shrinks to nothing as rows are rewritten in E.164; the audit query
    in this change's commit message is how you find the ones that have not
    been.

    Non-phone identifiers (emails, anything unparseable) come back as a
    single exact term: this function never widens anything it cannot
    prove is a phone number.
    """
    candidate = canonicalize_rule_identifier(identifier)
    digits = candidate[1:] if candidate.startswith("+") else candidate
    if not _DIGITS_RE.match(digits) or len(digits) < MIN_NATIONAL_DIGITS:
        return IdentifierMatchTerms(exact=(candidate,), prefix_patterns=())

    exact: list[str] = [candidate]
    for dropped in range(MAX_COUNTRY_CODE_DIGITS + 1):
        national = digits[dropped:]
        if len(national) < MIN_NATIONAL_DIGITS:
            break
        for spelling in (national, f"+{national}"):
            if spelling not in exact:
                exact.append(spelling)

    prefix_patterns = tuple(
        f"{sign}{'_' * length}{digits}"
        for length in range(1, MAX_COUNTRY_CODE_DIGITS + 1)
        for sign in ("+", "")
    )
    return IdentifierMatchTerms(exact=tuple(exact), prefix_patterns=prefix_patterns)


def identifiers_match(stored: str, incoming: str) -> bool:
    """Pure Python mirror of the ``WHERE`` clause
    ``GuestAccessRepository.list_matching_guest_rules`` builds from
    ``identifier_match_terms``.

    Exists because the two must not drift and only one of them can be run
    without a database: this codebase's guest-access tests use an
    in-memory fake repository, so without this the widened matching would
    be asserted nowhere. ``test_guest_access`` additionally compiles the
    real statement and checks it carries exactly the terms this function
    consumes, which is what keeps the mirror honest.
    """
    terms = identifier_match_terms(incoming)
    if stored in terms.exact:
        return True
    return any(_like_matches(pattern, stored) for pattern in terms.prefix_patterns)


def _like_matches(pattern: str, value: str) -> bool:
    """``_`` matches exactly one character, as in SQL ``LIKE``.
    ``identifier_match_terms`` never emits ``%``, so this stays a
    same-length character walk rather than a regex translation."""
    if len(pattern) != len(value):
        return False
    return all(p in ("_", v) for p, v in zip(pattern, value, strict=True))


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
