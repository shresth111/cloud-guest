"""Cross-cutting PII masking: pure string-transformation functions plus a
family of Pydantic ``Annotated`` types that apply them automatically at
serialization time.

## Presentation layer only -- the database always holds the raw value

Nothing in this module ever touches a repository, a query filter, or a
database column. Masking happens exclusively when a response schema
field is serialized (``model_dump()``/the HTTP response body) -- search
and filtering anywhere in this codebase continue to operate on real,
unmasked values, because they were never masked in the first place. See
``docs/masking/FLOW.md`` for the full design write-up (including why a
plain ``ContextVar`` read, not Pydantic's own ``model_dump(context=...)``,
is the mechanism that makes ``mobile: MaskedMobile`` work in every
existing router with zero call-site changes).

## Every mask function is null-safe and idempotent

``None``/``""`` pass through unchanged. A value that already looks like
this module's own masked output (e.g. re-serializing a value that was
already masked once) is detected and returned unchanged rather than
masked a second time (which would otherwise destroy information, e.g.
stripping the literal ``X``/``*`` characters of an already-masked value
as if they were real data).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Annotated, Literal

from pydantic import PlainSerializer

from app.middleware.request_context import get_masking_context

# ============================================================================
# Pure mask functions
# ============================================================================

_MASKED_MOBILE_PATTERN = re.compile(r"^X+\d{5}$")
_MOBILE_DIGITS_PATTERN = re.compile(r"\d")
_VISIBLE_MOBILE_DIGITS = 5

_MASKED_EMAIL_LOCAL_PATTERN = re.compile(r"^.\*{4}.?$")
_EMAIL_LOCAL_MASK = "****"

_MASKED_NAME_LAST_TOKEN_PATTERN = re.compile(r"^[^\s.]\.$")

_MASKED_MAC_PATTERN = re.compile(
    r"^(?:[Xx]{2}[:-]){4}[0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}$"
)
_MAC_SEPARATOR_PATTERN = re.compile(r"[:-]")


def mask_mobile(value: str | None) -> str | None:
    """``"+91 98765 98647"`` -> ``"XXXXXXX98647"``. Strips every
    non-digit character (``+``, spaces, dashes, parens) -- the country
    code's own digits are *not* additionally stripped out (there is no
    reliable, general way to tell a 2-3 digit ISD prefix apart from the
    start of a real subscriber number without a full numbering-plan
    database), so a 12-digit ``91XXXXXXXXXX`` input masks down to 7
    leading ``X``s + the last 5 digits, exactly matching this module's
    own worked example. The last ``_VISIBLE_MOBILE_DIGITS`` (5) digits
    are always left visible; if the input has 5 or fewer digits total,
    there is nothing left to mask (the whole value already *is* "the
    last 5 digits")."""
    if not value:
        return value
    if _MASKED_MOBILE_PATTERN.match(value):
        return value
    digits = "".join(_MOBILE_DIGITS_PATTERN.findall(value))
    if not digits:
        return value
    if len(digits) <= _VISIBLE_MOBILE_DIGITS:
        return digits
    masked_count = len(digits) - _VISIBLE_MOBILE_DIGITS
    return ("X" * masked_count) + digits[-_VISIBLE_MOBILE_DIGITS:]


def mask_email(value: str | None) -> str | None:
    """``"akhilrai@gmail.com"`` -> ``"a****l@gmail.com"``. Keeps the
    local part's first and last character, replaces everything between
    them with a fixed, 4-character mask (not proportional to the actual
    local-part length) -- the domain is never masked (a masked domain
    would make the value useless even for legitimate support/delivery
    purposes, and the domain alone reveals far less than the mailbox
    name). A local part with no ``@`` at all is treated as unparseable
    and returned unchanged rather than guessed at."""
    if not value:
        return value
    if "@" not in value:
        return value
    local, _, domain = value.partition("@")
    if _MASKED_EMAIL_LOCAL_PATTERN.match(local):
        return value
    if len(local) <= 1:
        return f"{local}{_EMAIL_LOCAL_MASK}@{domain}"
    return f"{local[0]}{_EMAIL_LOCAL_MASK}{local[-1]}@{domain}"


def mask_name(value: str | None) -> str | None:
    """``"Akhil Sharma"`` -> ``"Akhil S."``. Keeps every token except the
    last as-is, reduces the last token to its first character plus a
    period. A single-token name (no surname on file) is returned
    unchanged -- there is nothing to abbreviate."""
    if not value:
        return value
    tokens = value.split()
    if not tokens:
        return value
    if _MASKED_NAME_LAST_TOKEN_PATTERN.match(tokens[-1]) and len(tokens) > 1:
        return value
    if len(tokens) == 1:
        return value
    *lead, last = tokens
    return " ".join([*lead, f"{last[0]}."])


def mask_mac(value: str | None) -> str | None:
    """``"AA:BB:CC:DD:EE:FF"`` -> ``"XX:XX:XX:XX:EE:FF"`` (last two
    octets visible). Preserves whichever separator (``:`` or ``-``) the
    input already used. A value that doesn't look like a real
    colon/dash-separated 6-octet MAC address is returned unchanged
    rather than guessed at."""
    if not value:
        return value
    if _MASKED_MAC_PATTERN.match(value):
        return value
    separator_match = _MAC_SEPARATOR_PATTERN.search(value)
    if separator_match is None:
        return value
    separator = separator_match.group(0)
    octets = value.split(separator)
    if len(octets) != 6:
        return value
    masked = ["XX"] * 4 + octets[-2:]
    return separator.join(masked)


def mask_identifier(value: str | None) -> str | None:
    """``app.domains.guest.models.Guest.identifier`` (and
    ``GuestLoginHistory.identifier``) is a single column holding
    *either* a phone number *or* an email address, whichever a guest
    presented at login -- there is no separate, typed column to hang a
    static ``MaskedMobile``/``MaskedEmail`` field annotation off of. This
    dispatches at the *value* level: an ``@`` present means treat it as
    an email, otherwise treat it as a phone number. This is a real,
    accurate test for this codebase's own two identifier shapes (an
    email always contains ``@``; a phone number never does), not a
    fragile heuristic guessing at unrelated formats."""
    if not value:
        return value
    if "@" in value:
        return mask_email(value)
    return mask_mobile(value)


# ============================================================================
# Pydantic Annotated types -- read the request-scoped MaskingContext
# directly, never Pydantic's own ``model_dump(context=...)`` (see module
# docstring for why: no router call site in this codebase passes one).
# ============================================================================


@dataclass(slots=True)
class _MaskKind:
    name: Literal["mobile", "email", "name", "mac", "identifier"]
    fn: object = field(repr=False)


def _make_serializer(kind: _MaskKind):
    def _serialize(value: str | None) -> str | None:
        if value is None:
            return value
        context = get_masking_context()
        if context.masking_enabled:
            return kind.fn(value)  # type: ignore[operator]
        # Masking bypassed for this caller -- record it so
        # RequestContextMiddleware can write the required audit row (see
        # that module's own MaskingContext docstring).
        context.accessed_kinds.append(kind.name)
        return value

    _serialize.__name__ = f"_serialize_{kind.name}"
    return _serialize


MaskedMobile = Annotated[
    str | None, PlainSerializer(_make_serializer(_MaskKind("mobile", mask_mobile)))
]
MaskedEmail = Annotated[
    str | None, PlainSerializer(_make_serializer(_MaskKind("email", mask_email)))
]
MaskedName = Annotated[
    str | None, PlainSerializer(_make_serializer(_MaskKind("name", mask_name)))
]
MaskedMac = Annotated[
    str | None, PlainSerializer(_make_serializer(_MaskKind("mac", mask_mac)))
]
MaskedIdentifier = Annotated[
    str | None,
    PlainSerializer(_make_serializer(_MaskKind("identifier", mask_identifier))),
]


__all__ = [
    "mask_mobile",
    "mask_email",
    "mask_name",
    "mask_mac",
    "mask_identifier",
    "MaskedMobile",
    "MaskedEmail",
    "MaskedName",
    "MaskedMac",
    "MaskedIdentifier",
]
