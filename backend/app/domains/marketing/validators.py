"""Pure functions for the Guest Marketing domain: template variables and
rendering, SMS length/encoding/segments, address normalization, PII masking,
and the email HTML sanitizer. No I/O, so every rule here is unit-testable on
its own (contract §5.0 and §5.4).
"""

from __future__ import annotations

import html
import math
import re
from dataclasses import dataclass
from datetime import UTC, datetime, time, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import nh3

from .constants import (
    CAMPAIGN_VARIABLE_MAX_LENGTHS,
    DEFAULT_TIMEZONE,
    SMS_MAX_RAW_LENGTH,
    SMS_MAX_SEGMENTS,
    TEMPLATE_VARIABLES,
    WORST_CASE_VARIABLE_LENGTHS,
    Channel,
)

# ---------------------------------------------------------------------------
# Template variables
# ---------------------------------------------------------------------------

_VARIABLE_PATTERN = re.compile(r"\{\{([a-z_]+)\}\}")


class TemplateVariableError(ValueError):
    """A body references a variable outside the closed set, or has a
    malformed brace. ``variables`` lists the offending names/fragments."""

    def __init__(self, variables: list[str]) -> None:
        self.variables = variables
        super().__init__(f"Unknown or malformed variables: {', '.join(variables)}")


def extract_variables(text: str | None) -> list[str]:
    """Variables referenced by ``text``, in first-seen order. Raises
    ``TemplateVariableError`` for a name outside ``TEMPLATE_VARIABLES`` or a
    brace that is not part of a well-formed ``{{name}}``."""
    if not text:
        return []
    found: list[str] = []
    unknown: list[str] = []
    for match in _VARIABLE_PATTERN.finditer(text):
        name = match.group(1)
        if name not in TEMPLATE_VARIABLES:
            unknown.append(name)
        elif name not in found:
            found.append(name)
    residue = _VARIABLE_PATTERN.sub("", text)
    if "{{" in residue or "}}" in residue:
        for fragment in re.findall(r"\{\{[^}]{0,40}\}?\}?|\}\}", residue):
            unknown.append(fragment)
    if unknown:
        raise TemplateVariableError(sorted(set(unknown)))
    return found


def render(
    text: str | None, values: dict[str, str], *, escape_html: bool = False
) -> str:
    """Substitute every ``{{name}}``. A variable with no value renders as
    the empty string (the preview endpoint reports it in
    ``missing_variables``). Values are HTML-escaped for email bodies so a
    guest's display name can never inject markup."""
    if not text:
        return ""

    def _sub(match: re.Match[str]) -> str:
        value = values.get(match.group(1)) or ""
        return html.escape(value, quote=True) if escape_html else value

    return _VARIABLE_PATTERN.sub(_sub, text)


# ---------------------------------------------------------------------------
# SMS length / encoding / segments
# ---------------------------------------------------------------------------

_GSM7_BASIC = set(
    "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?"
    "¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà"
)
_GSM7_EXTENSION = set("^{}\\[~]|€\f")


@dataclass(frozen=True)
class SmsStats:
    length: int
    encoding: str
    segments: int


def sms_stats(text: str) -> SmsStats:
    """GSM-7: 160 chars in one segment, 153 per segment beyond that
    (extension characters count double). Any other character switches the
    whole message to UCS-2: 70, then 67."""
    if all(ch in _GSM7_BASIC or ch in _GSM7_EXTENSION for ch in text):
        units = sum(2 if ch in _GSM7_EXTENSION else 1 for ch in text)
        segments = 1 if units <= 160 else math.ceil(units / 153)
        return SmsStats(length=units, encoding="gsm7", segments=max(segments, 1))
    # UCS-2 counts UTF-16 code units (an emoji is two).
    units = len(text.encode("utf-16-le")) // 2
    segments = 1 if units <= 70 else math.ceil(units / 67)
    return SmsStats(length=units, encoding="ucs2", segments=max(segments, 1))


# The rendering bound (contract change 2026-09-25, §13.4): name variables are
# truncated to the lengths the worst-case check assumes, so the segments a
# recipient actually gets can never exceed ``sms_worst_case_segments``.
RENDER_TRUNCATION: dict[str, int] = {
    "guest_name": 20,
    "venue_name": 30,
    "location_name": 30,
}


def bound_values(values: dict[str, str]) -> dict[str, str]:
    """Apply the rendering bound: names to ``RENDER_TRUNCATION``, campaign
    variables to ``CAMPAIGN_VARIABLE_MAX_LENGTHS`` (already enforced on
    write; re-applied so a render can never exceed it). Links are never
    truncated -- a cut URL is a broken URL."""
    bounded = dict(values)
    for name, limit in {**RENDER_TRUNCATION, **CAMPAIGN_VARIABLE_MAX_LENGTHS}.items():
        value = bounded.get(name)
        if value and len(value) > limit:
            bounded[name] = value[:limit].rstrip()
    return bounded


def sms_worst_case_segments(
    body: str, *, unsubscribe_link_length: int = 0, review_link_length: int = 0
) -> int:
    """Segments when every variable renders at its maximum length. The
    unsubscribe link is taken at ``max(30, unsubscribe_link_length)`` -- the
    real link (base URL + ``/u/`` + token) is usually longer than 30 -- and
    the review link at ``max(30, review_link_length)`` (links are never
    truncated, so the credits reservation must budget the real one)."""
    lengths = dict(WORST_CASE_VARIABLE_LENGTHS)
    lengths["unsubscribe_link"] = max(
        lengths["unsubscribe_link"], unsubscribe_link_length
    )
    lengths["review_link"] = max(lengths["review_link"], review_link_length)
    worst = render(body, {name: "x" * length for name, length in lengths.items()})
    return sms_stats(worst).segments


def sms_body_problems(body: str, *, unsubscribe_link_length: int = 0) -> str | None:
    """The first SMS rule ``body`` breaks, as an error code, or ``None``."""
    if "{{unsubscribe_link}}" not in body:
        return "unsubscribe_link_missing"
    if len(body) > SMS_MAX_RAW_LENGTH:
        return "sms_too_long"
    if (
        sms_worst_case_segments(body, unsubscribe_link_length=unsubscribe_link_length)
        > SMS_MAX_SEGMENTS
    ):
        return "sms_too_long"
    return None


# ---------------------------------------------------------------------------
# Email HTML
# ---------------------------------------------------------------------------

_EMAIL_TAGS = {
    "p", "br", "strong", "em", "a", "ul", "ol", "li", "h1", "h2", "h3",
    "img", "table", "tr", "td", "span", "small", "b", "i",
}  # fmt: skip
_EMAIL_ATTRIBUTES = {
    "a": {"href"},
    "img": {"src", "alt", "width", "height"},
    "span": {"style"},
}


def sanitize_email_html(body: str) -> str:
    """Allowlist sanitizer (nh3/ammonia, the same library the captive
    portal's ``post_login_html`` uses). Scripts, iframes, event handlers and
    ``javascript:`` URLs are stripped. ``{{variable}}`` placeholders survive
    because braces are plain text to the sanitizer."""
    return nh3.clean(
        body,
        tags=_EMAIL_TAGS,
        attributes=_EMAIL_ATTRIBUTES,
        url_schemes={"http", "https", "mailto"},
        link_rel="noopener noreferrer",
    )


def _restore_placeholders_in_urls(body: str) -> str:
    """nh3 percent-encodes ``{{`` inside an ``href``; put placeholders back."""
    return body.replace("%7B%7B", "{{").replace("%7D%7D", "}}")


def clean_email_html(body: str) -> str:
    return _restore_placeholders_in_urls(sanitize_email_html(body))


# ---------------------------------------------------------------------------
# Addresses
# ---------------------------------------------------------------------------

_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_PHONE_CHARS = re.compile(r"[\s\-().]")


def normalize_email(value: str | None) -> str | None:
    if not value:
        return None
    candidate = value.strip().lower()
    return candidate if _EMAIL_PATTERN.match(candidate) else None


def looks_like_email(value: str | None) -> bool:
    return bool(value) and "@" in value  # type: ignore[operator]


def normalize_phone(value: str | None) -> str | None:
    """E.164, or ``None`` when ``value`` is not a usable phone number. A
    bare 10-digit Indian mobile (6-9 prefix) gets ``+91``."""
    if not value or "@" in value:
        return None
    raw = _PHONE_CHARS.sub("", value.strip())
    if raw.startswith("+"):
        digits = raw[1:]
        if digits.isdigit() and 8 <= len(digits) <= 15 and digits[0] != "0":
            return f"+{digits}"
        return None
    if not raw.isdigit():
        return None
    if len(raw) == 10 and raw[0] in "6789":
        return f"+91{raw}"
    if len(raw) == 12 and raw.startswith("91") and raw[2] in "6789":
        return f"+{raw}"
    if len(raw) == 11 and raw.startswith("0") and raw[1] in "6789":
        return f"+91{raw[1:]}"
    return None


def looks_like_phone(value: str | None) -> bool:
    """Digit-shaped enough that a failed normalization is an *invalid*
    address rather than *no* address."""
    if not value or "@" in value:
        return False
    raw = _PHONE_CHARS.sub("", value.strip()).lstrip("+")
    return raw.isdigit() and len(raw) >= 5


@dataclass(frozen=True)
class AddressResult:
    address: str | None
    problem: str | None  # "no_address" | "invalid_address" | None


def derive_address(
    channel: Channel, *, identifier: str | None, email: str | None
) -> AddressResult:
    """The guest's usable address for ``channel`` (contract §5.0)."""
    if channel in (Channel.SMS, Channel.WHATSAPP):
        phone = normalize_phone(identifier)
        if phone:
            return AddressResult(phone, None)
        if looks_like_phone(identifier):
            return AddressResult(None, "invalid_address")
        return AddressResult(None, "no_address")
    for candidate in (email, identifier if looks_like_email(identifier) else None):
        if candidate:
            normalized = normalize_email(candidate)
            if normalized:
                return AddressResult(normalized, None)
            return AddressResult(None, "invalid_address")
    return AddressResult(None, "no_address")


def normalize_address(channel: Channel, value: str) -> str | None:
    if channel is Channel.EMAIL:
        return normalize_email(value)
    return normalize_phone(value)


# ---------------------------------------------------------------------------
# Masking (contract §5.0: phone "+91******3210", email "r***@gmail.com")
# ---------------------------------------------------------------------------


def mask_phone(value: str | None) -> str | None:
    if not value:
        return value
    digits = re.sub(r"\D", "", value)
    if len(digits) <= 4:
        return "*" * len(digits)
    country = digits[: len(digits) - 10] if len(digits) > 10 else ""
    hidden = len(digits) - len(country) - 4
    prefix = f"+{country}" if country else ""
    return f"{prefix}{'*' * hidden}{digits[-4:]}"


def mask_email_address(value: str | None) -> str | None:
    if not value or "@" not in value:
        return "***" if value else value
    local, _, domain = value.partition("@")
    return f"{local[:1]}***@{domain}"


def mask_address(channel: Channel | str, value: str | None) -> str | None:
    if Channel(channel) is Channel.EMAIL:
        return mask_email_address(value)
    return mask_phone(value)


# ---------------------------------------------------------------------------
# Quiet hours
# ---------------------------------------------------------------------------


def organization_zone(tz_name: str | None) -> ZoneInfo:
    for candidate in (tz_name, DEFAULT_TIMEZONE):
        if not candidate:
            continue
        try:
            return ZoneInfo(candidate)
        except (ZoneInfoNotFoundError, ValueError):
            continue
    return ZoneInfo("UTC")


def _parse_hhmm(value: str) -> time:
    hours, minutes = value.split(":", 1)
    return time(int(hours), int(minutes))


def in_quiet_hours(at: datetime, *, start: str, end: str, zone: ZoneInfo) -> bool:
    local = at.astimezone(zone).time()
    quiet_start, quiet_end = _parse_hhmm(start), _parse_hhmm(end)
    if quiet_start <= quiet_end:
        return quiet_start <= local < quiet_end
    return local >= quiet_start or local < quiet_end


def next_allowed_at(at: datetime, *, start: str, end: str, zone: ZoneInfo) -> datetime:
    """The first instant at or after ``at`` outside quiet hours (UTC)."""
    if not in_quiet_hours(at, start=start, end=end, zone=zone):
        return at
    local = at.astimezone(zone)
    quiet_end = _parse_hhmm(end)
    candidate = local.replace(
        hour=quiet_end.hour, minute=quiet_end.minute, second=0, microsecond=0
    )
    if candidate <= local:
        candidate = candidate + timedelta(days=1)
    return candidate.astimezone(UTC)


def utc_iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
