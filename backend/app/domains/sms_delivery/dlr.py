"""Turning a provider's answer into a delivery status -- or into nothing.

The rule this module exists to enforce: a row becomes ``delivered`` or
``undelivered`` only when the provider's own answer names a recognised
delivery-report status. Anything else -- a numeric error code, an empty body,
``PENDING``, an answer shape we have never seen -- yields ``None`` and the row
stays ``sent``. Nothing is inferred from "the provider accepted it".

The token list is the carrier/SMPP DLR vocabulary Ping4SMS documents
(``DELIVRD``, ``UNDELIV``, ``EXPIRED``, ``REJECTD``, ``PENDING``) plus the
lowercase words Twilio's ``MessageStatus`` and Exotel's ``Status`` callbacks
use (``delivered``, ``undelivered``, ``failed``).
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping

from .constants import SmsDeliveryStatus

# Order matters only for readability: matching is on whole words, so
# "UNDELIVERED" never matches the DELIVERED token.
_DELIVERED_TOKENS = ("DELIVRD", "DELIVERED")
_UNDELIVERED_TOKENS = (
    "UNDELIV",
    "UNDELIVERED",
    "UNDELIVERABLE",
    "EXPIRED",
    "REJECTD",
    "REJECTED",
    "FAILED",
    "DELETED",
)

_TOKEN_RE = re.compile(r"[A-Za-z]+")

# Field names a callback or JSON answer may carry the status / id in.
STATUS_FIELDS = (
    "status",
    "dlr_status",
    "dlrstatus",
    "delivery_status",
    "MessageStatus",
    "SmsStatus",
    "Status",
)
MESSAGE_ID_FIELDS = (
    "messageid",
    "message_id",
    "msgid",
    "msg_id",
    "MessageSid",
    "SmsSid",
    "SmsMessageSid",
    "id",
)


# The SMPP-style tokens are distinctive enough to find inside free text. The
# plain English words ("failed", "rejected", "delivered") are not -- "request
# failed" is not a delivery report -- so they count only when they are the
# whole value of a status field.
_STRICT_TOKENS = frozenset({"DELIVRD", "UNDELIV", "REJECTD", "EXPIRED"})


def classify_dlr_status(
    value: str | None, *, strict: bool = False
) -> SmsDeliveryStatus | None:
    """``delivered`` / ``undelivered`` when ``value`` names a recognised final
    DLR status, else ``None`` (pending, unknown, error code, empty).

    ``strict`` is for unstructured text (a plain-text poll answer): only the
    SMPP tokens count there. Otherwise ``value`` is a status field's whole
    value and must be exactly one recognised word."""
    if not value:
        return None
    words = {word.upper() for word in _TOKEN_RE.findall(value)}
    if strict:
        words &= _STRICT_TOKENS
    elif len(words) != 1:
        return None
    if words & set(_UNDELIVERED_TOKENS):
        return SmsDeliveryStatus.UNDELIVERED
    if words & set(_DELIVERED_TOKENS):
        return SmsDeliveryStatus.DELIVERED
    return None


def first_field(data: Mapping[str, object], names: tuple[str, ...]) -> str | None:
    """First non-empty value among ``names`` (case-insensitive key match)."""
    lowered = {str(k).lower(): v for k, v in data.items()}
    for name in names:
        value = data.get(name)
        if value is None:
            value = lowered.get(name.lower())
        if value is not None and str(value).strip():
            return str(value).strip()
    return None


def parse_poll_answer(body: str) -> SmsDeliveryStatus | None:
    """Status from a DLR poll answer body.

    JSON answers are read by field name (``status`` and friends), never by
    scanning every value -- a JSON body is structured, and a stray word in
    some unrelated field must not decide delivery. Plain-text answers are
    classified on their words.
    """
    text = (body or "").strip()
    if not text:
        return None
    if text[:1] in "{[":
        try:
            parsed = json.loads(text)
        except ValueError:
            return None
        records = parsed if isinstance(parsed, list) else [parsed]
        for record in records:
            if not isinstance(record, Mapping):
                continue
            for container in (record, record.get("data")):
                if isinstance(container, Mapping):
                    status = first_field(container, STATUS_FIELDS)
                    result = classify_dlr_status(status)
                    if result is not None:
                        return result
        return None
    return classify_dlr_status(text, strict=True)


_URL_QUERY_RE = re.compile(r"(https?://[^\s?'\"<>]+)\?[^\s'\"<>]*")
_SECRET_PAIR_RE = re.compile(
    r"(?i)\b(key|api_key|apikey|token|auth_token|password|secret|sms|body)=[^&\s'\"]*"
)
_LONG_DIGITS_RE = re.compile(r"\+?\d{8,}")


def scrub(text: str | None, *, limit: int = 300) -> str | None:
    """Make provider/exception text safe to persist and show.

    httpx's ``HTTPStatusError`` message embeds the full request URL, and
    Ping4SMS takes its API key *and the OTP text* in the query string -- so
    every query string is dropped, any ``key=...``-shaped pair is redacted,
    and long digit runs (phone numbers, OTP-bearing ids) are masked.
    """
    if text is None:
        return None
    cleaned = _URL_QUERY_RE.sub(r"\1?<redacted>", str(text))
    cleaned = _SECRET_PAIR_RE.sub(r"\1=<redacted>", cleaned)
    cleaned = _LONG_DIGITS_RE.sub(
        lambda m: "*" * (len(m.group(0)) - 4) + m.group(0)[-4:], cleaned
    )
    return cleaned[:limit]


def error_code_for(exc: BaseException) -> str:
    """A short, stable code for a failed send attempt."""
    try:
        import httpx
    except ImportError:  # pragma: no cover - httpx is a hard dependency
        httpx = None  # type: ignore[assignment]
    if httpx is not None:
        if isinstance(exc, httpx.HTTPStatusError):
            return f"http_{exc.response.status_code}"
        if isinstance(exc, httpx.TimeoutException):
            return "timeout"
        if isinstance(exc, httpx.TransportError):
            return "transport_error"
    code = getattr(exc, "code", None)
    if isinstance(code, str) and code:
        return code[:64]
    return type(exc).__name__[:64]


__all__ = [
    "MESSAGE_ID_FIELDS",
    "STATUS_FIELDS",
    "classify_dlr_status",
    "error_code_for",
    "first_field",
    "parse_poll_answer",
    "scrub",
]
