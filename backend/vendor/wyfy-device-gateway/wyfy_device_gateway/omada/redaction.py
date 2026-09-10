"""Secret redaction, and the credential fingerprint used as a cache key.

## Why this is a module and not three inline helpers

Two requirements in contract section 2 are absolute: nothing secret may reach
a log line or an exception message, and the session cache may be keyed on a
credential *fingerprint* but never on the credential itself. Both are easy to
satisfy at the moment you write the code and easy to break six months later
by adding one ``logger.debug("... %s", response.text)``. Concentrating the
logic here means there is exactly one place to audit, and the test suite
asserts against this module directly rather than against every call site.

## The approach: allowlist the shape, not blocklist the name

Redaction by key name alone is fragile -- it protects ``password`` and misses
``pwd``. Redaction by value alone is worse: it cannot tell a token from a MAC
address. So both are applied:

* **By key** (``SENSITIVE_KEYS``) -- for structured data (headers, JSON
  bodies, log ``extra`` dicts) where the key is known. This catches
  ``password``, ``client_secret``, ``Csrf-Token``, ``Cookie`` and the token
  fields, case-insensitively and ignoring ``-``/``_`` differences, since
  Omada spells the same concept ``client_secret`` in a body and
  ``Csrf-Token`` in a header.
* **By pattern** (``_SECRET_PATTERNS``) -- for free text, where a secret may
  appear inside a sentence: ``AccessToken=...`` and ``AT-...`` (the observed
  Omada access-token prefix), ``Cookie:``/``Set-Cookie:`` lines, and the
  ``TPOMADA_SESSIONID`` / ``TPEAP_SESSIONID`` cookie values.

Neither is complete on its own and the combination is not provably complete
either. That is why ``sanitize_detail`` additionally refuses text that looks
like a serialized payload (contains ``{``/``}`` or exceeds a length cap)
rather than trying to clean it: an unrecognised body is discarded, not
sanitized. Failing closed is the only defensible default when the cost of a
miss is a credential in a customer-visible error string.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from typing import Any

REDACTED = "***redacted***"

#: Keys whose value is never safe to render. Compared case-insensitively
#: with ``-``/``_`` normalized away, so "Csrf-Token", "csrf_token" and
#: "CSRFTOKEN" all match the one entry.
SENSITIVE_KEYS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "clientsecret",
        "client_secret",
        "clientid",
        "client_id",
        "token",
        "csrftoken",
        "accesstoken",
        "refreshtoken",
        "cookie",
        "setcookie",
        "authorization",
        "sessionid",
        "apikey",
        "credentials",
    }
)

_MAX_DETAIL_CHARS = 200

_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    # "Authorization: AccessToken=AT-xxxx" / bare "AccessToken=AT-xxxx"
    re.compile(r"AccessToken\s*=\s*\S+", re.IGNORECASE),
    re.compile(r"Bearer\s+\S+", re.IGNORECASE),
    # Omada access tokens observed in the wild carry an "AT-" prefix; refresh
    # tokens an "RT-" one. Match them even when they appear bare in prose.
    re.compile(r"\b(?:AT|RT)-[A-Za-z0-9_-]{8,}"),
    # Session cookies, whether presented as a header line or a bare pair.
    re.compile(r"(?:TPOMADA_SESSIONID|TPEAP_SESSIONID)\s*=\s*\S+", re.IGNORECASE),
    re.compile(r"(?:Set-)?Cookie\s*:\s*\S+", re.IGNORECASE),
    re.compile(r"Csrf-?Token\s*[:=]\s*\S+", re.IGNORECASE),
    # "password=hunter2" / "client_secret: abc" appearing inside free text.
    re.compile(
        r"\b(?:password|passwd|pwd|client_secret|secret)\b\s*[:=]\s*\S+",
        re.IGNORECASE,
    ),
)


def _normalize_key(key: object) -> str:
    return str(key).replace("-", "").replace("_", "").strip().lower()


def is_sensitive_key(key: object) -> bool:
    """True when a mapping key's value must never be rendered."""
    return _normalize_key(key) in SENSITIVE_KEYS


def redact_text(text: str) -> str:
    """Replace anything secret-shaped in free text with ``REDACTED``.

    Used for strings that are *expected* to be human sentences. For anything
    that might be a controller response body, use ``sanitize_detail``, which
    fails closed instead.
    """
    if not text:
        return text
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(REDACTED, text)
    return text


def redact_mapping(data: Mapping[str, Any]) -> dict[str, Any]:
    """Copy a mapping with every sensitive value replaced.

    Recurses into nested mappings and into lists of mappings, because Omada
    nests the interesting parts (``result.token``, ``result.accessToken``)
    one or two levels down and a shallow pass would sail straight past them.
    Non-sensitive string values still go through ``redact_text``: a key named
    ``msg`` is not itself sensitive but its value may quote one.
    """
    out: dict[str, Any] = {}
    for key, value in data.items():
        if is_sensitive_key(key):
            out[key] = REDACTED
        elif isinstance(value, Mapping):
            out[key] = redact_mapping(value)
        elif isinstance(value, (list, tuple)):
            out[key] = [
                redact_mapping(item)
                if isinstance(item, Mapping)
                else (redact_text(item) if isinstance(item, str) else item)
                for item in value
            ]
        elif isinstance(value, str):
            out[key] = redact_text(value)
        else:
            out[key] = value
    return out


def sanitize_detail(detail: object) -> str | None:
    """Turn a controller-supplied string into something safe to show a human.

    Fails closed. Returns ``None`` -- meaning "say nothing extra" -- when the
    input is empty, is not a string, looks like a serialized payload rather
    than a sentence, or is long enough that we cannot reasonably eyeball what
    is in it. Only short, prose-shaped, pattern-clean strings survive.

    This is what lets ``OmadaAuthError`` say *"Controller ID not exist."* --
    genuinely useful to whoever is configuring the integration -- without
    opening the door to the whole response body.
    """
    if not isinstance(detail, str):
        return None
    text = detail.strip()
    if not text:
        return None
    # A body, not a sentence. Discard rather than clean.
    if any(ch in text for ch in "{}[]") or len(text) > _MAX_DETAIL_CHARS:
        return None
    cleaned = redact_text(text)
    if REDACTED in cleaned:
        # It contained something secret-shaped. We do not know what else it
        # contains, so drop the whole thing.
        return None
    return cleaned


def credential_fingerprint(*parts: object) -> str:
    """A stable, non-reversible id for a credential set, for cache keying.

    SHA-256 over the parts, truncated to 32 hex chars. Truncation is fine
    here: this value is never a security boundary -- it never authenticates
    anything and never leaves the process -- it only has to make collisions
    between two different credential sets on the same controller
    vanishingly unlikely, so that rotating a password cannot silently reuse
    the session cached under the old one.

    ``None`` parts are encoded distinctly from empty strings so that
    "no username" and "empty username" do not fingerprint identically.
    """
    digest = hashlib.sha256()
    for part in parts:
        digest.update(b"\x00null\x00" if part is None else str(part).encode("utf-8"))
        digest.update(b"\x1f")  # unit separator: prevents "ab"+"c" == "a"+"bc"
    return digest.hexdigest()[:32]


__all__ = [
    "REDACTED",
    "SENSITIVE_KEYS",
    "credential_fingerprint",
    "is_sensitive_key",
    "redact_mapping",
    "redact_text",
    "sanitize_detail",
]
