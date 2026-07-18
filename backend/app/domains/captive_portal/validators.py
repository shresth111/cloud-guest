"""Pure, side-effect-free validation for the Captive Portal domain.

Mirrors ``app.domains.voucher.validators``/``app.domains.otp.validators``'s
identical discipline: no I/O, just "is this a legal input" checks the
service layer calls before touching the database.
"""

from __future__ import annotations

import uuid

from .constants import HEX_COLOR_PATTERN
from .exceptions import (
    InvalidDefaultConfigScopeError,
    InvalidHexColorError,
    InvalidPortalContentSourceError,
)


def validate_hex_color(value: str, *, field_name: str) -> None:
    """Raises ``InvalidHexColorError`` unless ``value`` is a 6-digit hex
    color with a leading ``#`` (e.g. ``"#1A73E8"``)."""
    if not HEX_COLOR_PATTERN.match(value):
        raise InvalidHexColorError(field_name, value)


def validate_single_content_source(
    text_value: str | None, url_value: str | None, *, field_label: str
) -> None:
    """Raises ``InvalidPortalContentSourceError`` if **both**
    ``text_value``/``url_value`` are supplied (non-``None``, non-blank) at
    once for the same content field (terms and conditions / privacy
    policy).

    Deliberately does **not** require *exactly* one to be set -- a config
    may legitimately have neither populated yet (e.g. an admin iterating on
    branding before finalizing legal text, or a config created inactive as
    a draft). What must never happen is *both* being set at once: a
    captive portal frontend rendering this config would have no
    principled way to choose which one to show, and having both persisted
    invites them silently drifting out of sync with each other. See
    ``models.CaptivePortalConfig``'s module docstring for the full
    "content fields" write-up.
    """
    has_text = bool(text_value and text_value.strip())
    has_url = bool(url_value and url_value.strip())
    if has_text and has_url:
        raise InvalidPortalContentSourceError(field_label)


def validate_default_scope(*, is_default: bool, location_id: uuid.UUID | None) -> None:
    """Raises ``InvalidDefaultConfigScopeError`` if ``is_default=True`` is
    requested alongside a non-null ``location_id`` -- ``is_default`` only
    has meaning for an organization-level config. See
    ``models.CaptivePortalConfig``'s module docstring."""
    if is_default and location_id is not None:
        raise InvalidDefaultConfigScopeError()


__all__ = [
    "validate_hex_color",
    "validate_single_content_source",
    "validate_default_scope",
]
