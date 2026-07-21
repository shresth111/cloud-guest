"""Pure validation helpers for the MAC Authorization domain -- no I/O,
easy to unit-test in isolation (mirrors every other domain's own
``validators.py`` convention).
"""

from __future__ import annotations

from datetime import datetime

from .constants import MAC_ADDRESS_PATTERN, MacAuthorizationType
from .exceptions import InvalidExpiryError, InvalidMacAddressError


def normalize_mac_address(value: str) -> str:
    """Raises :class:`~.exceptions.InvalidMacAddressError` unless
    ``value`` is a real six-octet MAC address (colon- or dash-separated,
    case-insensitive) -- returns the canonical uppercase colon-separated
    form (``"AA:BB:CC:DD:EE:FF"``), never storing whatever mixed
    case/separator the caller happened to submit."""
    match = MAC_ADDRESS_PATTERN.match(value.strip())
    if match is None:
        raise InvalidMacAddressError(value)
    octets = (
        match.group(1),
        match.group(3),
        match.group(4),
        match.group(5),
        match.group(6),
        match.group(7),
    )
    return ":".join(octet.upper() for octet in octets)


def validate_expiry(
    authorization_type: MacAuthorizationType,
    expires_at: datetime | None,
    *,
    now: datetime,
) -> None:
    """Raises :class:`~.exceptions.InvalidExpiryError` unless
    ``expires_at`` agrees with ``authorization_type``: required and in
    the future for ``TEMPORARY``, absent entirely for ``PERMANENT``."""
    if authorization_type == MacAuthorizationType.TEMPORARY:
        if expires_at is None:
            raise InvalidExpiryError("expires_at is required for a temporary entry")
        if expires_at <= now:
            raise InvalidExpiryError("expires_at must be in the future")
    elif expires_at is not None:
        raise InvalidExpiryError("expires_at must not be set for a permanent entry")


def is_expired(expires_at: datetime | None, *, now: datetime) -> bool:
    """A permanent entry (``expires_at is None``) is never expired."""
    return expires_at is not None and expires_at <= now


def is_currently_valid(
    *, is_enabled: bool, expires_at: datetime | None, now: datetime
) -> bool:
    """Whether this entry would currently authorize its own MAC address --
    enabled and (permanent or not yet expired). The real seam a future
    guest-login-integration pass would call (see module docstring's
    "deliberately does not yet compose with the guest login flow" note)."""
    return is_enabled and not is_expired(expires_at, now=now)


__all__ = [
    "normalize_mac_address",
    "validate_expiry",
    "is_expired",
    "is_currently_valid",
]
