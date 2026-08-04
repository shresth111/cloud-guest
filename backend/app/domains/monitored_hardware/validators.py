"""Pure validation helpers for the Monitored Hardware domain -- no I/O,
easy to unit-test in isolation. Mirrors ``app.domains.network_device
.validators``'s identical MAC-address check (duplicated rather than
imported, per that module's own established precedent for this exact
check -- see its docstring).
"""

from __future__ import annotations

import re

from .exceptions import InvalidMacAddressError

_MAC_PATTERN = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def normalize_mac_address(value: str) -> str:
    return value.strip().upper()


def validate_mac_address(value: str) -> str:
    """Returns the normalized (uppercase, colon-separated) form, or raises
    :class:`~.exceptions.InvalidMacAddressError` if ``value`` isn't a
    real, colon-separated six-octet MAC address."""
    normalized = normalize_mac_address(value)
    if not _MAC_PATTERN.match(normalized):
        raise InvalidMacAddressError(value)
    return normalized


__all__ = ["normalize_mac_address", "validate_mac_address"]
