"""Pure validation helpers for the Network Device (NAC) domain -- no I/O,
easy to unit-test in isolation.

MAC address format validation is a trivial, one-line pure-string check --
mirrors ``app.domains.router_provisioning.validators
.validate_mac_address_format``'s own explicit precedent of duplicating
this exact check per-domain rather than importing it (neither
``app.domains.router.service``'s own normalizer nor
``router_provisioning``'s is exported for cross-domain reuse, and this is
"not a re-implementation of any business rule" per that module's own
docstring). Vendor OUI lookup is different -- a genuine, non-trivial data
table (``OUI_VENDOR_PREFIXES``) -- so that one *is* reused directly from
``app.domains.connected_devices.validators.vendor_from_mac`` rather than
duplicated (see ``service.py``).
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
