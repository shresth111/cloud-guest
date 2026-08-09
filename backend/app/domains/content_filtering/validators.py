"""Pure validation helpers for the Content Filtering domain -- no I/O,
easy to unit-test in isolation (mirrors every other domain's own
``validators.py`` convention, e.g. ``app.domains.firewall.validators``).
"""

from __future__ import annotations

import ipaddress
import re

from .constants import ContentFilterValueType
from .exceptions import InvalidContentFilterValueError

# One or more dot-separated labels, each 1-63 chars, alphanumeric with
# interior hyphens only (no leading/trailing hyphen per a label) -- the
# real DNS hostname-label grammar (RFC 1035 §2.3.1), requiring at least
# two labels so a bare single word ("localhost") is rejected the same way
# a real public domain block list always would be.
_DOMAIN_LABEL = r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
DOMAIN_PATTERN = re.compile(rf"^{_DOMAIN_LABEL}(\.{_DOMAIN_LABEL})+$")


def normalize_domain(value: str) -> str:
    """Raises :class:`~.exceptions.InvalidContentFilterValueError` unless
    ``value`` is a real, bare hostname -- no ``http(s)://`` scheme, no
    ``/path``, no ``:port``, since none of those are meaningful to
    RouterOS's own ``/ip dns static`` (see ``renderers.py``'s own
    docstring for what this value actually renders into). Returns it
    lowercased with any trailing dot stripped, never the caller's raw,
    possibly mixed-case input."""
    candidate = value.strip().lower().rstrip(".")
    if (
        not candidate
        or "/" in candidate
        or ":" in candidate
        or DOMAIN_PATTERN.match(candidate) is None
    ):
        raise InvalidContentFilterValueError(ContentFilterValueType.DOMAIN.value, value)
    return candidate


def normalize_ip_cidr(value: str) -> str:
    """Raises :class:`~.exceptions.InvalidContentFilterValueError` unless
    ``value`` is a real, parseable IPv4/IPv6 address or CIDR block --
    returns Python's own canonical ``str()`` form (e.g. strips a leading
    zero, normalizes a bare host to its own ``/32``/``/128``), never the
    caller's raw text."""
    try:
        network = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise InvalidContentFilterValueError(
            ContentFilterValueType.IP_CIDR.value, value
        ) from exc
    return str(network)


def normalize_rule_value(value_type: ContentFilterValueType, value: str) -> str:
    """Dispatches to :func:`normalize_domain`/:func:`normalize_ip_cidr`
    based on ``value_type``."""
    if value_type == ContentFilterValueType.DOMAIN:
        return normalize_domain(value)
    return normalize_ip_cidr(value)


__all__ = [
    "DOMAIN_PATTERN",
    "normalize_domain",
    "normalize_ip_cidr",
    "normalize_rule_value",
]
