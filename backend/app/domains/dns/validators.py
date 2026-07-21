"""Pure validation helpers for the DNS Management domain -- no I/O, easy to
unit-test in isolation (mirrors every other domain's own ``validators.py``
convention).
"""

from __future__ import annotations

import ipaddress
import re

from .constants import DnsRecordType
from .exceptions import InvalidDnsAddressError, InvalidDnsNameError

# Loose RFC 1123-ish hostname shape: labels of alphanumerics/hyphens,
# dot-separated -- intentionally not a full DNS-name grammar (no existing
# dependency in this codebase parses one), just enough to reject an
# obviously-malformed name/CNAME target, mirroring
# app.domains.otp.validators's own identical "loose, not a full parser"
# precedent.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def validate_name(name: str) -> None:
    if not _HOSTNAME_RE.match(name):
        raise InvalidDnsNameError("name", name)


def validate_address(record_type: DnsRecordType, address: str) -> None:
    """Raises unless ``address`` is the right shape for ``record_type``:
    a real IPv4 address for ``A``, a real IPv6 address for ``AAAA``, or a
    plausible hostname for ``CNAME``."""
    if record_type == DnsRecordType.A:
        try:
            ipaddress.IPv4Address(address)
        except ValueError as exc:
            raise InvalidDnsAddressError(record_type.value, address) from exc
    elif record_type == DnsRecordType.AAAA:
        try:
            ipaddress.IPv6Address(address)
        except ValueError as exc:
            raise InvalidDnsAddressError(record_type.value, address) from exc
    else:  # CNAME
        if not _HOSTNAME_RE.match(address):
            raise InvalidDnsNameError("address", address)


__all__ = ["validate_name", "validate_address"]
