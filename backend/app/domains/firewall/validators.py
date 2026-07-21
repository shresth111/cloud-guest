"""Pure validation helpers for the Firewall Rule Management domain -- no
I/O, easy to unit-test in isolation. Mirrors
``app.domains.port_forwarding.validators``'s identical shape.
"""

from __future__ import annotations

import ipaddress

from .constants import MAX_PORT, MIN_PORT
from .exceptions import InvalidFirewallAddressError, InvalidFirewallPortError


def validate_port(field_name: str, port: int | None) -> None:
    """No-op if ``port`` is ``None`` -- optional field. Otherwise raises
    unless it falls within the real 1-65535 usable range."""
    if port is None:
        return
    if not (MIN_PORT <= port <= MAX_PORT):
        raise InvalidFirewallPortError(field_name, port)


def validate_address(field_name: str, value: str | None) -> None:
    """No-op if ``value`` is ``None`` -- optional field ("any"). Otherwise
    raises unless it is a real, parseable IP address or CIDR block."""
    if value is None:
        return
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise InvalidFirewallAddressError(field_name, value) from exc


__all__ = ["validate_port", "validate_address"]
