"""Pure validation helpers for the Port Forwarding Management domain --
no I/O, easy to unit-test in isolation (mirrors every other domain's own
``validators.py`` convention).
"""

from __future__ import annotations

import ipaddress

from .constants import MAX_PORT, MIN_PORT, PortForwardingProtocol
from .exceptions import InvalidAddressError, InvalidPortError


def validate_port(field_name: str, port: int) -> None:
    """Raises :class:`~.exceptions.InvalidPortError` unless ``port`` falls
    within the real 1-65535 usable range."""
    if not (MIN_PORT <= port <= MAX_PORT):
        raise InvalidPortError(field_name, port)


def validate_address(field_name: str, value: str | None) -> None:
    """No-op if ``value`` is ``None`` -- optional field ("any"). Otherwise
    raises :class:`~.exceptions.InvalidAddressError` unless it is a real,
    parseable IP address or CIDR block."""
    if value is None:
        return
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise InvalidAddressError(field_name, value) from exc


def validate_ip_address(field_name: str, value: str) -> None:
    """Raises :class:`~.exceptions.InvalidAddressError` unless ``value``
    is a real, parseable single-host IP address -- unlike
    :func:`validate_address`, CIDR notation is not accepted here (a
    DSTNAT rule's own internal target is always exactly one host, never
    a range -- see ``models.PortForwardingRule``'s own module docstring)."""
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise InvalidAddressError(field_name, value) from exc


def protocols_overlap(protocol_a: str, protocol_b: str) -> bool:
    """``BOTH`` overlaps every protocol value (mirrors a real RouterOS
    DSTNAT rule with no ``protocol`` restriction matching every
    transport) -- otherwise two rules only overlap if they specify the
    exact same protocol."""
    if protocol_a == PortForwardingProtocol.BOTH.value:
        return True
    if protocol_b == PortForwardingProtocol.BOTH.value:
        return True
    return protocol_a == protocol_b


def addresses_overlap(address_a: str | None, address_b: str | None) -> bool:
    """``None`` (the "any address" wildcard) overlaps every other value.
    Otherwise two already-validated IP/CIDR values overlap iff their
    networks actually intersect (``ipaddress`` network ``.overlaps``)."""
    if address_a is None or address_b is None:
        return True
    return ipaddress.ip_network(address_a, strict=False).overlaps(
        ipaddress.ip_network(address_b, strict=False)
    )


__all__ = [
    "validate_port",
    "validate_address",
    "validate_ip_address",
    "protocols_overlap",
    "addresses_overlap",
]
