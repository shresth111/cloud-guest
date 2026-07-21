"""Pure validation helpers for the DHCP Pool Management domain -- no I/O,
easy to unit-test in isolation (mirrors every other domain's own
``validators.py`` convention).
"""

from __future__ import annotations

import ipaddress

from .exceptions import InvalidAddressRangeError, InvalidIpAddressError


def validate_ip_address(field_name: str, value: str | None) -> None:
    """No-op if ``value`` is ``None`` -- optional field. Otherwise raises
    :class:`~.exceptions.InvalidIpAddressError` unless it is a real,
    parseable IP address."""
    if value is None:
        return
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise InvalidIpAddressError(field_name, value) from exc


def validate_address_range(start: str, end: str) -> None:
    """Raises :class:`~.exceptions.InvalidAddressRangeError` unless both
    ``start``/``end`` are real, parseable IP addresses of the same family
    and ``start`` is numerically less than or equal to ``end``."""
    try:
        start_ip = ipaddress.ip_address(start)
    except ValueError as exc:
        raise InvalidAddressRangeError(
            start, end, f"'{start}' is not a valid IP"
        ) from exc
    try:
        end_ip = ipaddress.ip_address(end)
    except ValueError as exc:
        raise InvalidAddressRangeError(
            start, end, f"'{end}' is not a valid IP"
        ) from exc
    if start_ip.version != end_ip.version:
        raise InvalidAddressRangeError(
            start, end, "start and end must be the same IP version"
        )
    if int(start_ip) > int(end_ip):
        raise InvalidAddressRangeError(start, end, "start must not be after end")


def ranges_overlap(start_a: str, end_a: str, start_b: str, end_b: str) -> bool:
    """Pure "do these two already-validated IP ranges overlap" check --
    ``int(start_a) <= int(end_b) and int(start_b) <= int(end_a)``, the
    standard interval-overlap test. Assumes both ranges have already
    passed :func:`validate_address_range`."""
    return int(ipaddress.ip_address(start_a)) <= int(
        ipaddress.ip_address(end_b)
    ) and int(ipaddress.ip_address(start_b)) <= int(ipaddress.ip_address(end_a))


__all__ = ["validate_ip_address", "validate_address_range", "ranges_overlap"]
