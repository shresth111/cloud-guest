"""Pure validation helpers for the VLAN Management domain -- no I/O, easy
to unit-test in isolation (mirrors every other domain's own
``validators.py`` convention).
"""

from __future__ import annotations

import ipaddress

from .constants import MAX_VLAN_ID, MIN_VLAN_ID
from .exceptions import (
    InvalidCidrError,
    InvalidGatewayIpAddressError,
    InvalidVlanIdError,
)


def validate_vlan_id(vlan_id: int) -> None:
    """Raises :class:`~.exceptions.InvalidVlanIdError` unless ``vlan_id``
    falls within IEEE 802.1Q's real 1-4094 usable range."""
    if not (MIN_VLAN_ID <= vlan_id <= MAX_VLAN_ID):
        raise InvalidVlanIdError(vlan_id)


def validate_cidr(cidr: str | None) -> None:
    """No-op if ``cidr`` is ``None`` -- optional field. Otherwise raises
    :class:`~.exceptions.InvalidCidrError` unless it is a real, parseable
    CIDR block."""
    if cidr is None:
        return
    try:
        ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise InvalidCidrError(cidr) from exc


def validate_gateway_ip_address(gateway_ip_address: str | None) -> None:
    """No-op if ``gateway_ip_address`` is ``None`` -- optional field.
    Otherwise raises :class:`~.exceptions.InvalidGatewayIpAddressError`
    unless it is a real, parseable IP address."""
    if gateway_ip_address is None:
        return
    try:
        ipaddress.ip_address(gateway_ip_address)
    except ValueError as exc:
        raise InvalidGatewayIpAddressError(gateway_ip_address) from exc


__all__ = ["validate_vlan_id", "validate_cidr", "validate_gateway_ip_address"]
