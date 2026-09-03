"""Pure validation helpers for the VLAN Management domain -- no I/O, easy
to unit-test in isolation (mirrors every other domain's own
``validators.py`` convention).
"""

from __future__ import annotations

import ipaddress

from .constants import MAX_VLAN_ID, MIN_VLAN_ID
from .exceptions import (
    GatewayOutsideCidrError,
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


def validate_gateway_within_cidr(
    gateway_ip_address: str | None, cidr: str | None
) -> None:
    """Raises :class:`~.exceptions.GatewayOutsideCidrError` when both
    values are present and the gateway does not sit inside the block.

    Kept separate from the two single-value validators because it is a
    check on the *pair*: each half can be perfectly valid on its own and
    the combination still describe a router address on a subnet the VLAN
    does not have. Both being optional is real -- a tagged interface with
    no address is a legitimate VLAN -- so an absent half is a no-op here,
    not a failure.
    """
    if not gateway_ip_address or not cidr:
        return
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        gateway = ipaddress.ip_address(gateway_ip_address)
    except ValueError:
        # Each half has its own validator with its own error; re-reporting
        # a malformed value as a mismatch would name the wrong problem.
        return
    if gateway not in network:
        raise GatewayOutsideCidrError(gateway_ip_address, cidr)


__all__ = [
    "validate_vlan_id",
    "validate_cidr",
    "validate_gateway_ip_address",
    "validate_gateway_within_cidr",
]
