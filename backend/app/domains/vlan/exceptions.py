"""VLAN Management domain exceptions.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide exception handler / ``ApiResponse`` envelope exactly like every
other domain's exception hierarchy -- no route needs its own try/except
translation.
"""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError

from .constants import MAX_VLAN_ID, MIN_VLAN_ID

__all__ = [
    "VlanError",
    "VlanNotFoundError",
    "CrossOrganizationVlanAccessError",
    "VlanIdAlreadyExistsError",
    "InvalidVlanIdError",
    "InvalidCidrError",
    "InvalidGatewayIpAddressError",
]


class VlanError(CloudGuestError):
    """Base exception for VLAN Management domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class VlanNotFoundError(VlanError):
    def __init__(self, vlan_id: uuid.UUID | str) -> None:
        super().__init__(
            f"VLAN not found: {vlan_id}", status_code=status.HTTP_404_NOT_FOUND
        )


class CrossOrganizationVlanAccessError(VlanError):
    """A caller acting within organization A attempted to read/mutate a
    VLAN belonging to organization B -- mirrors
    ``app.domains.isp.exceptions.CrossOrganizationIspLinkAccessError``."""

    def __init__(self) -> None:
        super().__init__(
            "Cannot access a VLAN belonging to another organization",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class VlanIdAlreadyExistsError(VlanError):
    """A router may not hold two non-deleted ``Vlan`` rows with the same
    ``vlan_id`` -- raised by ``create_vlan``/``update_vlan`` when a
    duplicate is requested for the same router."""

    def __init__(self, router_id: uuid.UUID, vlan_id: int) -> None:
        super().__init__(
            f"Router '{router_id}' already has a VLAN with vlan_id {vlan_id}",
            status_code=status.HTTP_409_CONFLICT,
        )


class InvalidVlanIdError(VlanError):
    """Raised when ``vlan_id`` falls outside IEEE 802.1Q's real 1-4094
    usable range -- see ``constants.MIN_VLAN_ID``/``MAX_VLAN_ID``."""

    def __init__(self, vlan_id: int) -> None:
        super().__init__(
            f"Invalid vlan_id {vlan_id}: must be between "
            f"{MIN_VLAN_ID} and {MAX_VLAN_ID}",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )


class InvalidCidrError(VlanError):
    """Raised when ``cidr`` is supplied but is not a real, parseable CIDR
    block (validated via Python's own ``ipaddress`` module)."""

    def __init__(self, cidr: str) -> None:
        super().__init__(
            f"Invalid CIDR block: '{cidr}'",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )


class InvalidGatewayIpAddressError(VlanError):
    """Raised when ``gateway_ip_address`` is supplied but is not a real,
    parseable IP address (validated via Python's own ``ipaddress``
    module)."""

    def __init__(self, gateway_ip_address: str) -> None:
        super().__init__(
            f"Invalid gateway IP address: '{gateway_ip_address}'",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
