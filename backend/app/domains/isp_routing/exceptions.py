"""ISP Routing domain exceptions.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide exception handler / ``ApiResponse`` envelope exactly like every
other domain's exception hierarchy -- no route needs its own try/except
translation.
"""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError

__all__ = [
    "IspRoutingError",
    "IspRoutingRuleNotFoundError",
    "CrossOrganizationIspRoutingRuleAccessError",
    "IspRoutingRuleInvalidMatchFieldsError",
    "IspRoutingLinkRouterMismatchError",
]


class IspRoutingError(CloudGuestError):
    """Base exception for ISP Routing domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class IspRoutingRuleNotFoundError(IspRoutingError):
    def __init__(self, rule_id: uuid.UUID | str) -> None:
        super().__init__(
            f"ISP routing rule not found: {rule_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class CrossOrganizationIspRoutingRuleAccessError(IspRoutingError):
    """A caller acting within organization A attempted to read/mutate an
    ISP routing rule belonging to organization B -- mirrors
    ``app.domains.isp.exceptions.CrossOrganizationIspLinkAccessError``."""

    def __init__(self) -> None:
        super().__init__(
            "Cannot access an ISP routing rule belonging to another organization",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class IspRoutingRuleInvalidMatchFieldsError(IspRoutingError):
    """Raised when the match field(s) populated on a rule don't agree with
    its own ``rule_type`` -- exactly one of ``vlan_id``/
    ``source_mac_address``/``ip_address``/``source_cidr``/
    ``interface_name``/``policy_id`` must be set, and it must be the one
    ``rule_type`` names. See ``validators.validate_match_fields``."""

    def __init__(self, rule_type: str, reason: str) -> None:
        super().__init__(
            f"Invalid match fields for rule_type '{rule_type}': {reason}",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )


class IspRoutingLinkRouterMismatchError(IspRoutingError):
    """Raised when the ``isp_link_id`` supplied for a rule does not belong
    to the same ``router_id`` the rule itself is scoped to -- a routing
    rule can only steer traffic onto an uplink physically present on its
    own router."""

    def __init__(self, isp_link_id: uuid.UUID, router_id: uuid.UUID) -> None:
        super().__init__(
            f"ISP link '{isp_link_id}' does not belong to router '{router_id}'",
            status_code=status.HTTP_409_CONFLICT,
        )
