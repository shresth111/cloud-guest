"""Firewall Rule Management domain exceptions.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide exception handler / ``ApiResponse`` envelope exactly like every
other domain's exception hierarchy -- no route needs its own try/except
translation.
"""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError
from app.common.router_firewall_lock import FIREWALL_PUSH_IN_PROGRESS
from app.domains.router.device_domain_gate import unsupported_vendor_message

__all__ = [
    "FirewallError",
    "FirewallRuleNotFoundError",
    "CrossOrganizationFirewallRuleAccessError",
    "InvalidFirewallPortError",
    "InvalidFirewallAddressError",
    "FirewallMissingCredentialsError",
    "UnsupportedFirewallVendorError",
    "FirewallChainNotPushableError",
    "FirewallDeviceConnectionError",
    "FirewallDeviceOperationError",
    "FirewallPushRefusedError",
    "FirewallPushFailedError",
    "FirewallPushInProgressError",
]


class FirewallError(CloudGuestError):
    """Base exception for Firewall Rule Management domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class FirewallRuleNotFoundError(FirewallError):
    def __init__(self, rule_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Firewall rule not found: {rule_id}", status_code=status.HTTP_404_NOT_FOUND
        )


class CrossLocationFirewallRuleAccessError(FirewallError):
    """A caller confined to particular sites reached a rule at another site.

    Distinct from ``CrossOrganizationFirewallRuleAccessError``: both sites
    belong to the *same* organization, so the organization comparison sees
    nothing wrong. A firewall rule is reached by its own id, so
    ``RequirePermission`` had nothing to pin the check to -- see
    ``app.domains.rbac.location_scope`` for why the confinement is derived
    from the caller's grants rather than from ``X-Location-Id``.
    """

    def __init__(self) -> None:
        super().__init__(
            "Cannot access a firewall rule at a location outside your own scope",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class CrossOrganizationFirewallRuleAccessError(FirewallError):
    """Mirrors ``app.domains.dhcp.exceptions
    .CrossOrganizationDhcpPoolAccessError``'s identical shape."""

    def __init__(self) -> None:
        super().__init__(
            "Cannot access a firewall rule belonging to another organization",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class InvalidFirewallPortError(FirewallError):
    def __init__(self, field_name: str, port: int) -> None:
        super().__init__(
            f"Invalid {field_name}: {port} is outside the usable 1-65535 range",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )


class InvalidFirewallAddressError(FirewallError):
    """Raised when a source/destination address is supplied but is not a
    real, parseable IP address or CIDR block."""

    def __init__(self, field_name: str, value: str) -> None:
        super().__init__(
            f"Invalid {field_name}: '{value}'",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )


# ---------------------------------------------------------------------------
# Device push
# ---------------------------------------------------------------------------


class FirewallMissingCredentialsError(FirewallError):
    """Raise rather than guess -- mirrors content_filtering/vlan/dhcp."""

    def __init__(self, router_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Router '{router_id}' is missing device connection credentials "
            "(management or public IP, API username, or API secret)",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class UnsupportedFirewallVendorError(FirewallError):
    def __init__(self, vendor: str) -> None:
        super().__init__(
            unsupported_vendor_message(feature="Firewall Rules", vendor=vendor),
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class FirewallChainNotPushableError(FirewallError):
    """An enabled rule is in a chain the writer does not manage.

    Only ``forward`` has a sentinel band. ``input``/``output`` rules are
    traffic to and from the router itself -- the management tunnel, the
    RouterOS API, RADIUS -- and a misplaced one there is how a router was
    cut off from the platform on 2026-08-16. Refused before any connection,
    naming the rules, so the operator can disable them or move them."""

    def __init__(self, rule_names: list[str]) -> None:
        super().__init__(
            "Only between-network (forward) rules can be applied to the router "
            "today. Disable or change these rules first: "
            + ", ".join(sorted(rule_names)),
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            data={
                "code": "ACCESS_RULES_CHAIN_UNSUPPORTED",
                "rules": sorted(rule_names),
            },
        )


class FirewallDeviceConnectionError(FirewallError):
    def __init__(self, host: str, detail: str) -> None:
        super().__init__(
            f"Could not connect to router at {host}: {detail}",
            status_code=status.HTTP_502_BAD_GATEWAY,
        )


class FirewallDeviceOperationError(FirewallError):
    def __init__(self, operation: str, detail: str) -> None:
        super().__init__(
            f"Router rejected {operation}: {detail}",
            status_code=status.HTTP_502_BAD_GATEWAY,
        )


class FirewallPushRefusedError(FirewallError):
    """The writer refused before touching the device -- nothing changed.

    ``code`` is the gateway's ``ACCESS_RULES_*`` code, returned in ``data``
    so a caller can branch on it without parsing the message.
    ``ACCESS_RULES_BAND_MISSING`` means the router has never had its
    sentinel band placed, which is a Master-console action, not a retry."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(
            f"Firewall rules were not applied: {detail}",
            status_code=status.HTTP_409_CONFLICT,
            data={"code": code},
        )


class FirewallPushFailedError(FirewallError):
    """A push failed after it began writing. ``restored`` says whether the
    router's previous platform rules were put back; ``False`` means the
    router may hold a partial set and needs a look."""

    def __init__(self, detail: str, *, restored: bool) -> None:
        self.restored = restored
        super().__init__(
            f"Firewall rules could not be applied: {detail}",
            status_code=status.HTTP_502_BAD_GATEWAY,
            data={"code": "ACCESS_RULES_PUSH_FAILED", "restored": restored},
        )


class FirewallPushInProgressError(FirewallError):
    """Another firewall push, band placement or content-filter push to this
    router holds its forward-chain lock (``app.common.router_firewall_lock``).
    Nothing was sent to the device; retrying shortly is correct."""

    def __init__(self, router_id: uuid.UUID | str) -> None:
        super().__init__(
            "Another change to this router's firewall is in progress; "
            "try again in a moment",
            status_code=status.HTTP_409_CONFLICT,
            data={"code": FIREWALL_PUSH_IN_PROGRESS, "router_id": str(router_id)},
        )
