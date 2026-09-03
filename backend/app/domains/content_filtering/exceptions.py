"""Content Filtering domain exceptions.

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
    "ContentFilteringError",
    "ContentFilterRuleNotFoundError",
    "CrossOrganizationContentFilterRuleAccessError",
    "InvalidContentFilterValueError",
    "ContentFilterRuleAlreadyExistsError",
    "ContentFilterRuleNotEnabledError",
    "ContentFilterMissingCredentialsError",
    "UnsupportedContentFilterVendorError",
    "ContentFilterDeviceConnectionError",
    "ContentFilterDeviceOperationError",
]


class ContentFilteringError(CloudGuestError):
    """Base exception for Content Filtering domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class ContentFilterRuleNotFoundError(ContentFilteringError):
    def __init__(self, rule_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Content filter rule not found: {rule_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class CrossOrganizationContentFilterRuleAccessError(ContentFilteringError):
    """Mirrors ``app.domains.firewall.exceptions
    .CrossOrganizationFirewallRuleAccessError``'s identical shape."""

    def __init__(self) -> None:
        super().__init__(
            "Cannot access a content filter rule belonging to another organization",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class InvalidContentFilterValueError(ContentFilteringError):
    """Raised when a rule's ``value`` is not a real, parseable instance of
    its own ``value_type`` -- not a real hostname for ``DOMAIN``, not a
    real IP/CIDR for ``IP_CIDR``."""

    def __init__(self, value_type: str, value: str) -> None:
        super().__init__(
            f"Invalid {value_type} value for a content filter rule: '{value}'",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )


class ContentFilterRuleAlreadyExistsError(ContentFilteringError):
    """A router may not hold two non-deleted rules for the same
    ``(value_type, value)`` pair -- mirrors ``app.domains
    .mac_authorization.exceptions.MacAuthorizationAlreadyExistsError``'s
    identical "avoid a redundant, device-duplicating row" reasoning."""

    def __init__(self, router_id: uuid.UUID, value_type: str, value: str) -> None:
        super().__init__(
            f"Router '{router_id}' already has a {value_type} content "
            f"filter rule for '{value}'",
            status_code=status.HTTP_409_CONFLICT,
        )


# ---------------------------------------------------------------------------
# Device push
#
# Everything below is raised by ``ContentFilterService.push_rule_to_device``
# and its delete path. They all subclass ``CloudGuestError``, so the app-wide
# handler turns them into a real non-2xx response.
#
# That matters more than it looks: the frontend's response interceptor
# (``cloudguest-foundation/src/services/api.ts``) unwraps ``response.data.data``
# and never reads ``envelope.success``. A handler that "reported failure
# honestly" by returning ``200 {"success": false}`` would be indistinguishable
# from success to every caller in the app -- which is the exact shape of the
# bug this domain is being wired up to stop, since "Website Blocking" already
# reported success for a site it had never actually blocked.
# ---------------------------------------------------------------------------


class ContentFilterRuleNotEnabledError(ContentFilteringError):
    """Asked to push a rule whose ``is_enabled`` is ``False``.

    There is nothing correct to push: an ``is_enabled=False`` rule is the
    customer saying this site should *not* be blocked, and realizing it
    would block the site the toggle exists to unblock. Turning a rule off
    is a delete on the device, which is the delete path's job, not a
    push's.
    """

    def __init__(self, rule_id: uuid.UUID) -> None:
        super().__init__(
            f"Content filter rule '{rule_id}' is disabled and cannot be "
            "pushed to a device",
            status_code=status.HTTP_409_CONFLICT,
        )


class ContentFilterMissingCredentialsError(ContentFilteringError):
    """The rule's router has no management IP / API username / decrypted
    secret stored. Mirrors ``VlanMissingCredentialsError``."""

    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Router '{router_id}' is missing device connection credentials "
            "(management IP, API username, or API secret)",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class UnsupportedContentFilterVendorError(ContentFilteringError):
    """No content-filtering device adapter is registered for the router's
    vendor."""

    def __init__(self, vendor: str) -> None:
        super().__init__(
            "No content filtering device adapter is registered for vendor "
            f"'{vendor}'",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class ContentFilterDeviceConnectionError(ContentFilteringError):
    """A real connection attempt (RouterOS API, port 8728) failed."""

    def __init__(self, host: str, detail: str) -> None:
        super().__init__(
            f"Could not connect to device at '{host}': {detail}",
            status_code=status.HTTP_502_BAD_GATEWAY,
        )


class ContentFilterDeviceOperationError(ContentFilteringError):
    """A device content-filtering operation failed after a connection was
    established."""

    def __init__(self, operation: str, detail: str) -> None:
        super().__init__(
            f"Device operation '{operation}' failed: {detail}",
            status_code=status.HTTP_502_BAD_GATEWAY,
        )
