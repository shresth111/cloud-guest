"""ISP Management domain exceptions.

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
    "IspError",
    "IspLinkNotFoundError",
    "CrossOrganizationIspLinkAccessError",
    "IspPrimaryLinkAlreadyExistsError",
    "IspNoBackupLinkAvailableError",
    "IspLinkDisabledError",
    "IspMissingCredentialsError",
    "IspDeviceConnectionError",
    "IspDeviceOperationError",
    "UnsupportedIspVendorError",
]


class IspError(CloudGuestError):
    """Base exception for ISP Management domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class IspLinkNotFoundError(IspError):
    def __init__(self, link_id: uuid.UUID | str) -> None:
        super().__init__(
            f"ISP link not found: {link_id}", status_code=status.HTTP_404_NOT_FOUND
        )


class CrossOrganizationIspLinkAccessError(IspError):
    """A caller acting within organization A attempted to read/mutate an
    ISP link belonging to organization B -- mirrors
    ``app.domains.router.exceptions.CrossOrganizationRouterAccessError``."""

    def __init__(self) -> None:
        super().__init__(
            "Cannot access an ISP link belonging to another organization",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class IspPrimaryLinkAlreadyExistsError(IspError):
    """A router may hold exactly one ``IspLinkRole.PRIMARY`` link at a
    time -- raised by ``create_link``/``update_link`` when a second
    primary is requested for a router that already has one. An admin must
    first re-role the existing primary to ``BACKUP`` (or delete it)
    before promoting a different link."""

    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Router '{router_id}' already has a primary ISP link -- "
            "re-role or remove it before assigning a new one",
            status_code=status.HTTP_409_CONFLICT,
        )


class IspNoBackupLinkAvailableError(IspError):
    """``trigger_failover`` found no enabled, healthy (or at least not
    currently-unhealthy) ``BACKUP`` link to fail over to -- the primary's
    own outage is real, but there is nothing safe to switch traffic onto."""

    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Router '{router_id}' has no available backup ISP link to " "fail over to",
            status_code=status.HTTP_409_CONFLICT,
        )


class IspLinkDisabledError(IspError):
    """A caller attempted to health-check, activate, or fail over to a
    link with ``is_enabled=False`` -- an admin has deliberately taken it
    out of service."""

    def __init__(self, link_id: uuid.UUID) -> None:
        super().__init__(
            f"ISP link '{link_id}' is disabled and cannot be used",
            status_code=status.HTTP_409_CONFLICT,
        )


class IspMissingCredentialsError(IspError):
    """Raised when a router has no management IP/username/decrypted
    secret stored -- the same real gap
    ``app.domains.queue_management.exceptions.QueueMissingCredentialsError``
    documents, applied to ISP link health-check operations."""

    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Router '{router_id}' is missing device connection credentials "
            "(management IP, API username, or API secret)",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class IspDeviceConnectionError(IspError):
    """Could not open a real RouterOS API connection to the router at
    all -- mirrors
    ``app.domains.queue_management.exceptions.QueueDeviceConnectionError``."""

    def __init__(self, host: str, reason: str) -> None:
        super().__init__(
            f"Could not connect to router at '{host}': {reason}",
            status_code=status.HTTP_502_BAD_GATEWAY,
        )


class IspDeviceOperationError(IspError):
    """A connection was opened, but the RouterOS command itself failed
    (e.g. ``/tool/ping`` returned a ``!trap``) -- mirrors
    ``app.domains.queue_management.exceptions.QueueDeviceOperationError``."""

    def __init__(self, operation: str, reason: str) -> None:
        super().__init__(
            f"ISP device operation '{operation}' failed: {reason}",
            status_code=status.HTTP_502_BAD_GATEWAY,
        )


class UnsupportedIspVendorError(IspError):
    """No health-check adapter is registered for this router's own
    ``vendor`` -- mirrors
    ``app.domains.queue_management.exceptions.UnsupportedQueueVendorError``."""

    def __init__(self, vendor: str) -> None:
        super().__init__(
            f"No ISP health-check adapter registered for vendor '{vendor}'",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
