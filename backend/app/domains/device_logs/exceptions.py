"""Device Logs errors. ``data.code`` is the stable value the console
matches on; the message is for humans."""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError


class DeviceLogsError(CloudGuestError):
    code = "DEVICE_LOGS_ERROR"

    def __init__(self, message: str, *, status_code: int, **data: object) -> None:
        super().__init__(
            message, status_code=status_code, data={"code": self.code, **data}
        )


class DeviceLogsDisabledError(DeviceLogsError):
    code = "DEVICE_LOGS_DISABLED"

    def __init__(self) -> None:
        super().__init__(
            "Device logging is switched off on this platform "
            "(CLOUDGUEST_DEVICE_LOGS_ENABLED).",
            status_code=status.HTTP_409_CONFLICT,
        )


class DeviceLogsRouterNotFoundError(DeviceLogsError):
    code = "DEVICE_LOGS_ROUTER_NOT_FOUND"

    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Router {router_id} not found.",
            status_code=status.HTTP_404_NOT_FOUND,
            router_id=str(router_id),
        )


class DeviceLogsRouterBlockedError(DeviceLogsError):
    """The router cannot have remote logging right now; ``blocker`` names
    why (NOT_MIKROTIK / NO_TUNNEL / NO_API_CREDENTIALS)."""

    code = "DEVICE_LOGS_ROUTER_BLOCKED"

    def __init__(self, router_id: uuid.UUID, blocker: str, detail: str) -> None:
        super().__init__(
            detail,
            status_code=status.HTTP_409_CONFLICT,
            router_id=str(router_id),
            blocker=blocker,
        )


class DeviceLogsDeviceError(DeviceLogsError):
    code = "DEVICE_LOGS_DEVICE_ERROR"

    def __init__(self, router_id: uuid.UUID, detail: str) -> None:
        super().__init__(
            f"The router could not be configured: {detail}",
            status_code=status.HTTP_502_BAD_GATEWAY,
            router_id=str(router_id),
        )


class FirewallLoggingSwitchedOffError(DeviceLogsError):
    """The platform switch for firewall logging is off; nothing can be
    turned on (turning off always works)."""

    code = "FIREWALL_LOGGING_DISABLED"

    def __init__(self) -> None:
        super().__init__(
            "Firewall logging is switched off on this platform "
            "(CLOUDGUEST_DEVICE_LOGS_FIREWALL_LOGGING_ENABLED).",
            status_code=status.HTTP_409_CONFLICT,
        )


class FirewallLoggingNeedsRemoteLoggingError(DeviceLogsError):
    """Firewall lines only reach NetLogs through Wyfy's remote logging, so
    it must be applied (and not removed) first."""

    code = "FIREWALL_LOGGING_NEEDS_REMOTE_LOGGING"

    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            "Apply remote logging to this router first: firewall lines are "
            "sent through it.",
            status_code=status.HTTP_409_CONFLICT,
            router_id=str(router_id),
        )


class FirewallLoggingBusyError(DeviceLogsError):
    """Another writer holds the router's forward-chain lock."""

    code = "FIREWALL_PUSH_IN_PROGRESS"

    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            "Another firewall change is being written to this router; try "
            "again in a few seconds.",
            status_code=status.HTTP_409_CONFLICT,
            router_id=str(router_id),
        )


class DeviceLogsBadCursorError(DeviceLogsError):
    code = "DEVICE_LOGS_BAD_CURSOR"

    def __init__(self) -> None:
        super().__init__(
            "Invalid cursor.", status_code=status.HTTP_422_UNPROCESSABLE_ENTITY
        )


# -- customer NetLogs ---------------------------------------------------------


class NetLogsLocationNotFoundError(DeviceLogsError):
    """Unknown location *or* another organization's -- one answer for both,
    so the endpoint cannot be used to probe other tenants' ids."""

    code = "NETLOGS_LOCATION_NOT_FOUND"

    def __init__(self, location_id: uuid.UUID) -> None:
        super().__init__(
            f"Location {location_id} not found.",
            status_code=status.HTTP_404_NOT_FOUND,
            location_id=str(location_id),
        )


class NetLogsRouterNotFoundError(DeviceLogsError):
    code = "NETLOGS_ROUTER_NOT_FOUND"

    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Router {router_id} not found.",
            status_code=status.HTTP_404_NOT_FOUND,
            router_id=str(router_id),
        )


class NetLogsLocationForbiddenError(DeviceLogsError):
    """In the caller's organization, but not a location they hold
    ``network_logs.read`` on."""

    code = "NETLOGS_LOCATION_FORBIDDEN"

    def __init__(self) -> None:
        super().__init__(
            "You do not have access to logs for this location.",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class NetLogsBadFilterError(DeviceLogsError):
    code = "NETLOGS_BAD_FILTER"

    def __init__(self, field: str, value: str, allowed: list[str]) -> None:
        super().__init__(
            f"Unknown {field} {value!r}.",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            field=field,
            value=value,
            allowed=allowed,
        )
