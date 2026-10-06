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


class DeviceLogsBadCursorError(DeviceLogsError):
    code = "DEVICE_LOGS_BAD_CURSOR"

    def __init__(self) -> None:
        super().__init__(
            "Invalid cursor.", status_code=status.HTTP_422_UNPROCESSABLE_ENTITY
        )
