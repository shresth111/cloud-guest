"""IPDR errors. ``data.code`` is the stable value the console matches on."""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError


class IpdrError(CloudGuestError):
    code = "IPDR_ERROR"

    def __init__(self, message: str, *, status_code: int, **data: object) -> None:
        super().__init__(
            message, status_code=status_code, data={"code": self.code, **data}
        )


class IpdrLocationNotFoundError(IpdrError):
    """Unknown location *or* another organization's: one answer for both."""

    code = "IPDR_LOCATION_NOT_FOUND"

    def __init__(self, location_id: uuid.UUID) -> None:
        super().__init__(
            f"Location {location_id} not found.",
            status_code=status.HTTP_404_NOT_FOUND,
            location_id=str(location_id),
        )


class IpdrRouterNotFoundError(IpdrError):
    code = "IPDR_ROUTER_NOT_FOUND"

    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Router {router_id} not found.",
            status_code=status.HTTP_404_NOT_FOUND,
            router_id=str(router_id),
        )


class IpdrRangeTooLongError(IpdrError):
    code = "IPDR_RANGE_TOO_LONG"

    def __init__(self, max_days: int) -> None:
        super().__init__(
            f"The range may cover at most {max_days} days.",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            max_days=max_days,
        )


class IpdrBadFilterError(IpdrError):
    code = "IPDR_BAD_FILTER"

    def __init__(self, field: str, message: str) -> None:
        super().__init__(
            message, status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, field=field
        )


class IpdrBadCursorError(IpdrError):
    code = "IPDR_BAD_CURSOR"

    def __init__(self) -> None:
        super().__init__(
            "Invalid cursor.", status_code=status.HTTP_422_UNPROCESSABLE_ENTITY
        )
