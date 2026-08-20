"""Domain exceptions for router discovery / snapshot / compatibility."""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError

__all__ = [
    "PlannerError",
    "RouterSnapshotNotFoundError",
    "NoRouterSnapshotError",
    "DiscoveryMissingCredentialsError",
    "DiscoveryDeviceConnectionError",
]


class PlannerError(CloudGuestError):
    """Base exception for the discovery / planner package."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class RouterSnapshotNotFoundError(PlannerError):
    def __init__(self, snapshot_id: uuid.UUID) -> None:
        super().__init__(
            f"Router snapshot '{snapshot_id}' was not found",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class NoRouterSnapshotError(PlannerError):
    """Raised when compatibility is requested but the router has no snapshots."""

    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"No discovery snapshot exists for router '{router_id}'",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class DiscoveryMissingCredentialsError(PlannerError):
    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Router '{router_id}' is missing device connection credentials "
            "(management IP, API username, or API secret)",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class DiscoveryDeviceConnectionError(PlannerError):
    def __init__(self, host: str, detail: str) -> None:
        self.host = host
        self.detail = detail
        super().__init__(
            f"Could not connect to device at '{host}' for discovery: {detail}",
            status_code=status.HTTP_502_BAD_GATEWAY,
        )
