"""Analytics domain exceptions.

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
    "AnalyticsError",
    "InvalidAnalyticsDateRangeError",
    "AnalyticsOrganizationNotFoundError",
    "AnalyticsSnapshotNotFoundError",
]


class AnalyticsError(CloudGuestError):
    """Base exception for Analytics domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class InvalidAnalyticsDateRangeError(AnalyticsError):
    """Raised when both ``start``/``end`` are supplied and ``start`` is
    after ``end`` -- mirrors
    ``app.domains.guest.exceptions.InvalidAnalyticsDateRangeError``'s /
    ``app.domains.monitoring.exceptions.InvalidEventDateRangeError``'s
    identical validation."""

    def __init__(self) -> None:
        super().__init__(
            "start_date must be before or equal to end_date",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class AnalyticsOrganizationNotFoundError(AnalyticsError):
    """Raised by ``AnalyticsService.trigger_aggregation`` when the
    requested ``organization_id`` does not correspond to a real,
    non-deleted ``Organization`` row -- a manual trigger for an organization
    that does not exist should fail loudly, not silently compute an empty
    snapshot."""

    def __init__(self, organization_id: uuid.UUID) -> None:
        super().__init__(
            f"Organization not found: {organization_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class AnalyticsSnapshotNotFoundError(AnalyticsError):
    def __init__(self, snapshot_id: uuid.UUID) -> None:
        super().__init__(
            f"Analytics snapshot not found: {snapshot_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )
