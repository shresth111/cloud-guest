"""Monitoring domain exceptions.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide exception handler / ``ApiResponse`` envelope exactly like every
other domain's exception hierarchy -- no route needs its own try/except
translation.

Deliberately small: this module's health checks are designed to *catch*
their own failures and report them as an honest ``HealthStatus.UNHEALTHY``/
``UNKNOWN`` result (see ``service.py``), not raise -- a failing dependency
(Postgres down, Redis down) is exactly the condition this module exists to
observe and record, not to crash on. The only real exception surface is
input validation (an invalid event-timeline date range).
"""

from __future__ import annotations

from fastapi import status

from app.common.exceptions import CloudGuestError

__all__ = [
    "MonitoringError",
    "InvalidEventDateRangeError",
]


class MonitoringError(CloudGuestError):
    """Base exception for Monitoring domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class InvalidEventDateRangeError(MonitoringError):
    """Raised by ``MonitoringService.get_event_timeline`` when both
    ``start``/``end`` are supplied and ``start`` is after ``end`` -- mirrors
    ``app.domains.guest.exceptions.InvalidAnalyticsDateRangeError``'s
    identical validation."""

    def __init__(self) -> None:
        super().__init__(
            "start_date must be before or equal to end_date",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
