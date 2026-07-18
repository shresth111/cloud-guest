"""Exceptions for the Reports domain."""

from fastapi import status
from app.common.exceptions import CloudGuestError

class ReportError(CloudGuestError):
    """Base exception for reports domain errors."""
    def __init__(self, message: str, *, status_code: int = status.HTTP_400_BAD_REQUEST) -> None:
        super().__init__(message, status_code=status_code)

class ReportNotFoundError(ReportError):
    def __init__(self, report_id: object) -> None:
        super().__init__(
            f"Report not found: {report_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )

class ReportScheduleNotFoundError(ReportError):
    def __init__(self, schedule_id: object) -> None:
        super().__init__(
            f"Report schedule not found: {schedule_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )
