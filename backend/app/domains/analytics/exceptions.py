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
    "DashboardScopeForbiddenError",
    "ReportTemplateNotFoundError",
    "ScheduledReportNotFoundError",
    "MissingReportParametersError",
    "UnsupportedExportFormatError",
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


class DashboardScopeForbiddenError(AnalyticsError):
    """Raised by :class:`~.dashboard_scope.DashboardScope`'s ``require_*``
    methods when a caller's *real, RBAC-role-derived* dashboard scope does
    not cover the organization/location/global view they asked for -- the
    second, independent "which tenant's data" check every dashboard endpoint
    runs after RBAC's own ``RequirePermission`` "what action" check has
    already passed. See ``dashboard_scope.py``'s module docstring for why
    this check exists as a second, real layer rather than trusting the
    permission dependency alone."""

    def __init__(self, message: str) -> None:
        super().__init__(message, status_code=status.HTTP_403_FORBIDDEN)


class ReportTemplateNotFoundError(AnalyticsError):
    """Raised when a requested ``ReportTemplate`` id does not correspond to
    a real, non-deleted row visible to the caller (either because it truly
    does not exist, or because it belongs to an organization outside the
    caller's ``DashboardScope`` -- the same "not found" response for both,
    mirroring every other domain's own tenant-isolation convention of never
    distinguishing "doesn't exist" from "you can't see it")."""

    def __init__(self, template_id: uuid.UUID) -> None:
        super().__init__(
            f"Report template not found: {template_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class ScheduledReportNotFoundError(AnalyticsError):
    def __init__(self, scheduled_report_id: uuid.UUID) -> None:
        super().__init__(
            f"Scheduled report not found: {scheduled_report_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class MissingReportParametersError(AnalyticsError):
    """Raised by ``report_service.ReportGenerationService.generate`` when
    the caller's ``report_type`` requires an identifier (``organization_id``
    for ``ORGANIZATION``/``ROUTER``/``GUEST``/``NETWORK``, ``location_id``
    for ``LOCATION``) that neither the request nor a referenced
    ``ReportTemplate``'s own ``organization_id``/``config`` supplied."""

    def __init__(self, message: str) -> None:
        super().__init__(message, status_code=status.HTTP_400_BAD_REQUEST)


class UnsupportedExportFormatError(AnalyticsError):
    """Raised by ``export.render_report`` for any format outside
    :class:`~.constants.ExportFormat` -- defensive; FastAPI's own enum-typed
    request/query validation already rejects an unknown format before this
    would ever fire in the HTTP path, this guards the Celery task path too
    (a ``ScheduledReport.export_format`` value, read back from the
    database, is trusted less than a fresh Pydantic-validated request)."""

    def __init__(self, export_format: str) -> None:
        super().__init__(
            f"Unsupported export format: {export_format}",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
