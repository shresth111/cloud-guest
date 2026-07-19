"""Pydantic request/response schemas for the Report Engine + Export Engine
(BE-012 Part 5).

Follows this domain's own established convention (``schemas.py``,
``dashboard_schemas.py``, ...): ``ConfigDict(from_attributes=True)`` on every
response wrapping an ORM row, wrapped in the project's standard
``ApiResponse``/``build_response`` envelope by ``report_router.py`` for every
JSON-shaped response. The one exception is ``POST /reports`` itself when a
non-JSON ``export_format`` is requested -- that endpoint returns real,
raw file bytes with a ``Content-Type``/``Content-Disposition`` header pair
instead of the envelope (see ``report_router.py``'s own module docstring for
why a rendered CSV/Excel/PDF file cannot also be JSON-enveloped).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .constants import ExportFormat, ReportFrequency, ReportType

__all__ = [
    "ReportTemplateCreateRequest",
    "ReportTemplateUpdateRequest",
    "ReportTemplateResponse",
    "ReportTemplateListResponse",
    "GenerateReportRequest",
    "ReportPayloadResponse",
    "ScheduledReportCreateRequest",
    "ScheduledReportUpdateRequest",
    "ScheduledReportResponse",
    "ScheduledReportListResponse",
]


# ============================================================================
# ReportTemplate CRUD
# ============================================================================


class ReportTemplateCreateRequest(BaseModel):
    """``organization_id`` is deliberately **not** a body field: it is
    resolved from the ``X-Organization-Id`` request header (via RBAC's own
    ``CurrentOrganization`` dependency, which also validates the header
    names a real organization the caller actively belongs to) -- omitting
    the header creates a platform-wide system template (requires a
    GLOBAL-scoped ``reports.manage`` grant); sending it scopes the template
    to that organization (requires an ORGANIZATION-scoped grant covering
    it). See ``report_router.py``'s own module docstring for the full
    RBAC-scope-inference write-up."""

    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    report_type: ReportType
    config: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Optional composition defaults: 'location_id' (str UUID), "
            "'window_days' (int, for ROUTER/GUEST/NETWORK's trailing "
            "window), 'include_router_failure_risk' (bool, for HEALTH)."
        ),
    )
    is_active: bool = True


class ReportTemplateUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    config: dict[str, Any] | None = None
    is_active: bool | None = None


class ReportTemplateResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    organization_id: uuid.UUID | None
    report_type: str
    config: dict[str, Any]
    is_active: bool
    created_by_user_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ReportTemplateListResponse(BaseModel):
    items: list[ReportTemplateResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


# ============================================================================
# On-demand ("manual"/"dashboard") report generation
# ============================================================================


class GenerateReportRequest(BaseModel):
    """Either ``template_id`` (load a persisted :class:`ReportTemplate`'s
    ``report_type``/``config``) or ``report_type`` (an ad-hoc, unpersisted
    report) must be supplied -- see ``report_service.ReportGenerationService
    .generate``'s own docstring for exactly how the two are reconciled when
    both are given (explicit request fields always win over a template's
    own defaults). ``organization_id``/``location_id`` are, like every
    other analytics endpoint in this domain, resolved from the
    ``X-Organization-Id``/``X-Location-Id`` request headers (not body
    fields) -- see ``report_router.py``'s own module docstring."""

    template_id: uuid.UUID | None = None
    report_type: ReportType | None = None
    start_date: datetime | None = None
    end_date: datetime | None = None
    export_format: ExportFormat = ExportFormat.JSON


class ReportPayloadResponse(BaseModel):
    """The JSON shape of a generated report -- returned as-is (via the
    standard envelope) when ``export_format=json``; the exact same payload
    is what ``export.py`` renders into CSV/Excel/PDF for every other
    format, so this schema is also each of those exports' source of
    truth."""

    report_type: str
    title: str
    generated_at: str
    organization_id: uuid.UUID | None
    location_id: uuid.UUID | None
    period_start: str | None
    period_end: str | None
    sections: list[dict[str, Any]]


# ============================================================================
# ScheduledReport CRUD
# ============================================================================


class ScheduledReportCreateRequest(BaseModel):
    """``organization_id`` is likewise not a body field -- a schedule always
    belongs to a real organization (never platform-wide, see
    :class:`~.models.ScheduledReport`'s own docstring), resolved from the
    mandatory ``X-Organization-Id`` header via RBAC's ``RequireOrganization``
    dependency."""

    template_id: uuid.UUID
    frequency: ReportFrequency
    recipient_emails: list[str] = Field(min_length=1)
    export_format: ExportFormat = ExportFormat.PDF
    is_active: bool = True


class ScheduledReportUpdateRequest(BaseModel):
    frequency: ReportFrequency | None = None
    recipient_emails: list[str] | None = Field(default=None, min_length=1)
    export_format: ExportFormat | None = None
    is_active: bool | None = None


class ScheduledReportResponse(BaseModel):
    id: uuid.UUID
    template_id: uuid.UUID
    organization_id: uuid.UUID
    frequency: str
    recipient_emails: list[str]
    export_format: str
    next_run_at: datetime
    last_run_at: datetime | None
    last_run_status: str | None
    is_active: bool
    created_by_user_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScheduledReportListResponse(BaseModel):
    items: list[ScheduledReportResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool
