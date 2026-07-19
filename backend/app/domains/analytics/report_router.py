"""FastAPI routes for the Report Engine + Export Engine (BE-012 Part 5).

Included into ``router.py``'s own ``router`` (``router.include_router
(report_router)``) rather than registered separately in
``app/api/v1/router.py`` -- every analytics-domain route already reaches
the API through that one existing ``include_router(analytics_router)`` call,
so this file adds no new top-level wiring outside this domain's own package.

## RBAC scope design -- why most routes below omit an explicit ``scope=``

Every other endpoint in ``router.py`` (Parts 1-4) hard-codes one explicit
``scope=ScopeType.X`` on ``RequirePermission`` because each of those routes
answers exactly one kind of question at exactly one scope (the Super Admin
Dashboard is always GLOBAL, Router Analytics is always ORGANIZATION, ...).
This part's endpoints do not have that luxury:

* ``POST /reports`` generates **any** :class:`~.constants.ReportType` --
  some (``DASHBOARD``/``REVENUE``/plain ``HEALTH``) are inherently
  GLOBAL, others (``ORGANIZATION``/``ROUTER``/``GUEST``/``NETWORK``/
  ``HEALTH`` with an organization) are ORGANIZATION, and ``LOCATION`` is
  LOCATION -- one fixed ``scope=`` cannot express all three.
* ``GET``/list/get-by-id/update/delete on templates and schedules likewise
  serve both platform-wide and organization-scoped rows through the same
  route.

Rather than reinventing scope resolution, this module relies on RBAC's own,
already-existing ``RequirePermission``'s **scope inference**
(``app.domains.rbac.dependencies._infer_scope_type``): when no explicit
``scope=`` is given, the required scope is derived from whichever of
``X-Router-Id``/``X-Location-Id``/``X-Organization-Id`` headers the request
itself carries (falling back to GLOBAL when none are present) -- the same
mechanism ``GET /analytics/snapshots`` (Part 1) already relies on for its
own "may be platform-wide or organization-scoped" query. Every route below
that omits ``scope=`` therefore requires whatever scope the caller's own
headers imply: send no scope header for a GLOBAL report/template/schedule,
``X-Organization-Id`` for an organization-scoped one, ``X-Location-Id`` for
a location-scoped one. ``organization_id``/``location_id`` themselves are
resolved from those same headers via RBAC's own ``CurrentOrganization``/
``CurrentLocation``/``RequireOrganization`` dependencies -- never trusted
from a request body field, mirroring every other tenant-scoped endpoint in
this codebase.

``POST /reports/schedule`` is the one exception with an explicit,
fixed ``scope=ScopeType.ORGANIZATION``: a :class:`~.models.ScheduledReport`
is never platform-wide (see that model's own docstring), so its required
scope is always ORGANIZATION, and its ``organization_id`` is always
resolved via the mandatory ``RequireOrganization`` header dependency.

## Permission-action choice: ``reports.export`` for ``POST /reports``

``PermissionModule.REPORTS`` is seeded with exactly ``read``/``export``/
``view``/``manage`` (no ``create``). ``POST /reports`` always produces a
concrete rendered artifact (even the ``JSON`` format is "exporting" the
composed payload, not merely displaying an already-stored one) -- this is
squarely what the seeded ``export`` action names, and distinct from
``read`` (browsing template/schedule metadata) or ``manage`` (authoring
templates/schedules). ``reports.read`` was the other candidate the module
brief itself named; ``export`` is chosen because generating a report
always produces an output artifact, the exact action ``export`` already
means for ``ANALYTICS``/``AUDIT_LOGS``/``BILLING`` elsewhere in this same
permission catalog.

## Routing design: one ``POST /reports``, no separate ``GET .../export``

The module brief offered a choice between a dedicated ``GET
/analytics/reports/export`` and folding format selection into
``POST /reports`` via a request field. This module folds it in
(``GenerateReportRequest.export_format``): report generation already
composes several existing services' own queries per request (never free,
never cacheable the way a plain ``GET`` implies), so treating "generate a
report already rendered in format X" as one ``POST`` action -- not a
``GET`` with side-channel format selection, and not two round-trips
(generate, then separately export) -- is both RESTfully honest (this is an
action with real work behind it, not an idempotent resource fetch) and
keeps exactly one code path/one set of validation rules for every
supported format.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request, Response, status

from app.common.responses import ApiResponse, build_response
from app.domains.auth.models import AuthUser
from app.domains.rbac.dependencies import (
    CurrentLocation,
    CurrentOrganization,
    CurrentUser,
    RequireOrganization,
    RequirePermission,
)
from app.domains.rbac.enums import ScopeType

from .constants import ExportFormat, ReportType
from .dependencies import (
    get_report_generation_service,
    get_report_template_service,
    get_scheduled_report_service,
)
from .exceptions import MissingReportParametersError
from .export import render_report
from .models import ReportTemplate, ScheduledReport
from .report_schemas import (
    GenerateReportRequest,
    ReportTemplateCreateRequest,
    ReportTemplateListResponse,
    ReportTemplateResponse,
    ReportTemplateUpdateRequest,
    ScheduledReportCreateRequest,
    ScheduledReportListResponse,
    ScheduledReportResponse,
    ScheduledReportUpdateRequest,
)
from .report_service import (
    ReportGenerationService,
    ReportTemplateService,
    ScheduledReportService,
)

router = APIRouter(tags=["Reports"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _template_response(template: ReportTemplate) -> ReportTemplateResponse:
    return ReportTemplateResponse.model_validate(template)


def _schedule_response(schedule: ScheduledReport) -> ScheduledReportResponse:
    return ScheduledReportResponse.model_validate(schedule)


# ============================================================================
# ReportTemplate CRUD
# ============================================================================


@router.post(
    "/reports/templates",
    response_model=ApiResponse[ReportTemplateResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("reports.manage"))],
)
async def create_report_template(
    request: Request,
    payload: ReportTemplateCreateRequest,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ReportTemplateService = Depends(get_report_template_service),
):
    template = await service.create_template(
        uuid.UUID(user.id), organization_id, payload
    )
    return build_response(
        success=True,
        message="Report template created",
        data=_template_response(template).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/reports/templates",
    response_model=ApiResponse[ReportTemplateListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("reports.read"))],
)
async def list_report_templates(
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    service: ReportTemplateService = Depends(get_report_template_service),
):
    items, meta = await service.list_templates(
        uuid.UUID(user.id), page=page, page_size=page_size
    )
    payload = ReportTemplateListResponse(
        items=[_template_response(item) for item in items],
        page=meta.page,
        page_size=meta.page_size,
        total_items=meta.total_items,
        total_pages=meta.total_pages,
        has_next=meta.has_next,
        has_previous=meta.has_previous,
    )
    return build_response(
        success=True,
        message="Report templates retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/reports/templates/{template_id}",
    response_model=ApiResponse[ReportTemplateResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("reports.read"))],
)
async def get_report_template(
    request: Request,
    template_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ReportTemplateService = Depends(get_report_template_service),
):
    template = await service.get_visible_template(uuid.UUID(user.id), template_id)
    return build_response(
        success=True,
        message="Report template retrieved",
        data=_template_response(template).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.put(
    "/reports/templates/{template_id}",
    response_model=ApiResponse[ReportTemplateResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("reports.manage"))],
)
async def update_report_template(
    request: Request,
    template_id: uuid.UUID,
    payload: ReportTemplateUpdateRequest,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ReportTemplateService = Depends(get_report_template_service),
):
    template = await service.update_template(uuid.UUID(user.id), template_id, payload)
    return build_response(
        success=True,
        message="Report template updated",
        data=_template_response(template).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.delete(
    "/reports/templates/{template_id}",
    response_model=ApiResponse[dict],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("reports.manage"))],
)
async def delete_report_template(
    request: Request,
    template_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ReportTemplateService = Depends(get_report_template_service),
):
    await service.delete_template(uuid.UUID(user.id), template_id)
    return build_response(
        success=True,
        message="Report template deleted",
        data={},
        request_id=_request_id(request),
    )


# ============================================================================
# On-demand ("manual"/"dashboard") report generation
# ============================================================================


@router.post(
    "/reports",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("reports.export"))],
)
async def generate_report(
    request: Request,
    payload: GenerateReportRequest,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    location_id: uuid.UUID | None = Depends(CurrentLocation),
    template_service: ReportTemplateService = Depends(get_report_template_service),
    generation_service: ReportGenerationService = Depends(
        get_report_generation_service
    ),
):
    user_id = uuid.UUID(user.id)
    report_type = payload.report_type
    include_router_failure_risk = True

    if payload.template_id is not None:
        template = await template_service.get_visible_template(
            user_id, payload.template_id
        )
        report_type = ReportType(template.report_type)
        config = template.config or {}
        if location_id is None and config.get("location_id"):
            location_id = uuid.UUID(str(config["location_id"]))
        include_router_failure_risk = bool(
            config.get("include_router_failure_risk", True)
        )

    if report_type is None:
        raise MissingReportParametersError(
            "Either template_id or report_type must be supplied"
        )

    report_payload = await generation_service.generate(
        user_id,
        report_type=report_type,
        organization_id=organization_id,
        location_id=location_id,
        start=payload.start_date,
        end=payload.end_date,
        include_router_failure_risk=include_router_failure_risk,
        export_format=payload.export_format,
        template_id=payload.template_id,
    )

    if payload.export_format == ExportFormat.JSON:
        return build_response(
            success=True,
            message="Report generated",
            data=report_payload.to_dict(),
            request_id=_request_id(request),
        )

    rendered = render_report(report_payload, payload.export_format)
    return Response(
        content=rendered.content,
        media_type=rendered.content_type,
        headers={"Content-Disposition": f'attachment; filename="{rendered.filename}"'},
    )


# ============================================================================
# ScheduledReport CRUD
# ============================================================================


@router.post(
    "/reports/schedule",
    response_model=ApiResponse[ScheduledReportResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(RequirePermission("reports.manage", scope=ScopeType.ORGANIZATION))
    ],
)
async def create_scheduled_report(
    request: Request,
    payload: ScheduledReportCreateRequest,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    service: ScheduledReportService = Depends(get_scheduled_report_service),
):
    schedule = await service.create_schedule(
        uuid.UUID(user.id), organization_id, payload
    )
    return build_response(
        success=True,
        message="Scheduled report created",
        data=_schedule_response(schedule).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/reports/schedule",
    response_model=ApiResponse[ScheduledReportListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("reports.read"))],
)
async def list_scheduled_reports(
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    service: ScheduledReportService = Depends(get_scheduled_report_service),
):
    items, meta = await service.list_schedules(
        uuid.UUID(user.id), page=page, page_size=page_size
    )
    payload = ScheduledReportListResponse(
        items=[_schedule_response(item) for item in items],
        page=meta.page,
        page_size=meta.page_size,
        total_items=meta.total_items,
        total_pages=meta.total_pages,
        has_next=meta.has_next,
        has_previous=meta.has_previous,
    )
    return build_response(
        success=True,
        message="Scheduled reports retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/reports/schedule/{schedule_id}",
    response_model=ApiResponse[ScheduledReportResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("reports.read"))],
)
async def get_scheduled_report(
    request: Request,
    schedule_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ScheduledReportService = Depends(get_scheduled_report_service),
):
    schedule = await service.get_visible_schedule(uuid.UUID(user.id), schedule_id)
    return build_response(
        success=True,
        message="Scheduled report retrieved",
        data=_schedule_response(schedule).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.put(
    "/reports/schedule/{schedule_id}",
    response_model=ApiResponse[ScheduledReportResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("reports.manage"))],
)
async def update_scheduled_report(
    request: Request,
    schedule_id: uuid.UUID,
    payload: ScheduledReportUpdateRequest,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ScheduledReportService = Depends(get_scheduled_report_service),
):
    schedule = await service.update_schedule(uuid.UUID(user.id), schedule_id, payload)
    return build_response(
        success=True,
        message="Scheduled report updated",
        data=_schedule_response(schedule).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.delete(
    "/reports/schedule/{schedule_id}",
    response_model=ApiResponse[dict],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("reports.manage"))],
)
async def delete_scheduled_report(
    request: Request,
    schedule_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ScheduledReportService = Depends(get_scheduled_report_service),
):
    await service.delete_schedule(uuid.UUID(user.id), schedule_id)
    return build_response(
        success=True,
        message="Scheduled report deleted",
        data={},
        request_id=_request_id(request),
    )


__all__ = ["router"]
