"""FastAPI routes for the Analytics domain (BE-012 Part 1: Analytics Core
Infrastructure).

A deliberately minimal surface for this infra-focused part -- full
dashboard/per-domain-analytics/forecasting/reporting endpoints are later
BE-012 parts' job, not this one's. Two endpoints:

* ``GET /analytics/snapshots`` -- query already-computed snapshots by
  organization/location/type/date-range.
* ``POST /analytics/snapshots/trigger`` -- manually (re)trigger aggregation
  for one organization (on-demand recomputation, e.g. after a data
  backfill, without waiting for the next Beat tick).

## RBAC permission-key choices

``GET /analytics/snapshots`` uses ``analytics.read`` --
``app.domains.rbac.enums.PermissionModule.ANALYTICS`` is already seeded
(``app.domains.rbac.seed.MODULE_ACTIONS``) with exactly this action, and
``app.domains.guest.router``'s own analytics endpoints already establish
the precedent of gating guest-analytics reads behind this same key.

``POST /analytics/snapshots/trigger`` uses ``reports.manage`` --
``PermissionModule.ANALYTICS`` is seeded with only ``read``/``export``/
``view`` (no ``manage``/``create``/``execute`` action exists for it), so an
admin-gated *write* action (triggering real, if cheap, aggregation work on
demand) has no dedicated ``analytics.*`` key to reuse.
``PermissionModule.REPORTS`` is seeded with ``manage``, and
``app.domains.monitoring.router`` already establishes the precedent of
reusing ``reports.manage`` for an analytics-adjacent admin write action with
no dedicated key of its own (SLA target creation, on-demand SLA report
generation) -- this endpoint follows that exact precedent rather than
inventing a new permission module for one write action.

## Tenant isolation

``GET /analytics/snapshots``' ``organization_id`` is resolved via RBAC's
``CurrentOrganization`` dependency (``X-Organization-Id`` header), not a
raw, unchecked query parameter -- mirrors
``app.domains.guest.router``'s own analytics endpoints (``RequireOrganization``
there; ``CurrentOrganization`` here since an org-less, platform-wide query is
also a legal request for a GLOBAL-scoped caller, e.g. querying
``PLATFORM_DAILY_SUMMARY`` rows). When the header is present,
``CurrentOrganization`` itself validates the organization exists and that
the caller holds an *active* membership in it (raising otherwise) --
exactly the same tenant-isolation guarantee every other domain's own
organization-scoped endpoints already rely on, not reimplemented here.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Query, Request, status

from app.common.responses import ApiResponse, build_response
from app.domains.rbac.dependencies import CurrentOrganization, RequirePermission

from .constants import AnalyticsSnapshotType
from .dependencies import get_analytics_service
from .models import AnalyticsSnapshot
from .schemas import (
    AnalyticsSnapshotListResponse,
    AnalyticsSnapshotResponse,
    TriggerAggregationRequest,
    TriggerAggregationResponse,
)
from .service import AnalyticsService

router = APIRouter(tags=["Analytics"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _snapshot_response(snapshot: AnalyticsSnapshot) -> AnalyticsSnapshotResponse:
    return AnalyticsSnapshotResponse.model_validate(snapshot)


@router.get(
    "/analytics/snapshots",
    response_model=ApiResponse[AnalyticsSnapshotListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("analytics.read"))],
)
async def list_snapshots(
    request: Request,
    organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    location_id: uuid.UUID | None = Query(default=None),
    snapshot_type: AnalyticsSnapshotType | None = Query(default=None),
    start_date: datetime | None = Query(default=None),
    end_date: datetime | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    service: AnalyticsService = Depends(get_analytics_service),
):
    items, meta = await service.list_snapshots(
        organization_id=organization_id,
        location_id=location_id,
        snapshot_type=snapshot_type,
        start=start_date,
        end=end_date,
        page=page,
        page_size=page_size,
    )
    payload = AnalyticsSnapshotListResponse(
        items=[_snapshot_response(item) for item in items],
        page=meta.page,
        page_size=meta.page_size,
        total_items=meta.total_items,
        total_pages=meta.total_pages,
        has_next=meta.has_next,
        has_previous=meta.has_previous,
    )
    return build_response(
        success=True,
        message="Analytics snapshots retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.post(
    "/analytics/snapshots/trigger",
    response_model=ApiResponse[TriggerAggregationResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("reports.manage"))],
)
async def trigger_snapshot_aggregation(
    request: Request,
    payload: TriggerAggregationRequest,
    service: AnalyticsService = Depends(get_analytics_service),
):
    snapshots = await service.trigger_aggregation(
        payload.organization_id, target_date_iso=payload.target_date_iso
    )
    response_payload = TriggerAggregationResponse(
        organization_id=payload.organization_id,
        snapshots=[_snapshot_response(item) for item in snapshots],
    )
    return build_response(
        success=True,
        message="Analytics aggregation triggered",
        data=response_payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


__all__ = ["router"]
