"""FastAPI routes for the audit domain: query + CSV export over RBAC's
existing ``audit_log_entries`` table.

Responses use the project's standard envelope (``ApiResponse``/
``build_response``), matching every other domain's router -- except
``GET .../export``, which deliberately returns raw ``text/csv``, the same
deviation ``app.domains.voucher.router.export_voucher_batch`` already
establishes for an identical "downloadable file, not JSON" reason. Every
endpoint is gated by RBAC's existing ``RequirePermission`` dependency
against ``audit_logs.*`` (``PermissionModule.AUDIT_LOGS``, already seeded)
and resolves ``CurrentOrganization``, passed through as
``requesting_organization_id``.

**Entitlement pilot**: both endpoints additionally require
``PlanFeatureKey.AUDIT_LOGS`` via ``app.domains.billing.dependencies
.RequireFeature`` -- this is the first domain wired to the new
request-time license/feature-entitlement gate (see that module's own
docstring). A ``None`` organization context (no ``X-Organization-Id``
header) still passes through unchecked, same as ``RequirePermission``'s
own GLOBAL-scope behavior, so a platform-level caller is unaffected.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Query, Request, Response, status

from app.common.responses import ApiResponse, build_response
from app.database.utils.pagination import PaginationMeta
from app.domains.billing.constants import PlanFeatureKey
from app.domains.billing.dependencies import RequireFeature
from app.domains.rbac.dependencies import CurrentOrganization, RequirePermission
from app.domains.rbac.models import AuditLogEntry

from .dependencies import get_audit_service
from .schemas import AuditLogEntryListResponse, AuditLogEntryResponse
from .service import AuditService

router = APIRouter(prefix="/audit", tags=["Audit"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _pagination_fields(meta: PaginationMeta) -> dict[str, int | bool]:
    return {
        "page": meta.page,
        "page_size": meta.page_size,
        "total_items": meta.total_items,
        "total_pages": meta.total_pages,
        "has_next": meta.has_next,
        "has_previous": meta.has_previous,
    }


def _entry_response(entry: AuditLogEntry) -> AuditLogEntryResponse:
    return AuditLogEntryResponse(
        id=str(entry.id),
        actor_user_id=str(entry.actor_user_id) if entry.actor_user_id else None,
        action=entry.action,
        entity_type=entry.entity_type,
        entity_id=str(entry.entity_id) if entry.entity_id else None,
        description=entry.description,
        organization_id=str(entry.organization_id) if entry.organization_id else None,
        location_id=str(entry.location_id) if entry.location_id else None,
        created_at=entry.created_at,
    )


@router.get(
    "/entries",
    response_model=ApiResponse[AuditLogEntryListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(RequirePermission("audit_logs.read")),
        Depends(RequireFeature(PlanFeatureKey.AUDIT_LOGS)),
    ],
)
async def search_audit_log_entries(
    request: Request,
    actor_user_id: uuid.UUID | None = Query(default=None),
    action: str | None = Query(default=None),
    entity_type: str | None = Query(default=None),
    location_id: uuid.UUID | None = Query(default=None),
    start: datetime | None = Query(default=None),
    end: datetime | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: AuditService = Depends(get_audit_service),
):
    entries, meta = await service.search(
        requesting_organization_id=requesting_organization_id,
        actor_user_id=actor_user_id,
        action=action,
        entity_type=entity_type,
        location_id=location_id,
        start=start,
        end=end,
        page=page,
        page_size=page_size,
    )
    payload = AuditLogEntryListResponse(
        items=[_entry_response(entry) for entry in entries],
        **_pagination_fields(meta),
    )
    return build_response(
        success=True,
        message="Audit log entries retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/entries/export",
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(RequirePermission("audit_logs.export")),
        Depends(RequireFeature(PlanFeatureKey.AUDIT_LOGS)),
    ],
)
async def export_audit_log_entries(
    actor_user_id: uuid.UUID | None = Query(default=None),
    action: str | None = Query(default=None),
    entity_type: str | None = Query(default=None),
    location_id: uuid.UUID | None = Query(default=None),
    start: datetime | None = Query(default=None),
    end: datetime | None = Query(default=None),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: AuditService = Depends(get_audit_service),
) -> Response:
    csv_text, truncated = await service.export_csv(
        requesting_organization_id=requesting_organization_id,
        actor_user_id=actor_user_id,
        action=action,
        entity_type=entity_type,
        location_id=location_id,
        start=start,
        end=end,
    )
    headers = {"Content-Disposition": 'attachment; filename="audit_log_export.csv"'}
    if truncated:
        # Real, visible signal (not a silently-incomplete download) --
        # see service.py's own docstring for why the export caps at
        # AUDIT_EXPORT_MAX_ROWS.
        headers["X-Export-Truncated"] = "true"
    return Response(content=csv_text, media_type="text/csv", headers=headers)


__all__ = ["router"]
