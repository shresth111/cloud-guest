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

**No ``PlanFeatureKey.AUDIT_LOGS`` entitlement gate**: this domain's real
data is now surfaced org-scoped only from inside the customer dashboard's
Owner-only Admin Logs page (its "Account Activity" section) -- exactly
``app.domains.admin_logs.router``'s own posture, which was deliberately
never entitlement-gated for the identical reason its own docstring gives
("a real organization on a plan without that entitlement would otherwise
get a 402 on a page ... never asked to be plan-gated"). This endpoint
briefly *was* the pilot for ``app.domains.billing.dependencies
.RequireFeature`` / ``PlanFeatureKey.AUDIT_LOGS`` before the Audit Log tab
was folded into Admin Logs -- confirmed live against this feature's own
launch org ("xyz") that it does not hold that plan entitlement, which
would have made the merged Account Activity section silently empty for
the exact account this was built for. Dropped to match Admin Logs'
existing precedent rather than leave the two halves of one page
inconsistently gated.

**Owner-only when organization-scoped**: both endpoints additionally
require the real Organization Owner role *whenever called with an
organization context* (``X-Organization-Id``) -- ``audit_logs.read``/
``audit_logs.export`` alone is not enough to keep the customer dashboard's
use of this endpoint Owner-only, since Organization Admin (an
"Agent"-invitable role) also holds those permissions at ORGANIZATION scope
by default (see ``app.domains.admin_logs.router``'s own module docstring
for the full seed-table reasoning -- identical here). The customer
dashboard now surfaces this data only inside the Owner-only "Admin Logs"
page (its "Account Activity" section), so this closes the gap where an
Agent session could otherwise reach the same real change-audit trail
directly, even with the separate customer-side "Audit Log" nav entry
removed.

Deliberately *not* a plain ``RequireRole("organization-owner",
scope=ScopeType.ORGANIZATION)`` the way ``app.domains.admin_logs`` uses --
unlike that domain, this one is also queried with **no** organization
context at all (``requesting_organization_id=None`` means "search across
every organization", see ``service.py``'s own docstring) for a genuine
platform-level/cross-tenant caller. ``_require_owner_when_org_scoped``
below only narrows to Organization Owner when an organization context is
actually present -- an org-less call keeps relying on
``RequirePermission``'s own GLOBAL-scope check, unchanged.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Query, Request, Response, status

from app.common.responses import ApiResponse, build_response
from app.database.utils.pagination import PaginationMeta
from app.domains.auth.models import AuthUser
from app.domains.rbac.authorization import RoleResolver
from app.domains.rbac.context import ScopeContext
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequirePermission,
    get_rbac_repository,
)
from app.domains.rbac.exceptions import RoleNotHeldError
from app.domains.rbac.models import AuditLogEntry
from app.domains.rbac.repository import RBACRepositoryProtocol

from .dependencies import get_audit_service
from .schemas import AuditLogEntryListResponse, AuditLogEntryResponse
from .service import AuditService

router = APIRouter(prefix="/audit", tags=["Audit"])


async def _require_owner_when_org_scoped(
    user: AuthUser = Depends(CurrentUser),
    repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
    organization_id: uuid.UUID | None = Depends(CurrentOrganization),
) -> None:
    """See module docstring's "Owner-only when organization-scoped"
    section. A no-op (no DB lookup) when there is no organization context
    to narrow to."""
    if organization_id is None:
        return
    roles = await RoleResolver(repository).get_active_roles(
        uuid.UUID(user.id), scope_context=ScopeContext(organization_id=organization_id)
    )
    if not any(role.slug == "organization-owner" for role in roles):
        raise RoleNotHeldError("organization-owner")


# Shared by both routes below.
_OWNER_ONLY = Depends(_require_owner_when_org_scoped)


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
        _OWNER_ONLY,
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
        _OWNER_ONLY,
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
