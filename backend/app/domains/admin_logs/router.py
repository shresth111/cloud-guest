"""FastAPI routes for the Admin Logs domain: the customer dashboard's
"Admin Logs" page, with two real, organization-scoped log categories
(see ``service.py``'s own module docstring for how each is sourced).

Responses use the project's standard envelope (``ApiResponse``/
``build_response``), matching every other domain's router.

## Owner-only

Every endpoint requires an organization context (``RequireOrganization``
-- 400s with no ``X-Organization-Id`` header), the already-seeded
``audit_logs.read`` permission (``RequirePermission`` -- the same reuse
posture ``app.domains.controller_logs``/``app.domains.audit`` already
established for ``PermissionModule.AUDIT_LOGS``: log viewing is exactly
what that module was seeded for), *and* an explicit, additional
``RequireRole("organization-owner", scope=ScopeType.ORGANIZATION)``
check.

The permission alone is deliberately not enough to keep this page
Owner-only: Organization Admin (an "Agent"-invitable role via the
Manage Agents invite flow) also holds ``audit_logs.read`` at
ORGANIZATION scope by default (see ``app.domains.rbac.seed``'s own
``SYSTEM_ROLES`` table -- ``AUDIT_LOGS``'s applicable actions are all
non-``MANAGE``/``DELETE``, so Organization Admin's ``OPERATE`` default
resolves to the exact same grant as Organization Owner's own ``FULL``
default for this one module). ``RequireRole`` -- an existing,
general-purpose RBAC dependency (``app.domains.rbac.dependencies``), not
a new permission -- is what actually narrows this down to the real
Organization Owner, without touching ``app.domains.rbac.seed`` at all.

Deliberately *not* gated by ``app.domains.billing``'s
``PlanFeatureKey.AUDIT_LOGS`` entitlement the way ``app.domains.audit``
is -- that is a separate, plan/billing-driven concern (which
organizations paid for the Audit Logs *feature*) orthogonal to this
page's own access-control requirement (which *role* can see it). A real
organization on a plan without that entitlement (confirmed in
production against this feature's own launch org) would otherwise get a
402 on a page this task's own requirement never asked to be
plan-gated.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request, status

from app.common.responses import ApiResponse, build_response
from app.database.utils.pagination import PaginationMeta
from app.domains.auth.models import LoginAttempt
from app.domains.rbac.dependencies import (
    RequireOrganization,
    RequirePermission,
    RequireRole,
)
from app.domains.rbac.enums import ScopeType

from .constants import ERROR_EVENT_TYPES
from .dependencies import get_admin_logs_service
from .schemas import (
    DashboardLoginLogListResponse,
    DashboardLoginLogResponse,
    RouterErrorLogListResponse,
    RouterErrorLogResponse,
)
from .service import AdminLogsService, RouterLogRow

router = APIRouter(prefix="/admin-logs", tags=["Admin Logs"])

# Shared by both routes below -- see module docstring for why both are
# required together (permission + role, not permission alone).
_OWNER_ONLY_DEPENDENCIES = [
    Depends(RequirePermission("audit_logs.read")),
    Depends(RequireRole("organization-owner", scope=ScopeType.ORGANIZATION)),
]


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


def _dashboard_login_response(attempt: LoginAttempt) -> DashboardLoginLogResponse:
    return DashboardLoginLogResponse(
        id=str(attempt.id),
        user_id=str(attempt.user_id) if attempt.user_id else None,
        email=attempt.email,
        ip_address=attempt.ip_address,
        success=attempt.success,
        failure_reason=attempt.failure_reason,
        created_at=attempt.created_at,
    )


def _router_error_response(row: RouterLogRow) -> RouterErrorLogResponse:
    event = row.event
    return RouterErrorLogResponse(
        id=str(event.id),
        location_id=str(row.location_id),
        location_name=row.location_name,
        router_id=str(row.router_id),
        router_name=row.router_name,
        event_type=event.event_type,
        message=event.message,
        occurred_at=event.occurred_at,
        is_error=event.event_type in ERROR_EVENT_TYPES,
    )


@router.get(
    "/dashboard-logins",
    response_model=ApiResponse[DashboardLoginLogListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=_OWNER_ONLY_DEPENDENCIES,
)
async def list_dashboard_logins(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    service: AdminLogsService = Depends(get_admin_logs_service),
):
    attempts, meta = await service.list_dashboard_logins(
        organization_id=organization_id, page=page, page_size=page_size
    )
    payload = DashboardLoginLogListResponse(
        items=[_dashboard_login_response(a) for a in attempts],
        **_pagination_fields(meta),
    )
    return build_response(
        success=True,
        message="Dashboard login logs retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/router-events",
    response_model=ApiResponse[RouterErrorLogListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=_OWNER_ONLY_DEPENDENCIES,
)
async def list_router_event_logs(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    service: AdminLogsService = Depends(get_admin_logs_service),
):
    rows, meta = await service.list_router_error_logs(
        organization_id=organization_id, page=page, page_size=page_size
    )
    payload = RouterErrorLogListResponse(
        items=[_router_error_response(r) for r in rows],
        **_pagination_fields(meta),
    )
    return build_response(
        success=True,
        message="Router event logs retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["router"]
