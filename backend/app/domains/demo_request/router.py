"""FastAPI routes for the Demo Request domain.

``POST /demo-requests`` is a **public, unauthenticated** "Book a Demo"
lead-capture endpoint -- a prospective customer submitting this form has,
by definition, no platform-user identity or JWT to present, the same
"there is no RBAC permission a guest could ever be granted" justification
``app.domains.otp.router``'s own module docstring already establishes for
``POST /otp/request``. It carries no ``RequirePermission``/``CurrentUser``
dependency, and is explicitly allowlisted (with this same reason) in
``tests/unit/test_route_permission_coverage.py``'s
``_ALLOWED_UNAUTHENTICATED_ROUTES``. Abuse protection comes from
``app.middleware.rate_limit.RateLimitMiddleware`` (this path is added to
``RATE_LIMITED_PATH_PREFIXES``, the same per-IP throttling every other
genuinely public endpoint in this codebase already gets) plus Pydantic
input validation (``EmailStr``, length bounds -- see ``schemas.py``).

``GET /demo-requests``/``GET /demo-requests/{id}``/``PATCH
/demo-requests/{id}`` are the Master console's internal view -- gated by
RBAC's existing ``RequirePermission`` dependency against the
``demo_requests.*`` permission keys
(``app.domains.rbac.seed.MODULE_ACTIONS[PermissionModule.DEMO_REQUESTS]``),
seeded at ``ScopeType.GLOBAL`` (a demo request belongs to no organization --
see ``models.py``'s own module docstring) -- mirrors
``app.domains.support_tickets.router``'s identical RBAC-gated-admin-view
pattern, minus the tenant-scoping/reply-thread/WebSocket machinery this
much simpler, non-tenant-scoped domain has no need for.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request, status

from app.common.responses import ApiResponse, build_response
from app.domains.auth.models import AuthUser
from app.domains.rbac.dependencies import CurrentUser, RequirePermission

from .dependencies import get_demo_request_service
from .models import DemoRequest
from .schemas import (
    DemoRequestCreateRequest,
    DemoRequestListResponse,
    DemoRequestResponse,
    DemoRequestUpdateRequest,
)
from .service import DemoRequestService

router = APIRouter(prefix="/demo-requests", tags=["Demo Requests"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _demo_request_response(demo_request: DemoRequest) -> DemoRequestResponse:
    return DemoRequestResponse(
        id=demo_request.id,
        full_name=demo_request.full_name,
        email=demo_request.email,
        phone=demo_request.phone,
        company_name=demo_request.company_name,
        message=demo_request.message,
        status=demo_request.status,
        internal_notes=demo_request.internal_notes,
        submitted_at=demo_request.created_at,
        updated_at=demo_request.updated_at,
    )


# ============================================================================
# Public: lead capture, no auth
# ============================================================================


@router.post(
    "",
    response_model=ApiResponse[DemoRequestResponse],
    status_code=status.HTTP_201_CREATED,
)
async def submit_demo_request(
    request: Request,
    payload: DemoRequestCreateRequest,
    service: DemoRequestService = Depends(get_demo_request_service),
):
    demo_request = await service.submit_demo_request(
        full_name=payload.full_name,
        email=payload.email,
        phone=payload.phone,
        company_name=payload.company_name,
        message=payload.message,
    )
    return build_response(
        success=True,
        message="Thanks! Our team will reach out to schedule your demo.",
        data=_demo_request_response(demo_request).model_dump(mode="json"),
        request_id=_request_id(request),
    )


# ============================================================================
# Master console: RBAC-gated
# ============================================================================


@router.get(
    "",
    response_model=ApiResponse[DemoRequestListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("demo_requests.read"))],
)
async def list_demo_requests(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    request_status: str | None = Query(default=None, alias="status"),
    search: str | None = Query(default=None),
    service: DemoRequestService = Depends(get_demo_request_service),
):
    result = await service.list_demo_requests(
        page=page, page_size=page_size, status=request_status, search=search
    )
    payload = DemoRequestListResponse(
        items=[_demo_request_response(r) for r in result.items],
        page=result.meta.page,
        page_size=result.meta.page_size,
        total_items=result.meta.total_items,
        total_pages=result.meta.total_pages,
        has_next=result.meta.has_next,
        has_previous=result.meta.has_previous,
    )
    return build_response(
        success=True,
        message="Demo requests retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/{demo_request_id}",
    response_model=ApiResponse[DemoRequestResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("demo_requests.read"))],
)
async def get_demo_request(
    request: Request,
    demo_request_id: uuid.UUID,
    service: DemoRequestService = Depends(get_demo_request_service),
):
    demo_request = await service.get_demo_request(demo_request_id)
    return build_response(
        success=True,
        message="Demo request retrieved",
        data=_demo_request_response(demo_request).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.patch(
    "/{demo_request_id}",
    response_model=ApiResponse[DemoRequestResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("demo_requests.manage"))],
)
async def update_demo_request(
    request: Request,
    demo_request_id: uuid.UUID,
    payload: DemoRequestUpdateRequest,
    user: AuthUser = Depends(CurrentUser),
    service: DemoRequestService = Depends(get_demo_request_service),
):
    data = payload.model_dump(exclude_unset=True)
    demo_request = await service.update_demo_request(
        demo_request_id=demo_request_id,
        data=data,
        actor_user_id=uuid.UUID(user.id),
    )
    return build_response(
        success=True,
        message="Demo request updated",
        data=_demo_request_response(demo_request).model_dump(mode="json"),
        request_id=_request_id(request),
    )


__all__ = ["router"]
