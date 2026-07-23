"""FastAPI routes for the Support Tickets domain.

Customers (org members) raise a support ticket from their own
organization's dashboard (``POST``/``GET``, always scoped by
``CurrentOrganization`` -- ``X-Organization-Id``); platform admins see
every organization's tickets on the Master dashboard and update
status/assignment/resolution (``PATCH``). ``GET /support-tickets`` serves
both: when ``X-Organization-Id`` is present it lists that organization's
own tickets (the customer dashboard view); when absent -- a platform-level
caller with no organization context -- it lists across every organization
(the Master dashboard view), gated the same way every other list endpoint
in this codebase is, by ``support_tickets.read``.

Every endpoint is gated by RBAC's existing ``RequirePermission`` dependency
against the ``support_tickets.*`` permission keys
(``app.domains.rbac.seed.MODULE_ACTIONS[PermissionModule.SUPPORT_TICKETS]``)
-- mirrors ``app.domains.guest_access.router``'s identical pattern. No
``DELETE`` endpoint: tickets are closed, not deleted.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request, status

from app.common.responses import ApiResponse, build_response
from app.domains.auth.models import AuthUser
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequirePermission,
)

from .dependencies import get_ticket_service
from .repository import TicketRecord
from .schemas import (
    TicketCreateRequest,
    TicketListResponse,
    TicketResponse,
    TicketUpdateRequest,
)
from .service import TicketService

router = APIRouter(prefix="/support-tickets", tags=["Support Tickets"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _ticket_response(record: TicketRecord) -> TicketResponse:
    ticket = record.ticket
    return TicketResponse(
        id=ticket.id,
        organization_id=ticket.organization_id,
        location_id=ticket.location_id,
        created_by_user_id=ticket.created_by_user_id,
        created_by_name=record.created_by_name,
        created_by_email=record.created_by_email,
        assigned_to_user_id=ticket.assigned_to_user_id,
        assigned_to_name=record.assigned_to_name,
        subject=ticket.subject,
        description=ticket.description,
        category=ticket.category,
        priority=ticket.priority,
        status=ticket.status,
        resolution_notes=ticket.resolution_notes,
        resolved_at=ticket.resolved_at,
        created_at=ticket.created_at,
        updated_at=ticket.updated_at,
    )


@router.post(
    "",
    response_model=ApiResponse[TicketResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("support_tickets.create"))],
)
async def create_ticket(
    request: Request,
    payload: TicketCreateRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: TicketService = Depends(get_ticket_service),
):
    record = await service.create_ticket(
        requesting_organization_id=requesting_organization_id,
        location_id=(
            uuid.UUID(payload.location_id) if payload.location_id is not None else None
        ),
        subject=payload.subject,
        description=payload.description,
        category=payload.category,
        priority=payload.priority,
        created_by_user_id=uuid.UUID(user.id),
    )
    return build_response(
        success=True,
        message="Support ticket created",
        data=_ticket_response(record).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "",
    response_model=ApiResponse[TicketListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("support_tickets.read"))],
)
async def list_tickets(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    ticket_status: str | None = Query(default=None, alias="status"),
    priority: str | None = Query(default=None),
    search: str | None = Query(default=None),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: TicketService = Depends(get_ticket_service),
):
    result = await service.list_tickets(
        requesting_organization_id=requesting_organization_id,
        page=page,
        page_size=page_size,
        status=ticket_status,
        priority=priority,
        search=search,
    )
    payload = TicketListResponse(
        items=[_ticket_response(r) for r in result.items],
        page=result.meta.page,
        page_size=result.meta.page_size,
        total_items=result.meta.total_items,
        total_pages=result.meta.total_pages,
        has_next=result.meta.has_next,
        has_previous=result.meta.has_previous,
    )
    return build_response(
        success=True,
        message="Support tickets retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/{ticket_id}",
    response_model=ApiResponse[TicketResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("support_tickets.read"))],
)
async def get_ticket(
    request: Request,
    ticket_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: TicketService = Depends(get_ticket_service),
):
    record = await service.get_ticket(
        ticket_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Support ticket retrieved",
        data=_ticket_response(record).model_dump(),
        request_id=_request_id(request),
    )


@router.patch(
    "/{ticket_id}",
    response_model=ApiResponse[TicketResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("support_tickets.manage"))],
)
async def update_ticket(
    request: Request,
    ticket_id: uuid.UUID,
    payload: TicketUpdateRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: TicketService = Depends(get_ticket_service),
):
    data = payload.model_dump(exclude_unset=True)
    if "assigned_to_user_id" in data and data["assigned_to_user_id"] is not None:
        data["assigned_to_user_id"] = uuid.UUID(data["assigned_to_user_id"])
    record = await service.update_ticket(
        ticket_id=ticket_id,
        requesting_organization_id=requesting_organization_id,
        data=data,
        actor_user_id=uuid.UUID(user.id),
    )
    return build_response(
        success=True,
        message="Support ticket updated",
        data=_ticket_response(record).model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["router"]
