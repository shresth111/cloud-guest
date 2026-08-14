"""FastAPI routes for the Quotation domain.

Every endpoint is Master-console-only and RBAC-gated by
``RequirePermission`` against ``quotations.*``
(``app.domains.rbac.seed.MODULE_ACTIONS[PermissionModule.QUOTATIONS]``,
seeded at ``ScopeType.GLOBAL`` -- a quotation belongs to no organization,
see ``models.py``'s own module docstring) -- mirrors
``app.domains.demo_request.router``'s identical RBAC-gated-admin-view
pattern for its own Master-console-only endpoints. Unlike Demo Requests,
there is no public/unauthenticated endpoint here at all: a quotation is
always operator-initiated.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request, Response, status

from app.common.responses import ApiResponse, build_response
from app.domains.auth.models import AuthUser
from app.domains.rbac.dependencies import CurrentUser, RequirePermission

from .dependencies import get_quotation_service
from .models import Quotation, QuotationLineItem
from .schemas import (
    QuotationCreateRequest,
    QuotationLineItemResponse,
    QuotationListResponse,
    QuotationResponse,
)
from .service import LineItemInput, QuotationService

router = APIRouter(prefix="/quotations", tags=["Quotations"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


async def _quotation_response(
    quotation: Quotation, service: QuotationService
) -> QuotationResponse:
    items = await service.list_line_items(quotation.id)
    return _build_quotation_response(quotation, items)


def _build_quotation_response(
    quotation: Quotation, items: list[QuotationLineItem]
) -> QuotationResponse:
    return QuotationResponse(
        id=quotation.id,
        quotation_number=quotation.quotation_number,
        status=quotation.status,
        client_name=quotation.client_name,
        client_email=quotation.client_email,
        client_company_name=quotation.client_company_name,
        line_items=[
            QuotationLineItemResponse.model_validate(item) for item in items
        ],
        subtotal=quotation.subtotal,
        tax_percentage=quotation.tax_percentage,
        tax_amount=quotation.tax_amount,
        total_amount=quotation.total_amount,
        currency=quotation.currency,
        valid_until=quotation.valid_until,
        notes=quotation.notes,
        sent_at=quotation.sent_at,
        email_error=quotation.email_error,
        created_at=quotation.created_at,
        updated_at=quotation.updated_at,
    )


@router.post(
    "",
    response_model=ApiResponse[QuotationResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("quotations.create"))],
)
async def create_and_send_quotation(
    request: Request,
    payload: QuotationCreateRequest,
    user: AuthUser = Depends(CurrentUser),
    service: QuotationService = Depends(get_quotation_service),
):
    """Generates a branded PDF quotation and emails it to the client in one
    step. Always returns ``201`` with the created quotation -- a failed or
    unconfigured email send never fails this request, it is reflected in
    the returned ``status``/``email_error`` fields instead (see
    ``service.QuotationService``'s own docstring)."""
    quotation = await service.create_and_send_quotation(
        actor_user_id=uuid.UUID(user.id),
        client_name=payload.client_name,
        client_email=payload.client_email,
        client_company_name=payload.client_company_name,
        line_items=[
            LineItemInput(
                description=item.description,
                quantity=item.quantity,
                unit_price=item.unit_price,
            )
            for item in payload.line_items
        ],
        tax_percentage=payload.tax_percentage,
        currency=payload.currency,
        valid_until=payload.valid_until,
        notes=payload.notes,
    )
    response_payload = await _quotation_response(quotation, service)
    return build_response(
        success=True,
        message=(
            f"Quotation {quotation.quotation_number} generated and emailed to "
            f"{quotation.client_email}"
            if quotation.status == "sent"
            else f"Quotation {quotation.quotation_number} generated, but the "
            "email could not be sent"
        ),
        data=response_payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "",
    response_model=ApiResponse[QuotationListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("quotations.read"))],
)
async def list_quotations(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    quotation_status: str | None = Query(default=None, alias="status"),
    search: str | None = Query(default=None),
    service: QuotationService = Depends(get_quotation_service),
):
    result = await service.list_quotations(
        page=page, page_size=page_size, status=quotation_status, search=search
    )
    items = []
    for quotation in result.items:
        line_items = await service.list_line_items(quotation.id)
        items.append(_build_quotation_response(quotation, line_items))
    payload = QuotationListResponse(
        items=items,
        page=result.meta.page,
        page_size=result.meta.page_size,
        total_items=result.meta.total_items,
        total_pages=result.meta.total_pages,
        has_next=result.meta.has_next,
        has_previous=result.meta.has_previous,
    )
    return build_response(
        success=True,
        message="Quotations retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/{quotation_id}",
    response_model=ApiResponse[QuotationResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("quotations.read"))],
)
async def get_quotation(
    request: Request,
    quotation_id: uuid.UUID,
    service: QuotationService = Depends(get_quotation_service),
):
    quotation = await service.get_quotation(quotation_id)
    response_payload = await _quotation_response(quotation, service)
    return build_response(
        success=True,
        message="Quotation retrieved",
        data=response_payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/{quotation_id}/pdf",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("quotations.read"))],
)
async def download_quotation_pdf(
    quotation_id: uuid.UUID,
    service: QuotationService = Depends(get_quotation_service),
):
    """Lets an operator fetch the exact same PDF that was (or would have
    been) emailed -- the fallback ``billing.router``'s own docstring calls
    out for a failed send: "hand them the ``/download`` link directly"."""
    quotation = await service.get_quotation(quotation_id)
    items = await service.list_line_items(quotation_id)
    pdf_bytes = service.pdf_renderer(quotation, items)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{quotation.quotation_number}.pdf"'
            )
        },
    )


__all__ = ["router"]
