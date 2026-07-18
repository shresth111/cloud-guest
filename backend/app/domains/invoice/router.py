"""API Router for the Invoice domain."""

import uuid
from typing import Sequence
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import RedirectResponse

from .dependencies import get_invoice_service
from .schemas import (
    CreditNoteCreate,
    CreditNoteResponse,
    InvoiceCreate,
    InvoiceResponse,
)
from .service import InvoiceService

router = APIRouter()


@router.post(
    "/invoices",
    response_model=InvoiceResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Invoices"],
)
async def create_invoice(
    payload: InvoiceCreate, service: InvoiceService = Depends(get_invoice_service)
):
    """Generate a new draft or official financial invoice."""
    return await service.create_invoice(
        organization_id=payload.organization_id,
        subtotal=payload.subtotal,
        tax_rate=payload.tax_rate,
        discount_amount=payload.discount_amount,
        currency=payload.currency,
        subscription_id=payload.subscription_id,
        line_items=payload.line_items,
    )


@router.get(
    "/invoices/organization/{organization_id}",
    response_model=Sequence[InvoiceResponse],
    tags=["Invoices"],
)
async def list_organization_invoices(
    organization_id: uuid.UUID,
    service: InvoiceService = Depends(get_invoice_service),
):
    """Retrieve all invoices issued to an organization."""
    return await service.list_organization_invoices(organization_id)


@router.get(
    "/invoices/{invoice_id}", response_model=InvoiceResponse, tags=["Invoices"]
)
async def get_invoice(
    invoice_id: uuid.UUID, service: InvoiceService = Depends(get_invoice_service)
):
    """Retrieve details of a specific invoice."""
    return await service.get_invoice(invoice_id)


@router.post(
    "/invoices/{invoice_id}/void", response_model=InvoiceResponse, tags=["Invoices"]
)
async def void_invoice(
    invoice_id: uuid.UUID, service: InvoiceService = Depends(get_invoice_service)
):
    """Mark an invoice as void/cancelled."""
    return await service.void_invoice(invoice_id)


@router.post(
    "/invoices/{invoice_id}/pay", response_model=InvoiceResponse, tags=["Invoices"]
)
async def pay_invoice(
    invoice_id: uuid.UUID, service: InvoiceService = Depends(get_invoice_service)
):
    """Manually apply payment to clear an invoice."""
    return await service.mark_paid(invoice_id)


@router.get("/invoices/{invoice_id}/download", tags=["Invoices"])
async def download_invoice(
    invoice_id: uuid.UUID, service: InvoiceService = Depends(get_invoice_service)
):
    """Redirect to the secure cloud hosted PDF file of the invoice."""
    inv = await service.get_invoice(invoice_id)
    if not inv.pdf_url:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invoice PDF is being compiled",
        )
    return RedirectResponse(url=inv.pdf_url)


@router.post(
    "/credit-notes",
    response_model=CreditNoteResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Credit Notes"],
)
async def issue_credit_note(
    payload: CreditNoteCreate, service: InvoiceService = Depends(get_invoice_service)
):
    """Issue a credit adjustment note against an invoice."""
    return await service.issue_credit_note(
        invoice_id=payload.invoice_id,
        organization_id=payload.organization_id,
        amount=payload.amount,
        reason=payload.reason,
    )
