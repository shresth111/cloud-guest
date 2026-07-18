"""Service layer for the Invoice domain."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Sequence

from .constants import InvoiceStatus
from .exceptions import InvoiceNotFoundError, InvoiceActionNotAllowedError
from .models import Invoice, CreditNote
from .repository import InvoiceRepositoryProtocol


class InvoiceService:
    def __init__(self, repository: InvoiceRepositoryProtocol) -> None:
        self.repository = repository

    async def _generate_invoice_number(self) -> str:
        """Generates a professional sequential invoice number like INV-2026-00001."""
        year = datetime.now(UTC).year
        seq = await self.repository.get_next_invoice_sequence()
        return f"INV-{year}-{seq:05d}"

    async def create_invoice(
        self,
        organization_id: uuid.UUID,
        subtotal: float,
        tax_rate: float = 0.18,
        discount_amount: float = 0.0,
        currency: str = "USD",
        subscription_id: uuid.UUID | None = None,
        line_items: list | None = None,
    ) -> Invoice:
        invoice_number = await self._generate_invoice_number()
        now = datetime.now(UTC)

        tax_amount = round((subtotal - discount_amount) * tax_rate, 2)
        total = round(subtotal - discount_amount + tax_amount, 2)

        data = {
            "organization_id": organization_id,
            "subscription_id": subscription_id,
            "invoice_number": invoice_number,
            "status": InvoiceStatus.DRAFT.value,
            "issue_date": now,
            "due_date": now + timedelta(days=14),  # Net 14 default
            "subtotal": subtotal,
            "tax_amount": tax_amount,
            "tax_rate": tax_rate,
            "discount_amount": discount_amount,
            "total": total,
            "currency": currency,
            "pdf_url": f"https://assets.cloudguest.net/invoices/{invoice_number}.pdf",
            "invoice_metadata": {
                "line_items": line_items or [],
                "tax_regime": "GST" if tax_rate == 0.18 else "Standard",
                "notes": "Thank you for your business!",
            },
        }

        return await self.repository.create_invoice(data)

    async def mark_paid(self, invoice_id: uuid.UUID) -> Invoice:
        invoice = await self.repository.get_by_id(invoice_id)
        if not invoice:
            raise InvoiceNotFoundError(str(invoice_id))

        if invoice.status == InvoiceStatus.VOID.value:
            raise InvoiceActionNotAllowedError("mark_paid", invoice.status)

        update_data = {
            "status": InvoiceStatus.PAID.value,
            "paid_at": datetime.now(UTC),
        }
        return await self.repository.update_invoice(invoice, update_data)

    async def void_invoice(self, invoice_id: uuid.UUID) -> Invoice:
        invoice = await self.repository.get_by_id(invoice_id)
        if not invoice:
            raise InvoiceNotFoundError(str(invoice_id))

        if invoice.status == InvoiceStatus.PAID.value:
            raise InvoiceActionNotAllowedError("void", invoice.status)

        return await self.repository.update_invoice(invoice, {"status": InvoiceStatus.VOID.value})

    async def issue_credit_note(
        self, invoice_id: uuid.UUID, organization_id: uuid.UUID, amount: float, reason: str | None = None
    ) -> CreditNote:
        invoice = await self.repository.get_by_id(invoice_id)
        if not invoice:
            raise InvoiceNotFoundError(str(invoice_id))

        data = {
            "invoice_id": invoice_id,
            "organization_id": organization_id,
            "amount": amount,
            "currency": invoice.currency,
            "reason": reason,
            "status": "applied",
        }
        return await self.repository.create_credit_note(data)

    async def get_invoice(self, invoice_id: uuid.UUID) -> Invoice:
        invoice = await self.repository.get_by_id(invoice_id)
        if not invoice:
            raise InvoiceNotFoundError(str(invoice_id))
        return invoice

    async def list_organization_invoices(self, organization_id: uuid.UUID) -> Sequence[Invoice]:
        return await self.repository.list_by_org(organization_id)

    async def list_organization_credit_notes(self, organization_id: uuid.UUID) -> Sequence[CreditNote]:
        return await self.repository.list_credit_notes_by_org(organization_id)
