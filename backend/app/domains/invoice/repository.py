"""Repository layer for the Invoice domain."""

from __future__ import annotations

import uuid
from typing import Protocol, Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories.generic import GenericRepository
from .models import Invoice, CreditNote


class InvoiceRepositoryProtocol(Protocol):
    async def get_by_id(self, invoice_id: uuid.UUID) -> Invoice | None: ...
    async def get_by_number(self, invoice_number: str) -> Invoice | None: ...
    async def list_by_org(self, organization_id: uuid.UUID) -> Sequence[Invoice]: ...
    async def create_invoice(self, data: dict) -> Invoice: ...
    async def update_invoice(self, invoice: Invoice, data: dict) -> Invoice: ...
    async def get_next_invoice_sequence(self) -> int: ...
    
    async def create_credit_note(self, data: dict) -> CreditNote: ...
    async def list_credit_notes_by_org(self, organization_id: uuid.UUID) -> Sequence[CreditNote]: ...


class InvoiceRepository(InvoiceRepositoryProtocol):
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.invoice_repo = GenericRepository(Invoice, session)
        self.cn_repo = GenericRepository(CreditNote, session)

    async def get_by_id(self, invoice_id: uuid.UUID) -> Invoice | None:
        stmt = select(Invoice).where(
            Invoice.id == invoice_id,
            Invoice.is_deleted == False
        )
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def get_by_number(self, invoice_number: str) -> Invoice | None:
        stmt = select(Invoice).where(
            Invoice.invoice_number == invoice_number,
            Invoice.is_deleted == False
        )
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def list_by_org(self, organization_id: uuid.UUID) -> Sequence[Invoice]:
        stmt = select(Invoice).where(
            Invoice.organization_id == organization_id,
            Invoice.is_deleted == False
        ).order_by(Invoice.created_at.desc())
        res = await self.session.execute(stmt)
        return res.scalars().all()

    async def create_invoice(self, data: dict) -> Invoice:
        return await self.invoice_repo.create(data)

    async def update_invoice(self, invoice: Invoice, data: dict) -> Invoice:
        return await self.invoice_repo.partial_update(invoice, data)

    async def get_next_invoice_sequence(self) -> int:
        # Mock counting existing invoices to generate sequential IDs safely
        stmt = select(Invoice)
        res = await self.session.execute(stmt)
        return len(res.scalars().all()) + 1

    async def create_credit_note(self, data: dict) -> CreditNote:
        return await self.cn_repo.create(data)

    async def list_credit_notes_by_org(self, organization_id: uuid.UUID) -> Sequence[CreditNote]:
        stmt = select(CreditNote).where(
            CreditNote.organization_id == organization_id,
            CreditNote.is_deleted == False
        ).order_by(CreditNote.created_at.desc())
        res = await self.session.execute(stmt)
        return res.scalars().all()
