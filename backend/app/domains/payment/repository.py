"""Repository layer for the Payment domain."""

from __future__ import annotations

import uuid
from typing import Protocol, Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories.generic import GenericRepository
from .models import Payment, Coupon


class PaymentRepositoryProtocol(Protocol):
    async def get_payment_by_id(self, payment_id: uuid.UUID) -> Payment | None: ...
    async def get_payment_by_intent(self, intent_id: str) -> Payment | None: ...
    async def list_payments_by_org(self, organization_id: uuid.UUID) -> Sequence[Payment]: ...
    async def create_payment(self, data: dict) -> Payment: ...
    async def update_payment(self, payment: Payment, data: dict) -> Payment: ...
    
    async def get_coupon_by_code(self, code: str) -> Coupon | None: ...
    async def create_coupon(self, data: dict) -> Coupon: ...
    async def update_coupon(self, coupon: Coupon, data: dict) -> Coupon: ...


class PaymentRepository(PaymentRepositoryProtocol):
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.pay_repo = GenericRepository(Payment, session)
        self.coupon_repo = GenericRepository(Coupon, session)

    async def get_payment_by_id(self, payment_id: uuid.UUID) -> Payment | None:
        stmt = select(Payment).where(
            Payment.id == payment_id,
            Payment.is_deleted == False
        )
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def get_payment_by_intent(self, intent_id: str) -> Payment | None:
        stmt = select(Payment).where(
            Payment.gateway_payment_intent_id == intent_id,
            Payment.is_deleted == False
        )
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def list_payments_by_org(self, organization_id: uuid.UUID) -> Sequence[Payment]:
        stmt = select(Payment).where(
            Payment.organization_id == organization_id,
            Payment.is_deleted == False
        ).order_by(Payment.created_at.desc())
        res = await self.session.execute(stmt)
        return res.scalars().all()

    async def create_payment(self, data: dict) -> Payment:
        return await self.pay_repo.create(data)

    async def update_payment(self, payment: Payment, data: dict) -> Payment:
        return await self.pay_repo.partial_update(payment, data)

    async def get_coupon_by_code(self, code: str) -> Coupon | None:
        stmt = select(Coupon).where(
            Coupon.code == code,
            Coupon.is_deleted == False
        )
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def create_coupon(self, data: dict) -> Coupon:
        return await self.coupon_repo.create(data)

    async def update_coupon(self, coupon: Coupon, data: dict) -> Coupon:
        return await self.coupon_repo.partial_update(coupon, data)
