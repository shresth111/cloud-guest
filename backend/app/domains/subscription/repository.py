"""Repository layer for the Subscription domain."""

from __future__ import annotations

import uuid
from typing import Protocol, Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories.generic import GenericRepository
from .models import SubscriptionPlan, Subscription, PlanChangeHistory


class SubscriptionRepositoryProtocol(Protocol):
    async def get_plan_by_id(self, plan_id: uuid.UUID) -> SubscriptionPlan | None: ...
    async def get_plan_by_code(self, code: str) -> SubscriptionPlan | None: ...
    async def list_active_plans(self) -> Sequence[SubscriptionPlan]: ...
    async def create_plan(self, data: dict) -> SubscriptionPlan: ...
    async def get_subscription_by_org(self, organization_id: uuid.UUID) -> Subscription | None: ...
    async def create_subscription(self, data: dict) -> Subscription: ...
    async def update_subscription(self, subscription: Subscription, data: dict) -> Subscription: ...
    async def get_subscription_by_id(self, subscription_id: uuid.UUID) -> Subscription | None: ...
    async def add_plan_change_history(self, data: dict) -> PlanChangeHistory: ...
    async def get_plan_change_history(self, organization_id: uuid.UUID) -> Sequence[PlanChangeHistory]: ...


class SubscriptionRepository(SubscriptionRepositoryProtocol):
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.plan_repo = GenericRepository(SubscriptionPlan, session)
        self.sub_repo = GenericRepository(Subscription, session)
        self.history_repo = GenericRepository(PlanChangeHistory, session)

    async def get_plan_by_id(self, plan_id: uuid.UUID) -> SubscriptionPlan | None:
        stmt = select(SubscriptionPlan).where(
            SubscriptionPlan.id == plan_id,
            SubscriptionPlan.is_deleted == False
        )
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def get_plan_by_code(self, code: str) -> SubscriptionPlan | None:
        stmt = select(SubscriptionPlan).where(
            SubscriptionPlan.code == code,
            SubscriptionPlan.is_deleted == False
        )
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def list_active_plans(self) -> Sequence[SubscriptionPlan]:
        stmt = select(SubscriptionPlan).where(
            SubscriptionPlan.is_active == True,
            SubscriptionPlan.is_deleted == False
        )
        res = await self.session.execute(stmt)
        return res.scalars().all()

    async def create_plan(self, data: dict) -> SubscriptionPlan:
        return await self.plan_repo.create(data)

    async def get_subscription_by_org(self, organization_id: uuid.UUID) -> Subscription | None:
        stmt = select(Subscription).where(
            Subscription.organization_id == organization_id,
            Subscription.is_deleted == False
        ).order_by(Subscription.created_at.desc())
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def create_subscription(self, data: dict) -> Subscription:
        return await self.sub_repo.create(data)

    async def update_subscription(self, subscription: Subscription, data: dict) -> Subscription:
        return await self.sub_repo.partial_update(subscription, data)

    async def get_subscription_by_id(self, subscription_id: uuid.UUID) -> Subscription | None:
        stmt = select(Subscription).where(
            Subscription.id == subscription_id,
            Subscription.is_deleted == False
        )
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def add_plan_change_history(self, data: dict) -> PlanChangeHistory:
        return await self.history_repo.create(data)

    async def get_plan_change_history(self, organization_id: uuid.UUID) -> Sequence[PlanChangeHistory]:
        stmt = select(PlanChangeHistory).where(
            PlanChangeHistory.organization_id == organization_id,
            PlanChangeHistory.is_deleted == False
        ).order_by(PlanChangeHistory.created_at.desc())
        res = await self.session.execute(stmt)
        return res.scalars().all()
