"""Repository layer for the Billing domain."""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories.generic import GenericRepository
from .models import BillingProfile


class BillingRepositoryProtocol(Protocol):
    async def get_by_org_id(self, organization_id: uuid.UUID) -> BillingProfile | None: ...
    async def create_profile(self, data: dict) -> BillingProfile: ...
    async def update_profile(self, profile: BillingProfile, data: dict) -> BillingProfile: ...


class BillingRepository(BillingRepositoryProtocol):
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.profile_repo = GenericRepository(BillingProfile, session)

    async def get_by_org_id(self, organization_id: uuid.UUID) -> BillingProfile | None:
        stmt = select(BillingProfile).where(
            BillingProfile.organization_id == organization_id,
            BillingProfile.is_deleted == False
        )
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def create_profile(self, data: dict) -> BillingProfile:
        return await self.profile_repo.create(data)

    async def update_profile(self, profile: BillingProfile, data: dict) -> BillingProfile:
        return await self.profile_repo.partial_update(profile, data)
