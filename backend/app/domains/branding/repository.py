"""Repository layer for the Branding domain."""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories.generic import GenericRepository
from .models import Branding


class BrandingRepositoryProtocol(Protocol):
    async def get_by_organization(self, organization_id: uuid.UUID) -> Branding | None: ...
    async def get_by_location(self, location_id: uuid.UUID) -> Branding | None: ...
    async def create_branding(self, data: dict) -> Branding: ...
    async def update_branding(self, branding: Branding, data: dict) -> Branding: ...


class BrandingRepository(BrandingRepositoryProtocol):
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.repo = GenericRepository(Branding, session)

    async def get_by_organization(self, organization_id: uuid.UUID) -> Branding | None:
        stmt = select(Branding).where(
            Branding.organization_id == organization_id,
            Branding.is_deleted == False
        )
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def get_by_location(self, location_id: uuid.UUID) -> Branding | None:
        stmt = select(Branding).where(
            Branding.location_id == location_id,
            Branding.is_deleted == False
        )
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def create_branding(self, data: dict) -> Branding:
        return await self.repo.create(data)

    async def update_branding(self, branding: Branding, data: dict) -> Branding:
        return await self.repo.partial_update(branding, data)
