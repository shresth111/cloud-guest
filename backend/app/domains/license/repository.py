"""Repository layer for the License domain."""

from __future__ import annotations

import uuid
from typing import Protocol, Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories.generic import GenericRepository
from .models import License


class LicenseRepositoryProtocol(Protocol):
    async def get_by_key(self, key: str) -> License | None: ...
    async def get_by_id(self, license_id: uuid.UUID) -> License | None: ...
    async def list_by_organization(self, organization_id: uuid.UUID) -> Sequence[License]: ...
    async def create_license(self, data: dict) -> License: ...
    async def update_license(self, license: License, data: dict) -> License: ...


class LicenseRepository(LicenseRepositoryProtocol):
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.repo = GenericRepository(License, session)

    async def get_by_key(self, key: str) -> License | None:
        stmt = select(License).where(
            License.license_key == key,
            License.is_deleted == False
        )
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def get_by_id(self, license_id: uuid.UUID) -> License | None:
        stmt = select(License).where(
            License.id == license_id,
            License.is_deleted == False
        )
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def list_by_organization(self, organization_id: uuid.UUID) -> Sequence[License]:
        stmt = select(License).where(
            License.organization_id == organization_id,
            License.is_deleted == False
        ).order_by(License.created_at.desc())
        res = await self.session.execute(stmt)
        return res.scalars().all()

    async def create_license(self, data: dict) -> License:
        return await self.repo.create(data)

    async def update_license(self, license: License, data: dict) -> License:
        return await self.repo.partial_update(license, data)
