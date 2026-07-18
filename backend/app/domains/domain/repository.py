"""Repository layer for the Custom Domains domain."""

from __future__ import annotations

import uuid
from typing import Protocol, Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories.generic import GenericRepository
from .models import CustomDomain


class CustomDomainRepositoryProtocol(Protocol):
    async def get_by_id(self, domain_id: uuid.UUID) -> CustomDomain | None: ...
    async def get_by_name(self, domain_name: str) -> CustomDomain | None: ...
    async def list_by_organization(self, organization_id: uuid.UUID) -> Sequence[CustomDomain]: ...
    async def create_domain(self, data: dict) -> CustomDomain: ...
    async def update_domain(self, domain: CustomDomain, data: dict) -> CustomDomain: ...


class CustomDomainRepository(CustomDomainRepositoryProtocol):
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.repo = GenericRepository(CustomDomain, session)

    async def get_by_id(self, domain_id: uuid.UUID) -> CustomDomain | None:
        stmt = select(CustomDomain).where(
            CustomDomain.id == domain_id,
            CustomDomain.is_deleted == False
        )
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def get_by_name(self, domain_name: str) -> CustomDomain | None:
        stmt = select(CustomDomain).where(
            CustomDomain.domain_name == domain_name,
            CustomDomain.is_deleted == False
        )
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def list_by_organization(self, organization_id: uuid.UUID) -> Sequence[CustomDomain]:
        stmt = select(CustomDomain).where(
            CustomDomain.organization_id == organization_id,
            CustomDomain.is_deleted == False
        ).order_by(CustomDomain.created_at.desc())
        res = await self.session.execute(stmt)
        return res.scalars().all()

    async def create_domain(self, data: dict) -> CustomDomain:
        return await self.repo.create(data)

    async def update_domain(self, domain: CustomDomain, data: dict) -> CustomDomain:
        return await self.repo.partial_update(domain, data)
