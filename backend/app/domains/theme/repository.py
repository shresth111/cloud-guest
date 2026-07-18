"""Repository layer for the Theme domain."""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories.generic import GenericRepository
from .models import Theme


class ThemeRepositoryProtocol(Protocol):
    async def get_by_branding_id(self, branding_id: uuid.UUID) -> Theme | None: ...
    async def create_theme(self, data: dict) -> Theme: ...
    async def update_theme(self, theme: Theme, data: dict) -> Theme: ...


class ThemeRepository(ThemeRepositoryProtocol):
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.repo = GenericRepository(Theme, session)

    async def get_by_branding_id(self, branding_id: uuid.UUID) -> Theme | None:
        stmt = select(Theme).where(
            Theme.branding_id == branding_id,
            Theme.is_deleted == False
        )
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def create_theme(self, data: dict) -> Theme:
        return await self.repo.create(data)

    async def update_theme(self, theme: Theme, data: dict) -> Theme:
        return await self.repo.partial_update(theme, data)
