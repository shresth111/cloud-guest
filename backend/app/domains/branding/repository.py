"""Branding repository: protocol + async SQLAlchemy implementation."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories.generic import GenericRepository

from .models import Branding


class BrandingRepositoryProtocol(Protocol):
    """Minimal surface the service needs from the repo."""

    async def get_by_organization(
        self, organization_id: uuid.UUID
    ) -> Branding | None: ...

    async def upsert(
        self,
        organization_id: uuid.UUID,
        data: dict,
        *,
        actor_user_id: uuid.UUID | None = None,
    ) -> Branding: ...


class BrandingRepository(BrandingRepositoryProtocol):
    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.generic = GenericRepository[Branding](db, Branding)

    async def get_by_organization(
        self, organization_id: uuid.UUID
    ) -> Branding | None:
        stmt = select(Branding).where(
            Branding.organization_id == organization_id,
            Branding.is_deleted == False,
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def upsert(
        self,
        organization_id: uuid.UUID,
        data: dict,
        *,
        actor_user_id: uuid.UUID | None = None,
    ) -> Branding:
        existing = await self.get_by_organization(organization_id)
        if existing:
            for key, value in data.items():
                if value is not None:
                    setattr(existing, key, value)
            existing.updated_by = actor_user_id
            await self.db.flush()
            return existing

        branding = Branding(
            organization_id=organization_id,
            company_name=data.get("company_name"),
            logo_url=data.get("logo_url"),
            favicon_url=data.get("favicon_url"),
            primary_color=data.get("primary_color"),
            secondary_color=data.get("secondary_color"),
            accent_color=data.get("accent_color"),
            theme=data.get("theme", "light"),
            created_by=actor_user_id,
            updated_by=actor_user_id,
        )
        self.db.add(branding)
        await self.db.flush()
        return branding
