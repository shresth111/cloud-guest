"""Persistence for login-code providers: ``org_marketing_providers`` rows with
``purpose='otp'``. Every read filters on the organization AND the purpose,
so this domain can never see or change a campaign account."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.auth.models import User
from app.domains.location.models import Location
from app.domains.marketing.models import OrgMarketingProvider
from app.domains.organization.models import Organization

PURPOSE = "otp"


class LoginProviderRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def list_providers(
        self, organization_id: uuid.UUID
    ) -> dict[str, OrgMarketingProvider]:
        result = await self.session.execute(
            select(OrgMarketingProvider).where(
                OrgMarketingProvider.organization_id == organization_id,
                OrgMarketingProvider.purpose == PURPOSE,
                OrgMarketingProvider.is_deleted.is_(False),
            )
        )
        return {row.channel: row for row in result.scalars()}

    async def get_provider(
        self, organization_id: uuid.UUID, channel: str
    ) -> OrgMarketingProvider | None:
        return (await self.list_providers(organization_id)).get(channel)

    async def create_provider(self, **fields: Any) -> OrgMarketingProvider:
        row = OrgMarketingProvider(purpose=PURPOSE, **fields)
        self.session.add(row)
        await self.session.flush()
        await self.session.refresh(row)
        return row

    async def update_provider(
        self, row: OrgMarketingProvider, data: dict[str, Any]
    ) -> OrgMarketingProvider:
        for key, value in data.items():
            setattr(row, key, value)
        row.version = (row.version or 1) + 1
        await self.session.flush()
        return row

    async def soft_delete_provider(self, row: OrgMarketingProvider) -> None:
        row.mark_deleted()
        await self.session.flush()

    async def record_fallback(
        self, provider_id: uuid.UUID, *, at: datetime, error: str
    ) -> None:
        """Atomic increment: concurrent logins falling back do not lose
        counts."""
        await self.session.execute(
            update(OrgMarketingProvider)
            .where(
                OrgMarketingProvider.id == provider_id,
                OrgMarketingProvider.purpose == PURPOSE,
            )
            .values(
                fallback_count=OrgMarketingProvider.fallback_count + 1,
                last_fallback_at=at,
                last_fallback_error=error[:500],
            )
        )

    async def organization_exists(self, organization_id: uuid.UUID) -> bool:
        return await self.session.get(Organization, organization_id) is not None

    async def organization_name(self, organization_id: uuid.UUID) -> str | None:
        org = await self.session.get(Organization, organization_id)
        return getattr(org, "name", None)

    async def location_organization(self, location_id: uuid.UUID) -> uuid.UUID | None:
        result = await self.session.execute(
            select(Location.organization_id).where(
                Location.id == location_id, Location.is_deleted.is_(False)
            )
        )
        return result.scalar_one_or_none()

    async def get_user_names(
        self, user_ids: Sequence[uuid.UUID | None]
    ) -> dict[uuid.UUID, str]:
        ids = [user_id for user_id in set(user_ids) if user_id is not None]
        if not ids:
            return {}
        result = await self.session.execute(
            select(User.id, User.first_name, User.last_name).where(User.id.in_(ids))
        )
        return {
            row.id: " ".join(part for part in (row.first_name, row.last_name) if part)
            for row in result
        }


__all__ = ["PURPOSE", "LoginProviderRepository"]
