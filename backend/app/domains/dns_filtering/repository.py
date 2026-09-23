"""Data access for DNS filtering. A Protocol naming what the service needs,
and a ``GenericRepository``-backed implementation.

No read here touches the ``routers`` table: the router is always resolved
through ``RouterService`` (org-scoped) by the service layer, so this module
never needs a vendor classification in ``test_router_read_vendor_coverage``.
"""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories.generic import GenericRepository

from .constants import RULE_PRECEDENCE_BASE, RouterFilteringState
from .models import DnsFilteringPolicy, DnsFilteringProfile, DnsFilteringRouterLocation


class DnsFilteringRepositoryProtocol(Protocol):
    # profiles
    async def get_profile(
        self, profile_id: uuid.UUID
    ) -> DnsFilteringProfile | None: ...
    async def get_profile_by_fingerprint(
        self, fingerprint: str
    ) -> DnsFilteringProfile | None: ...
    async def create_profile(self, **fields: object) -> DnsFilteringProfile: ...
    async def next_rule_precedence(self) -> int: ...
    async def lock_profile(
        self, profile_id: uuid.UUID
    ) -> DnsFilteringProfile | None: ...
    async def update_profile(
        self, profile: DnsFilteringProfile, data: dict[str, object]
    ) -> DnsFilteringProfile: ...
    async def count_profiles_with_rule(self) -> int: ...

    # policies
    async def get_policy(
        self, organization_id: uuid.UUID, location_id: uuid.UUID | None
    ) -> DnsFilteringPolicy | None: ...
    async def create_policy(self, **fields: object) -> DnsFilteringPolicy: ...
    async def update_policy(
        self, policy: DnsFilteringPolicy, data: dict[str, object]
    ) -> DnsFilteringPolicy: ...

    # router locations
    async def get_router_location(
        self, router_id: uuid.UUID
    ) -> DnsFilteringRouterLocation | None: ...
    async def create_router_location(
        self, **fields: object
    ) -> DnsFilteringRouterLocation: ...
    async def update_router_location(
        self, row: DnsFilteringRouterLocation, data: dict[str, object]
    ) -> DnsFilteringRouterLocation: ...
    async def count_cloudflare_locations(self) -> int: ...
    async def list_profile_members(
        self, profile_id: uuid.UUID
    ) -> list[DnsFilteringRouterLocation]: ...
    async def list_enabled_in_scope(
        self, organization_id: uuid.UUID, location_id: uuid.UUID | None
    ) -> list[DnsFilteringRouterLocation]: ...

    async def commit(self) -> None: ...


class DnsFilteringRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.profiles = GenericRepository(DnsFilteringProfile, session)
        self.policies = GenericRepository(DnsFilteringPolicy, session)
        self.router_locations = GenericRepository(DnsFilteringRouterLocation, session)

    # -- profiles ------------------------------------------------------------

    async def get_profile(self, profile_id: uuid.UUID) -> DnsFilteringProfile | None:
        return await self.profiles.get_by_id(profile_id)

    async def get_profile_by_fingerprint(
        self, fingerprint: str
    ) -> DnsFilteringProfile | None:
        rows = await self.profiles.get_all(
            filters={"fingerprint": fingerprint}, limit=1
        )
        return rows[0] if rows else None

    async def create_profile(self, **fields: object) -> DnsFilteringProfile:
        return await self.profiles.create(fields)

    async def next_rule_precedence(self) -> int:
        # Includes soft-deleted rows: the column's unique index does too.
        result = await self.session.execute(
            select(func.max(DnsFilteringProfile.rule_precedence))
        )
        current = result.scalar_one_or_none()
        return RULE_PRECEDENCE_BASE if current is None else int(current) + 1

    async def lock_profile(self, profile_id: uuid.UUID) -> DnsFilteringProfile | None:
        """``SELECT ... FOR UPDATE``: two venues changing membership of the
        same shared rule at once must not each PUT a location set computed
        without the other's change."""
        result = await self.session.execute(
            select(DnsFilteringProfile)
            .where(DnsFilteringProfile.id == profile_id)
            .with_for_update()
        )
        return result.scalar_one_or_none()

    async def update_profile(
        self, profile: DnsFilteringProfile, data: dict[str, object]
    ) -> DnsFilteringProfile:
        return await self.profiles.update(profile, data)

    async def count_profiles_with_rule(self) -> int:
        result = await self.session.execute(
            select(func.count())
            .select_from(DnsFilteringProfile)
            .where(
                DnsFilteringProfile.is_deleted.is_(False),
                DnsFilteringProfile.cf_rule_id.is_not(None),
            )
        )
        return int(result.scalar_one())

    # -- policies ------------------------------------------------------------

    async def get_policy(
        self, organization_id: uuid.UUID, location_id: uuid.UUID | None
    ) -> DnsFilteringPolicy | None:
        statement = select(DnsFilteringPolicy).where(
            DnsFilteringPolicy.is_deleted.is_(False),
            DnsFilteringPolicy.organization_id == organization_id,
            DnsFilteringPolicy.location_id.is_(None)
            if location_id is None
            else DnsFilteringPolicy.location_id == location_id,
        )
        result = await self.session.execute(statement.limit(1))
        return result.scalar_one_or_none()

    async def create_policy(self, **fields: object) -> DnsFilteringPolicy:
        return await self.policies.create(fields)

    async def update_policy(
        self, policy: DnsFilteringPolicy, data: dict[str, object]
    ) -> DnsFilteringPolicy:
        return await self.policies.update(policy, data)

    # -- router locations ----------------------------------------------------

    async def get_router_location(
        self, router_id: uuid.UUID
    ) -> DnsFilteringRouterLocation | None:
        rows = await self.router_locations.get_all(
            filters={"router_id": router_id}, limit=1
        )
        return rows[0] if rows else None

    async def create_router_location(
        self, **fields: object
    ) -> DnsFilteringRouterLocation:
        return await self.router_locations.create(fields)

    async def update_router_location(
        self, row: DnsFilteringRouterLocation, data: dict[str, object]
    ) -> DnsFilteringRouterLocation:
        return await self.router_locations.update(row, data)

    async def count_cloudflare_locations(self) -> int:
        """Every Gateway location this platform holds, across all tenants --
        the number Cloudflare's 250-per-account ceiling is measured against."""
        result = await self.session.execute(
            select(func.count())
            .select_from(DnsFilteringRouterLocation)
            .where(
                DnsFilteringRouterLocation.is_deleted.is_(False),
                DnsFilteringRouterLocation.cf_location_id.is_not(None),
            )
        )
        return int(result.scalar_one())

    async def list_profile_members(
        self, profile_id: uuid.UUID
    ) -> list[DnsFilteringRouterLocation]:
        result = await self.session.execute(
            select(DnsFilteringRouterLocation).where(
                DnsFilteringRouterLocation.is_deleted.is_(False),
                DnsFilteringRouterLocation.applied_profile_id == profile_id,
                DnsFilteringRouterLocation.cf_location_id.is_not(None),
            )
        )
        return list(result.scalars().all())

    async def list_enabled_in_scope(
        self, organization_id: uuid.UUID, location_id: uuid.UUID | None
    ) -> list[DnsFilteringRouterLocation]:
        statement = select(DnsFilteringRouterLocation).where(
            DnsFilteringRouterLocation.is_deleted.is_(False),
            DnsFilteringRouterLocation.organization_id == organization_id,
            DnsFilteringRouterLocation.state != RouterFilteringState.DISABLED.value,
        )
        if location_id is not None:
            statement = statement.where(
                DnsFilteringRouterLocation.location_id == location_id
            )
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    async def commit(self) -> None:
        await self.session.commit()


__all__ = ["DnsFilteringRepository", "DnsFilteringRepositoryProtocol"]
