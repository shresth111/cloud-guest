"""Data access layer for the Location domain.

Mirrors ``app.domains.organization.repository``'s shape: a ``Protocol``
describing the operations the service layer needs
(``LocationRepositoryProtocol``), and a concrete, ``GenericRepository``
-backed implementation (``LocationRepository``). Hand-written queries are
used only where ``GenericRepository``'s equality/IN filters can't express
the need (the combined organization + status + search listing query, the
same shape ``OrganizationRepository.list_organizations`` uses).
"""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy import func, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PageParams, PaginationMeta, paginate

from .models import Location, LocationCodeCounter


class LocationRepositoryProtocol(Protocol):
    async def get_by_id(
        self, location_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Location | None: ...

    async def get_by_slug(
        self, organization_id: uuid.UUID, slug: str
    ) -> Location | None: ...

    async def create_location(self, **fields: object) -> Location: ...

    async def update_location(
        self, location: Location, data: dict[str, object]
    ) -> Location: ...

    async def soft_delete_location(self, location: Location) -> Location: ...

    async def list_locations(
        self,
        *,
        organization_id: uuid.UUID,
        page: int,
        page_size: int,
        search: str | None = None,
        status: str | None = None,
    ) -> tuple[list[Location], PaginationMeta]: ...


class LocationRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``LocationRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.locations = GenericRepository(Location, session)

    async def get_by_id(
        self, location_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Location | None:
        return await self.locations.get_by_id(
            location_id, include_deleted=include_deleted
        )

    async def get_by_slug(
        self, organization_id: uuid.UUID, slug: str
    ) -> Location | None:
        results = await self.locations.get_all(
            filters={"organization_id": organization_id, "slug": slug}, limit=1
        )
        return results[0] if results else None

    async def create_location(self, **fields: object) -> Location:
        return await self.locations.create(fields)

    async def update_location(
        self, location: Location, data: dict[str, object]
    ) -> Location:
        return await self.locations.update(location, data)

    async def soft_delete_location(self, location: Location) -> Location:
        return await self.locations.soft_delete(location)

    async def list_locations(
        self,
        *,
        organization_id: uuid.UUID,
        page: int,
        page_size: int,
        search: str | None = None,
        status: str | None = None,
    ) -> tuple[list[Location], PaginationMeta]:
        params = PageParams(page=page, page_size=page_size)
        conditions = [
            Location.is_deleted.is_(False),
            Location.organization_id == organization_id,
        ]
        if status is not None:
            conditions.append(Location.status == status)
        if search:
            like = f"%{search}%"
            conditions.append(
                or_(
                    Location.name.ilike(like),
                    Location.slug.ilike(like),
                    Location.city.ilike(like),
                )
            )

        count_statement = select(func.count()).select_from(Location).where(*conditions)
        total_result = await self.session.execute(count_statement)
        total_items = int(total_result.scalar_one())

        statement = (
            select(Location).where(*conditions).order_by(Location.created_at.desc())
        )
        result = await self.session.execute(paginate(statement, params))
        rows = list(result.scalars().all())
        return rows, PaginationMeta.from_total(params, total_items)


class LocationCodeCounterRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``number_generator.LocationCodeCounterRepositoryProtocol`` -- mirrors
    ``app.domains.billing.repository.NumberCounterRepository`` exactly (see
    ``number_generator.py``'s module docstring for the full concurrency-
    safety write-up)."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def increment_and_get_next(self, counter_key: str) -> int:
        statement = (
            pg_insert(LocationCodeCounter)
            .values(counter_key=counter_key, last_value=1)
            .on_conflict_do_update(
                index_elements=[LocationCodeCounter.counter_key],
                set_={
                    "last_value": LocationCodeCounter.last_value + 1,
                    "version": LocationCodeCounter.version + 1,
                },
            )
            .returning(LocationCodeCounter.last_value)
        )
        result = await self.session.execute(statement)
        await self.session.flush()
        return int(result.scalar_one())
