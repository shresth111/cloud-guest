"""Data access layer for the MAC Authorization domain.

Mirrors ``app.domains.vlan.repository``'s shape: a ``Protocol`` describing
every operation the service layer needs
(``MacAuthorizationRepositoryProtocol``), and a concrete,
``GenericRepository``-backed implementation
(``MacAuthorizationRepository``).
"""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import DEFAULT_SORT_FIELD, SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PaginationMeta

from .models import MacAuthorizationEntry


class MacAuthorizationRepositoryProtocol(Protocol):
    async def create_entry(self, **fields: object) -> MacAuthorizationEntry: ...

    async def get_entry_by_id(
        self, entry_id: uuid.UUID, *, include_deleted: bool = False
    ) -> MacAuthorizationEntry | None: ...

    async def get_entry_by_org_and_mac(
        self, organization_id: uuid.UUID, mac_address: str
    ) -> MacAuthorizationEntry | None: ...

    async def update_entry(
        self, entry: MacAuthorizationEntry, data: dict[str, object]
    ) -> MacAuthorizationEntry: ...

    async def soft_delete_entry(
        self, entry: MacAuthorizationEntry
    ) -> MacAuthorizationEntry: ...

    async def list_entries(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[MacAuthorizationEntry], PaginationMeta]: ...

    async def list_all_for_organization(
        self, organization_id: uuid.UUID
    ) -> list[MacAuthorizationEntry]: ...


class MacAuthorizationRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``MacAuthorizationRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.entries = GenericRepository(MacAuthorizationEntry, session)

    async def create_entry(self, **fields: object) -> MacAuthorizationEntry:
        return await self.entries.create(fields)

    async def get_entry_by_id(
        self, entry_id: uuid.UUID, *, include_deleted: bool = False
    ) -> MacAuthorizationEntry | None:
        return await self.entries.get_by_id(entry_id, include_deleted=include_deleted)

    async def get_entry_by_org_and_mac(
        self, organization_id: uuid.UUID, mac_address: str
    ) -> MacAuthorizationEntry | None:
        results = await self.entries.get_all(
            filters={"organization_id": organization_id, "mac_address": mac_address},
            limit=1,
        )
        return results[0] if results else None

    async def update_entry(
        self, entry: MacAuthorizationEntry, data: dict[str, object]
    ) -> MacAuthorizationEntry:
        return await self.entries.update(entry, data)

    async def soft_delete_entry(
        self, entry: MacAuthorizationEntry
    ) -> MacAuthorizationEntry:
        return await self.entries.soft_delete(entry)

    async def list_entries(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[MacAuthorizationEntry], PaginationMeta]:
        filters: dict[str, object] = {}
        if requesting_organization_id is not None:
            filters["organization_id"] = requesting_organization_id
        if location_id is not None:
            filters["location_id"] = location_id
        return await self.entries.paginate(
            page=page,
            page_size=page_size,
            filters=filters or None,
            sort_by=sort_by,
            sort_order=sort_order,
        )

    async def list_all_for_organization(
        self, organization_id: uuid.UUID
    ) -> list[MacAuthorizationEntry]:
        return await self.entries.get_all(filters={"organization_id": organization_id})


__all__ = ["MacAuthorizationRepositoryProtocol", "MacAuthorizationRepository"]
