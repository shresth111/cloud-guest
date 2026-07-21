"""Data access layer for the DNS Management domain.

Mirrors ``app.domains.dhcp.repository``'s shape exactly: a ``Protocol``
describing every operation the service layer needs
(``DnsRepositoryProtocol``), and a concrete, ``GenericRepository``-backed
implementation (``DnsRepository``).
"""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import DEFAULT_SORT_FIELD, SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PaginationMeta

from .models import DnsRecord


class DnsRepositoryProtocol(Protocol):
    async def create_record(self, **fields: object) -> DnsRecord: ...

    async def get_record_by_id(
        self, record_id: uuid.UUID, *, include_deleted: bool = False
    ) -> DnsRecord | None: ...

    async def update_record(
        self, record: DnsRecord, data: dict[str, object]
    ) -> DnsRecord: ...

    async def soft_delete_record(self, record: DnsRecord) -> DnsRecord: ...

    async def list_records(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[DnsRecord], PaginationMeta]: ...

    async def list_records_for_router(
        self, router_id: uuid.UUID
    ) -> list[DnsRecord]: ...


class DnsRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``DnsRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.records = GenericRepository(DnsRecord, session)

    async def create_record(self, **fields: object) -> DnsRecord:
        return await self.records.create(fields)

    async def get_record_by_id(
        self, record_id: uuid.UUID, *, include_deleted: bool = False
    ) -> DnsRecord | None:
        return await self.records.get_by_id(record_id, include_deleted=include_deleted)

    async def update_record(
        self, record: DnsRecord, data: dict[str, object]
    ) -> DnsRecord:
        return await self.records.update(record, data)

    async def soft_delete_record(self, record: DnsRecord) -> DnsRecord:
        return await self.records.soft_delete(record)

    async def list_records(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[DnsRecord], PaginationMeta]:
        filters: dict[str, object] = {}
        if requesting_organization_id is not None:
            filters["organization_id"] = requesting_organization_id
        if router_id is not None:
            filters["router_id"] = router_id
        return await self.records.paginate(
            page=page,
            page_size=page_size,
            filters=filters or None,
            sort_by=sort_by,
            sort_order=sort_order,
        )

    async def list_records_for_router(self, router_id: uuid.UUID) -> list[DnsRecord]:
        return await self.records.get_all(filters={"router_id": router_id})


__all__ = ["DnsRepositoryProtocol", "DnsRepository"]
