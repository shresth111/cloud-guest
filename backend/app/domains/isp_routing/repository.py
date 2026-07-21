"""Data access layer for the ISP Routing domain.

Mirrors ``app.domains.isp.repository``'s shape: a ``Protocol`` describing
every operation the service layer needs (``IspRoutingRepositoryProtocol``),
and a concrete, ``GenericRepository``-backed implementation
(``IspRoutingRepository``).
"""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import DEFAULT_SORT_FIELD, SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PaginationMeta

from .models import IspRoutingRule


class IspRoutingRepositoryProtocol(Protocol):
    async def create_rule(self, **fields: object) -> IspRoutingRule: ...

    async def get_rule_by_id(
        self, rule_id: uuid.UUID, *, include_deleted: bool = False
    ) -> IspRoutingRule | None: ...

    async def update_rule(
        self, rule: IspRoutingRule, data: dict[str, object]
    ) -> IspRoutingRule: ...

    async def soft_delete_rule(self, rule: IspRoutingRule) -> IspRoutingRule: ...

    async def list_rules(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[IspRoutingRule], PaginationMeta]: ...

    async def list_rules_for_router(
        self, router_id: uuid.UUID
    ) -> list[IspRoutingRule]: ...


class IspRoutingRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``IspRoutingRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.rules = GenericRepository(IspRoutingRule, session)

    async def create_rule(self, **fields: object) -> IspRoutingRule:
        return await self.rules.create(fields)

    async def get_rule_by_id(
        self, rule_id: uuid.UUID, *, include_deleted: bool = False
    ) -> IspRoutingRule | None:
        return await self.rules.get_by_id(rule_id, include_deleted=include_deleted)

    async def update_rule(
        self, rule: IspRoutingRule, data: dict[str, object]
    ) -> IspRoutingRule:
        return await self.rules.update(rule, data)

    async def soft_delete_rule(self, rule: IspRoutingRule) -> IspRoutingRule:
        return await self.rules.soft_delete(rule)

    async def list_rules(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[IspRoutingRule], PaginationMeta]:
        filters: dict[str, object] = {}
        if requesting_organization_id is not None:
            filters["organization_id"] = requesting_organization_id
        if router_id is not None:
            filters["router_id"] = router_id
        return await self.rules.paginate(
            page=page,
            page_size=page_size,
            filters=filters or None,
            sort_by=sort_by,
            sort_order=sort_order,
        )

    async def list_rules_for_router(self, router_id: uuid.UUID) -> list[IspRoutingRule]:
        return await self.rules.get_all(
            filters={"router_id": router_id},
            sort_by="priority",
            sort_order=SortOrder.ASC,
        )


__all__ = ["IspRoutingRepositoryProtocol", "IspRoutingRepository"]
