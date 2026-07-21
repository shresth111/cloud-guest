"""Data access layer for the Port Forwarding Management domain.

Mirrors ``app.domains.dhcp.repository``'s shape: a ``Protocol`` describing
every operation the service layer needs
(``PortForwardingRepositoryProtocol``), and a concrete,
``GenericRepository``-backed implementation
(``PortForwardingRepository``).
"""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import DEFAULT_SORT_FIELD, SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PaginationMeta

from .models import PortForwardingRule


class PortForwardingRepositoryProtocol(Protocol):
    async def create_rule(self, **fields: object) -> PortForwardingRule: ...

    async def get_rule_by_id(
        self, rule_id: uuid.UUID, *, include_deleted: bool = False
    ) -> PortForwardingRule | None: ...

    async def update_rule(
        self, rule: PortForwardingRule, data: dict[str, object]
    ) -> PortForwardingRule: ...

    async def soft_delete_rule(
        self, rule: PortForwardingRule
    ) -> PortForwardingRule: ...

    async def list_rules(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[PortForwardingRule], PaginationMeta]: ...

    async def list_rules_for_router(
        self, router_id: uuid.UUID
    ) -> list[PortForwardingRule]: ...


class PortForwardingRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``PortForwardingRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.rules = GenericRepository(PortForwardingRule, session)

    async def create_rule(self, **fields: object) -> PortForwardingRule:
        return await self.rules.create(fields)

    async def get_rule_by_id(
        self, rule_id: uuid.UUID, *, include_deleted: bool = False
    ) -> PortForwardingRule | None:
        return await self.rules.get_by_id(rule_id, include_deleted=include_deleted)

    async def update_rule(
        self, rule: PortForwardingRule, data: dict[str, object]
    ) -> PortForwardingRule:
        return await self.rules.update(rule, data)

    async def soft_delete_rule(self, rule: PortForwardingRule) -> PortForwardingRule:
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
    ) -> tuple[list[PortForwardingRule], PaginationMeta]:
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

    async def list_rules_for_router(
        self, router_id: uuid.UUID
    ) -> list[PortForwardingRule]:
        return await self.rules.get_all(filters={"router_id": router_id})


__all__ = ["PortForwardingRepositoryProtocol", "PortForwardingRepository"]
