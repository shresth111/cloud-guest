"""Data access layer for the Firewall Rule Management domain.

Mirrors ``app.domains.dhcp.repository``'s shape exactly: a ``Protocol``
describing every operation the service layer needs
(``FirewallRepositoryProtocol``), and a concrete, ``GenericRepository``-
backed implementation (``FirewallRepository``).
"""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PaginationMeta

from .models import FirewallRule


class FirewallRepositoryProtocol(Protocol):
    async def create_rule(self, **fields: object) -> FirewallRule: ...

    async def get_rule_by_id(
        self, rule_id: uuid.UUID, *, include_deleted: bool = False
    ) -> FirewallRule | None: ...

    async def update_rule(
        self, rule: FirewallRule, data: dict[str, object]
    ) -> FirewallRule: ...

    async def soft_delete_rule(self, rule: FirewallRule) -> FirewallRule: ...

    async def list_rules(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
    ) -> tuple[list[FirewallRule], PaginationMeta]: ...

    async def list_rules_for_router(
        self, router_id: uuid.UUID
    ) -> list[FirewallRule]: ...


class FirewallRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``FirewallRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.rules = GenericRepository(FirewallRule, session)

    async def create_rule(self, **fields: object) -> FirewallRule:
        return await self.rules.create(fields)

    async def get_rule_by_id(
        self, rule_id: uuid.UUID, *, include_deleted: bool = False
    ) -> FirewallRule | None:
        return await self.rules.get_by_id(rule_id, include_deleted=include_deleted)

    async def update_rule(
        self, rule: FirewallRule, data: dict[str, object]
    ) -> FirewallRule:
        return await self.rules.update(rule, data)

    async def soft_delete_rule(self, rule: FirewallRule) -> FirewallRule:
        return await self.rules.soft_delete(rule)

    async def list_rules(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
    ) -> tuple[list[FirewallRule], PaginationMeta]:
        filters: dict[str, object] = {}
        if requesting_organization_id is not None:
            filters["organization_id"] = requesting_organization_id
        if router_id is not None:
            filters["router_id"] = router_id
        return await self.rules.paginate(
            page=page,
            page_size=page_size,
            filters=filters or None,
            sort_by="priority",
            sort_order=SortOrder.ASC,
        )

    async def list_rules_for_router(self, router_id: uuid.UUID) -> list[FirewallRule]:
        return await self.rules.get_all(
            filters={"router_id": router_id},
            sort_by="priority",
            sort_order=SortOrder.ASC,
        )


__all__ = ["FirewallRepositoryProtocol", "FirewallRepository"]
