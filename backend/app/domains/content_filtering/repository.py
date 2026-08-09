"""Data access layer for the Content Filtering domain.

Mirrors ``app.domains.firewall.repository``'s shape: a ``Protocol``
describing every operation the service layer needs
(``ContentFilterRepositoryProtocol``), and a concrete,
``GenericRepository``-backed implementation (``ContentFilterRepository``).
"""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import DEFAULT_SORT_FIELD, SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PaginationMeta

from .models import ContentFilterRule


class ContentFilterRepositoryProtocol(Protocol):
    async def create_rule(self, **fields: object) -> ContentFilterRule: ...

    async def get_rule_by_id(
        self, rule_id: uuid.UUID, *, include_deleted: bool = False
    ) -> ContentFilterRule | None: ...

    async def get_rule_by_router_and_value(
        self, router_id: uuid.UUID, value_type: str, value: str
    ) -> ContentFilterRule | None: ...

    async def update_rule(
        self, rule: ContentFilterRule, data: dict[str, object]
    ) -> ContentFilterRule: ...

    async def soft_delete_rule(self, rule: ContentFilterRule) -> ContentFilterRule: ...

    async def list_rules(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
    ) -> tuple[list[ContentFilterRule], PaginationMeta]: ...

    async def list_rules_for_router(
        self, router_id: uuid.UUID
    ) -> list[ContentFilterRule]: ...


class ContentFilterRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``ContentFilterRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.rules = GenericRepository(ContentFilterRule, session)

    async def create_rule(self, **fields: object) -> ContentFilterRule:
        return await self.rules.create(fields)

    async def get_rule_by_id(
        self, rule_id: uuid.UUID, *, include_deleted: bool = False
    ) -> ContentFilterRule | None:
        return await self.rules.get_by_id(rule_id, include_deleted=include_deleted)

    async def get_rule_by_router_and_value(
        self, router_id: uuid.UUID, value_type: str, value: str
    ) -> ContentFilterRule | None:
        results = await self.rules.get_all(
            filters={"router_id": router_id, "value_type": value_type, "value": value},
            limit=1,
        )
        return results[0] if results else None

    async def update_rule(
        self, rule: ContentFilterRule, data: dict[str, object]
    ) -> ContentFilterRule:
        return await self.rules.update(rule, data)

    async def soft_delete_rule(self, rule: ContentFilterRule) -> ContentFilterRule:
        return await self.rules.soft_delete(rule)

    async def list_rules(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
    ) -> tuple[list[ContentFilterRule], PaginationMeta]:
        filters: dict[str, object] = {}
        if requesting_organization_id is not None:
            filters["organization_id"] = requesting_organization_id
        if router_id is not None:
            filters["router_id"] = router_id
        return await self.rules.paginate(
            page=page,
            page_size=page_size,
            filters=filters or None,
            sort_by=DEFAULT_SORT_FIELD,
            sort_order=SortOrder.DESC,
        )

    async def list_rules_for_router(
        self, router_id: uuid.UUID
    ) -> list[ContentFilterRule]:
        return await self.rules.get_all(filters={"router_id": router_id})


__all__ = ["ContentFilterRepositoryProtocol", "ContentFilterRepository"]
