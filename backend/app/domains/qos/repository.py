"""Data access layer for the QoS & VOIP Priority domain.

Mirrors ``app.domains.hotspot.repository``'s shape: a ``Protocol``
describing every operation the service layer needs
(``QosRepositoryProtocol``), and a concrete, ``GenericRepository``-backed
implementation (``QosRepository``).
"""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import DEFAULT_SORT_FIELD, SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PaginationMeta

from .models import QosTrafficRule


class QosRepositoryProtocol(Protocol):
    async def create_rule(self, **fields: object) -> QosTrafficRule: ...

    async def get_rule_by_id(
        self, rule_id: uuid.UUID, *, include_deleted: bool = False
    ) -> QosTrafficRule | None: ...

    async def update_rule(
        self, rule: QosTrafficRule, data: dict[str, object]
    ) -> QosTrafficRule: ...

    async def soft_delete_rule(self, rule: QosTrafficRule) -> QosTrafficRule: ...

    async def list_rules(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[QosTrafficRule], PaginationMeta]: ...

    async def list_rules_for_router(
        self, router_id: uuid.UUID
    ) -> list[QosTrafficRule]: ...


class QosRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``QosRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.rules = GenericRepository(QosTrafficRule, session)

    async def create_rule(self, **fields: object) -> QosTrafficRule:
        return await self.rules.create(fields)

    async def get_rule_by_id(
        self, rule_id: uuid.UUID, *, include_deleted: bool = False
    ) -> QosTrafficRule | None:
        return await self.rules.get_by_id(rule_id, include_deleted=include_deleted)

    async def update_rule(
        self, rule: QosTrafficRule, data: dict[str, object]
    ) -> QosTrafficRule:
        return await self.rules.update(rule, data)

    async def soft_delete_rule(self, rule: QosTrafficRule) -> QosTrafficRule:
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
    ) -> tuple[list[QosTrafficRule], PaginationMeta]:
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

    async def list_rules_for_router(self, router_id: uuid.UUID) -> list[QosTrafficRule]:
        """Every non-deleted rule for this router, unpaginated -- the
        real read source ``app.domains.network_config`` composes to
        render a router's full QoS mangle config, mirroring
        ``app.domains.hotspot.repository.HotspotRepository
        .list_profiles_for_router``'s identical shape."""
        return await self.rules.get_all(filters={"router_id": router_id})


__all__ = ["QosRepositoryProtocol", "QosRepository"]
