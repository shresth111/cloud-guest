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
        location_ids: frozenset[uuid.UUID] | None = None,
        router_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
    ) -> tuple[list[FirewallRule], PaginationMeta]: ...

    async def list_rules_for_router(
        self, router_id: uuid.UUID
    ) -> list[FirewallRule]: ...

    async def list_rule_ids_for_router(
        self, router_id: uuid.UUID
    ) -> list[uuid.UUID]: ...

    async def commit(self) -> None: ...


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
        location_ids: frozenset[uuid.UUID] | None = None,
        router_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
    ) -> tuple[list[FirewallRule], PaginationMeta]:
        filters: dict[str, object] = {}
        if requesting_organization_id is not None:
            filters["organization_id"] = requesting_organization_id
        if router_id is not None:
            filters["router_id"] = router_id
        # `None` means unconstrained; a set becomes an IN clause
        # (`app.database.utils.filters.apply_filters`). An *empty* set is
        # meaningful and must not be dropped -- it means "confined to no
        # locations", which matches nothing.
        if location_ids is not None:
            filters["location_id"] = set(location_ids) or {None}
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

    async def list_rule_ids_for_router(self, router_id: uuid.UUID) -> list[uuid.UUID]:
        """Every rule id this platform has ever held for the router,
        soft-deleted included.

        The device push uses it to tell "a rule of ours the customer deleted
        or disabled" (remove it) from "a marker nothing here ever wrote"
        (refuse the whole push and say so). Without deleted rows here, every
        deletion would read as an orphan and block the next push."""
        rows = await self.rules.get_all(
            filters={"router_id": router_id}, include_deleted=True
        )
        return [row.id for row in rows]

    async def commit(self) -> None:
        """Commits the current transaction. Needed by the device push only:
        ``GenericRepository.update`` flushes, and ``get_db_session`` rolls
        back on any exception, so a failure record written just before a
        re-raise would otherwise be discarded -- see
        ``ContentFilterRepository.commit`` for the same reasoning."""
        await self.session.commit()


__all__ = ["FirewallRepositoryProtocol", "FirewallRepository"]
