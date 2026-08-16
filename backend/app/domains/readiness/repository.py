"""Data access layer for the Router Readiness Checklist domain.

Mirrors ``app.domains.content_filtering.repository``'s shape: a
``Protocol`` describing every operation the service layer needs
(``ReadinessRepositoryProtocol``), and a concrete, ``GenericRepository``
-backed implementation (``ReadinessRepository``). ``upsert_item`` composes
plain ``get_all``/``create``/``update`` calls rather than a native SQL
``ON CONFLICT`` -- the same "no upsert primitive on ``GenericRepository``,
compose it in the domain that needs it" posture every other domain with a
unique-pair row (e.g. ``app.domains.router_agent.service
.issue_credential_for_router``'s own get-then-create-or-rotate shape)
already takes.
"""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories.generic import GenericRepository

from .models import RouterChecklistItem


class ReadinessRepositoryProtocol(Protocol):
    async def get_all_for_router(
        self, router_id: uuid.UUID
    ) -> list[RouterChecklistItem]: ...

    async def get_item(
        self, router_id: uuid.UUID, item_key: str
    ) -> RouterChecklistItem | None: ...

    async def upsert_item(
        self, router_id: uuid.UUID, item_key: str, data: dict[str, object]
    ) -> RouterChecklistItem: ...


class ReadinessRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``ReadinessRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.items = GenericRepository(RouterChecklistItem, session)

    async def get_all_for_router(
        self, router_id: uuid.UUID
    ) -> list[RouterChecklistItem]:
        return await self.items.get_all(filters={"router_id": router_id})

    async def get_item(
        self, router_id: uuid.UUID, item_key: str
    ) -> RouterChecklistItem | None:
        results = await self.items.get_all(
            filters={"router_id": router_id, "item_key": item_key}, limit=1
        )
        return results[0] if results else None

    async def upsert_item(
        self, router_id: uuid.UUID, item_key: str, data: dict[str, object]
    ) -> RouterChecklistItem:
        existing = await self.get_item(router_id, item_key)
        if existing is None:
            return await self.items.create(
                {"router_id": router_id, "item_key": item_key, **data}
            )
        return await self.items.update(existing, data)


__all__ = ["ReadinessRepositoryProtocol", "ReadinessRepository"]
