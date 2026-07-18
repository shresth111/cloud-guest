"""Data access layer for the Router Agent domain.

Mirrors ``app.domains.router.repository``'s shape: a ``Protocol`` describing
the operations the service layer needs (``RouterAgentRepositoryProtocol``),
and a concrete, ``GenericRepository``-backed implementation
(``RouterAgentRepository``) for the module's single table.

This module deliberately does **not** define its own repository for reading
``Router`` rows, ``ConfigVersion`` rows, or ``ProvisioningJob`` rows -- those
are composed from BE-008 (``app.domains.router``) and Module 009 Part 1
(``app.domains.router_provisioning``) through narrow protocols defined in
``service.py``, never re-queried directly here. See ``service.py``'s module
docstring for the full cross-domain composition map.
"""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories.generic import GenericRepository

from .models import RouterAgentCredential


class RouterAgentRepositoryProtocol(Protocol):
    async def get_by_router_id(
        self, router_id: uuid.UUID
    ) -> RouterAgentCredential | None: ...

    async def get_by_credential_hash(
        self, credential_hash: str
    ) -> RouterAgentCredential | None: ...

    async def create_credential(self, **fields: object) -> RouterAgentCredential: ...

    async def update_credential(
        self, credential: RouterAgentCredential, data: dict[str, object]
    ) -> RouterAgentCredential: ...


class RouterAgentRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``RouterAgentRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.credentials = GenericRepository(RouterAgentCredential, session)

    async def get_by_router_id(
        self, router_id: uuid.UUID
    ) -> RouterAgentCredential | None:
        results = await self.credentials.get_all(
            filters={"router_id": router_id}, limit=1
        )
        return results[0] if results else None

    async def get_by_credential_hash(
        self, credential_hash: str
    ) -> RouterAgentCredential | None:
        results = await self.credentials.get_all(
            filters={"credential_hash": credential_hash}, limit=1
        )
        return results[0] if results else None

    async def create_credential(self, **fields: object) -> RouterAgentCredential:
        return await self.credentials.create(fields)

    async def update_credential(
        self, credential: RouterAgentCredential, data: dict[str, object]
    ) -> RouterAgentCredential:
        return await self.credentials.update(credential, data)


__all__ = ["RouterAgentRepositoryProtocol", "RouterAgentRepository"]
