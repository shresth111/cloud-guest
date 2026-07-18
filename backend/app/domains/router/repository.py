"""Data access layer for the Router domain.

Mirrors ``app.domains.location.repository``'s shape: a ``Protocol``
describing the operations the service layer needs
(``RouterRepositoryProtocol``), and a concrete, ``GenericRepository``-backed
implementation (``RouterRepository``). Hand-written queries are used only
where ``GenericRepository``'s equality/IN filters can't express the need
(the combined location + status + search listing query, the same shape
``LocationRepository.list_locations`` uses).

``RouterProvisioningToken`` reads/writes are exposed on the same repository
(``RouterRepository``) rather than a second repository class -- it is a
single small table tightly coupled to the Router aggregate with no
independent lifecycle of its own, the same reasoning RBAC's
``RBACRepository`` uses for e.g. ``role_scopes``/``role_permissions``
living alongside ``roles`` in one repository.
"""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PageParams, PaginationMeta, paginate

from .models import Router, RouterProvisioningToken


class RouterRepositoryProtocol(Protocol):
    async def get_by_id(
        self, router_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Router | None: ...

    async def get_by_serial_number(self, serial_number: str) -> Router | None: ...

    async def get_by_mac_address(self, mac_address: str) -> Router | None: ...

    async def create_router(self, **fields: object) -> Router: ...

    async def update_router(
        self, router: Router, data: dict[str, object]
    ) -> Router: ...

    async def soft_delete_router(self, router: Router) -> Router: ...

    async def list_routers(
        self,
        *,
        location_id: uuid.UUID,
        page: int,
        page_size: int,
        search: str | None = None,
        status: str | None = None,
    ) -> tuple[list[Router], PaginationMeta]: ...

    async def create_provisioning_token(
        self, **fields: object
    ) -> RouterProvisioningToken: ...

    async def get_provisioning_token_by_hash(
        self, token_hash: str
    ) -> RouterProvisioningToken | None: ...

    async def mark_provisioning_token_used(
        self, token: RouterProvisioningToken, *, used_at: object
    ) -> RouterProvisioningToken: ...


class RouterRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``RouterRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.routers = GenericRepository(Router, session)
        self.provisioning_tokens = GenericRepository(RouterProvisioningToken, session)

    # -- routers ---------------------------------------------------------------

    async def get_by_id(
        self, router_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Router | None:
        return await self.routers.get_by_id(router_id, include_deleted=include_deleted)

    async def get_by_serial_number(self, serial_number: str) -> Router | None:
        results = await self.routers.get_all(
            filters={"serial_number": serial_number}, limit=1
        )
        return results[0] if results else None

    async def get_by_mac_address(self, mac_address: str) -> Router | None:
        results = await self.routers.get_all(
            filters={"mac_address": mac_address}, limit=1
        )
        return results[0] if results else None

    async def create_router(self, **fields: object) -> Router:
        return await self.routers.create(fields)

    async def update_router(self, router: Router, data: dict[str, object]) -> Router:
        return await self.routers.update(router, data)

    async def soft_delete_router(self, router: Router) -> Router:
        return await self.routers.soft_delete(router)

    async def list_routers(
        self,
        *,
        location_id: uuid.UUID,
        page: int,
        page_size: int,
        search: str | None = None,
        status: str | None = None,
    ) -> tuple[list[Router], PaginationMeta]:
        params = PageParams(page=page, page_size=page_size)
        conditions = [
            Router.is_deleted.is_(False),
            Router.location_id == location_id,
        ]
        if status is not None:
            conditions.append(Router.status == status)
        if search:
            like = f"%{search}%"
            conditions.append(
                or_(
                    Router.name.ilike(like),
                    Router.serial_number.ilike(like),
                    Router.mac_address.ilike(like),
                )
            )

        count_statement = select(func.count()).select_from(Router).where(*conditions)
        total_result = await self.session.execute(count_statement)
        total_items = int(total_result.scalar_one())

        statement = select(Router).where(*conditions).order_by(Router.created_at.desc())
        result = await self.session.execute(paginate(statement, params))
        rows = list(result.scalars().all())
        return rows, PaginationMeta.from_total(params, total_items)

    # -- provisioning tokens -----------------------------------------------------

    async def create_provisioning_token(
        self, **fields: object
    ) -> RouterProvisioningToken:
        return await self.provisioning_tokens.create(fields)

    async def get_provisioning_token_by_hash(
        self, token_hash: str
    ) -> RouterProvisioningToken | None:
        results = await self.provisioning_tokens.get_all(
            filters={"token_hash": token_hash}, limit=1
        )
        return results[0] if results else None

    async def mark_provisioning_token_used(
        self, token: RouterProvisioningToken, *, used_at: object
    ) -> RouterProvisioningToken:
        return await self.provisioning_tokens.update(token, {"used_at": used_at})
