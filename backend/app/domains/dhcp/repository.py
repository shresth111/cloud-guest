"""Data access layer for the DHCP Pool Management domain.

Mirrors ``app.domains.vlan.repository``'s shape: a ``Protocol`` describing
every operation the service layer needs (``DhcpRepositoryProtocol``), and
a concrete, ``GenericRepository``-backed implementation
(``DhcpRepository``).
"""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import DEFAULT_SORT_FIELD, SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PaginationMeta

from .models import DhcpPool, RouterRogueDhcpStatus


class DhcpRepositoryProtocol(Protocol):
    async def create_pool(self, **fields: object) -> DhcpPool: ...

    async def get_pool_by_id(
        self, pool_id: uuid.UUID, *, include_deleted: bool = False
    ) -> DhcpPool | None: ...

    async def update_pool(
        self, pool: DhcpPool, data: dict[str, object]
    ) -> DhcpPool: ...

    async def soft_delete_pool(self, pool: DhcpPool) -> DhcpPool: ...

    async def commit(self) -> None: ...

    async def list_pools(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[DhcpPool], PaginationMeta]: ...

    async def list_pools_for_router(self, router_id: uuid.UUID) -> list[DhcpPool]: ...

    # ------------------------------------------------------------------
    # Rogue-DHCP detection state -- written by ``tasks.py``'s sweep, read
    # by the readiness checklist. See ``models.RouterRogueDhcpStatus``.
    # ------------------------------------------------------------------

    async def list_router_ids_serving_dhcp(self) -> list[uuid.UUID]: ...

    async def list_rogue_dhcp_statuses(
        self, router_id: uuid.UUID
    ) -> list[RouterRogueDhcpStatus]: ...

    async def upsert_rogue_dhcp_status(
        self, router_id: uuid.UUID, interface: str, data: dict[str, object]
    ) -> RouterRogueDhcpStatus: ...

    async def delete_rogue_dhcp_statuses(
        self, router_id: uuid.UUID, interfaces: set[str]
    ) -> int: ...


class DhcpRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``DhcpRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.pools = GenericRepository(DhcpPool, session)
        self.rogue_statuses = GenericRepository(RouterRogueDhcpStatus, session)

    async def create_pool(self, **fields: object) -> DhcpPool:
        return await self.pools.create(fields)

    async def get_pool_by_id(
        self, pool_id: uuid.UUID, *, include_deleted: bool = False
    ) -> DhcpPool | None:
        return await self.pools.get_by_id(pool_id, include_deleted=include_deleted)

    async def update_pool(self, pool: DhcpPool, data: dict[str, object]) -> DhcpPool:
        return await self.pools.update(pool, data)

    async def commit(self) -> None:
        """Commits the current transaction.

        Needed by ``DhcpService.push_pool_to_device`` and nothing else.
        ``GenericRepository.update`` only ``flush()``es, and
        ``get_db_session`` rolls the session back on any exception -- so a
        failure record written just before a re-raise is discarded, and the
        row still reads ``pending`` after a real device failure with
        ``device_push_error`` NULL. Committing explicitly before raising is
        what makes the record survive to be read.
        """
        await self.session.commit()

    async def soft_delete_pool(self, pool: DhcpPool) -> DhcpPool:
        return await self.pools.soft_delete(pool)

    async def list_pools(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[DhcpPool], PaginationMeta]:
        filters: dict[str, object] = {}
        if requesting_organization_id is not None:
            filters["organization_id"] = requesting_organization_id
        if router_id is not None:
            filters["router_id"] = router_id
        return await self.pools.paginate(
            page=page,
            page_size=page_size,
            filters=filters or None,
            sort_by=sort_by,
            sort_order=sort_order,
        )

    async def list_pools_for_router(self, router_id: uuid.UUID) -> list[DhcpPool]:
        """Every non-deleted pool for this router, regardless of
        ``interface`` -- ``GenericRepository``'s own equality-filter
        support silently skips ``None``-valued filters (would never
        express ``interface IS NULL``), so the "same interface, including
        NULL == NULL" grouping conflict detection needs is done in Python
        by the caller (``service.py``'s own ``_check_range_conflict``),
        not pushed down into this query."""
        return await self.pools.get_all(filters={"router_id": router_id})

    # ------------------------------------------------------------------
    # Rogue-DHCP detection state
    # ------------------------------------------------------------------

    async def list_router_ids_serving_dhcp(self) -> list[uuid.UUID]:
        """Every router this platform believes is handing out addresses --
        the set the detection sweep fans out over.

        Scoped to *enabled* pools deliberately. A disabled pool hands out
        nothing, so there is no server of ours on that segment to compare an
        unknown offer against, and RouterOS's own alert would have no
        baseline either (see ``mikrotik_adapter._dhcp_serving_interfaces``,
        which excludes disabled servers for the identical reason). Polling
        those routers would spend a real device round trip to learn nothing.

        Distinct rather than one row per pool: a router with six pools is
        still one API read, because ``read_rogue_dhcp_alerts`` answers for
        every interface in a single pass.
        """
        rows = await self.pools.get_all(filters={"is_enabled": True})
        seen: dict[uuid.UUID, None] = {}
        for row in rows:
            seen.setdefault(row.router_id, None)
        return list(seen)

    async def list_rogue_dhcp_statuses(
        self, router_id: uuid.UUID
    ) -> list[RouterRogueDhcpStatus]:
        return await self.rogue_statuses.get_all(filters={"router_id": router_id})

    async def upsert_rogue_dhcp_status(
        self, router_id: uuid.UUID, interface: str, data: dict[str, object]
    ) -> RouterRogueDhcpStatus:
        """One row per ``(router_id, interface)``, updated in place --
        composed from plain get/create/update rather than a native
        ``ON CONFLICT``, the same posture
        ``app.domains.readiness.repository.upsert_item`` already takes for
        its own unique-pair row."""
        existing = await self.rogue_statuses.get_all(
            filters={"router_id": router_id, "interface": interface}, limit=1
        )
        if not existing:
            return await self.rogue_statuses.create(
                {"router_id": router_id, "interface": interface, **data}
            )
        return await self.rogue_statuses.update(existing[0], data)

    async def delete_rogue_dhcp_statuses(
        self, router_id: uuid.UUID, interfaces: set[str]
    ) -> int:
        """Hard-deletes this router's rows for ``interfaces``.

        Called only after a *successful* read, for interfaces the device no
        longer reports at all -- meaning it neither serves DHCP there nor
        holds an alert row there, so there is no longer any finding to make.
        Leaving them would be worse than deleting them: a stale
        ``unguarded`` row for an interface that no longer exists fails the
        readiness item forever, with nothing an operator can do to clear it.

        A hard delete rather than ``soft_delete`` because this row is a
        cached observation, not a record of intent -- there is no history
        here worth preserving, and a soft-deleted row would still collide
        with the unique ``(router_id, interface)`` index the next time that
        interface came back.
        """
        deleted = 0
        for interface in interfaces:
            rows = await self.rogue_statuses.get_all(
                filters={"router_id": router_id, "interface": interface}, limit=1
            )
            if rows:
                await self.rogue_statuses.delete(rows[0])
                deleted += 1
        return deleted


__all__ = ["DhcpRepositoryProtocol", "DhcpRepository"]
