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
from datetime import datetime
from typing import Protocol

from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PageParams, PaginationMeta, paginate

from .enums import RouterStatus
from .models import Router, RouterProvisioningToken


def stale_heartbeat_statement(*, cutoff: datetime):
    """The ``ONLINE`` + stale-heartbeat query, built outside the repository
    so it can be read without a database.

    EXTRACTED DELIBERATELY. The suite drives ``RouterService`` through an
    in-memory fake repository, so a predicate living only inside the real
    method is executed by no test -- and this one carries a guarantee that
    matters: ``PROVISIONING`` routers must NEVER be swept, because a router
    mid-install has by definition never sent a heartbeat (the only
    transition out of ``PROVISIONING`` is ``heartbeat``). Widening this to
    include it would mark every router being installed right now as
    offline. Measured, not assumed: doing exactly that left the entire
    suite green, which is why this is no longer inlined.

    ``last_seen_at IS NULL`` IS INCLUDED, deliberately. ``heartbeat()`` is
    the only path into ``ONLINE`` and it always stamps ``last_seen_at``, so
    a NULL here means the row came from somewhere else. Excluding it would
    create a permanently unsweepable state -- the same bug in a smaller box.
    """
    return select(Router).where(
        Router.is_deleted.is_(False),
        Router.status == RouterStatus.ONLINE.value,
        or_(Router.last_seen_at.is_(None), Router.last_seen_at < cutoff),
    )


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
    ) -> bool: ...

    async def list_expired_unused_provisioning_tokens(
        self, *, now: datetime
    ) -> list[RouterProvisioningToken]: ...

    async def list_online_routers_with_stale_heartbeat(
        self, *, cutoff: datetime
    ) -> list[Router]: ...

    async def soft_delete_provisioning_token(
        self, token: RouterProvisioningToken
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
    ) -> bool:
        """Atomic compare-and-set on ``used_at`` -- a single ``UPDATE ...
        WHERE id = :id AND used_at IS NULL`` rather than
        ``GenericRepository.update``'s unconditional read-modify-write.
        Two concurrent ``RouterService.check_in`` calls for the same
        token can both pass the earlier in-memory ``token.is_used()``
        check before either one's write lands; without a
        compare-and-set at the database layer both would then happily
        flip ``used_at`` and both would be treated as a successful,
        first-time consumption of the same one-time token. Returns
        whether *this* call actually consumed the token -- ``False``
        means someone else's concurrent check-in already claimed it
        first, which the caller must treat the same as an
        already-used token (mirrors ``VoucherRepository
        .bulk_revoke_vouchers_for_batch``'s identical
        ``UPDATE ... WHERE`` + rowcount pattern)."""
        statement = (
            update(RouterProvisioningToken)
            .where(
                RouterProvisioningToken.id == token.id,
                RouterProvisioningToken.used_at.is_(None),
            )
            .values(used_at=used_at)
        )
        result = await self.session.execute(statement)
        await self.session.flush()
        consumed = int(result.rowcount or 0) > 0
        if consumed:
            # Keep the in-memory instance the caller already holds in sync
            # with what was just committed, without a second round trip.
            token.used_at = used_at
        return consumed

    async def list_expired_unused_provisioning_tokens(
        self, *, now: datetime
    ) -> list[RouterProvisioningToken]:
        """Every not-yet-soft-deleted, never-used token whose ``expires_at``
        has already passed, platform-wide -- for
        ``service.sweep_expired_provisioning_tokens``. Hand-written (not
        ``GenericRepository.get_all``'s equality-only filters) for the same
        reason ``list_routers`` above is: a ``<`` comparison on
        ``expires_at``, not an equality match."""
        statement = select(RouterProvisioningToken).where(
            RouterProvisioningToken.is_deleted.is_(False),
            RouterProvisioningToken.used_at.is_(None),
            RouterProvisioningToken.expires_at < now,
        )
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    async def list_online_routers_with_stale_heartbeat(
        self, *, cutoff: datetime
    ) -> list[Router]:
        """Every live router still marked ``ONLINE`` whose last heartbeat is
        older than ``cutoff`` -- for ``service.sweep_stale_heartbeats``.

        This query had no caller and no equivalent anywhere, which is the
        whole defect: ``ONLINE`` was written by ``heartbeat()`` and NOTHING
        ever wrote it back. ``RouterStatus.OFFLINE``'s own docstring has
        always described it as "was previously ``ONLINE`` but missed its
        expected heartbeat window", and the ``ONLINE -> OFFLINE`` edge has
        always been in ``ROUTER_STATUS_TRANSITIONS``. Only the writer was
        missing, so a router that died weeks ago read as online for ever.

        The predicate itself lives in ``stale_heartbeat_statement`` -- see
        its docstring for why it is not inlined here."""
        result = await self.session.execute(stale_heartbeat_statement(cutoff=cutoff))
        return list(result.scalars().all())

    async def soft_delete_provisioning_token(
        self, token: RouterProvisioningToken
    ) -> RouterProvisioningToken:
        """``GenericRepository.update()`` deliberately refuses to set
        ``is_deleted``/``deleted_at`` -- only this dedicated
        ``soft_delete()`` path actually flips them, mirroring
        ``app.domains.guest.repository.GuestRepository
        .soft_delete_nas_client``'s identical convention."""
        return await self.provisioning_tokens.soft_delete(token)
