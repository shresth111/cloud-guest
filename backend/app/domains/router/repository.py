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
from collections.abc import Sequence
from datetime import datetime
from typing import Protocol

from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PageParams, PaginationMeta, paginate

# Read-only cross-domain import, the same shape
# ``app.domains.monitoring.repository`` already uses to read ``Router``/
# ``IspLink``/``RouterRogueDhcpStatus``: this repository never writes a
# ``RouterAgentCredential``, it only reads when one was last used.
from app.domains.network_integration.models import NetworkIntegration
from app.domains.router_agent.models import RouterAgentCredential

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


# The statuses whose routers are asked "are you talking to us right now?".
#
# ONLINE and OFFLINE only. A router in PENDING_PROVISIONING or PROVISIONING
# has by definition never checked in, so its silence is not news -- exactly
# the reasoning ``stale_heartbeat_statement`` gives for leaving PROVISIONING
# alone. SUSPENDED and DECOMMISSIONED are administrative states: a venue we
# switched off on purpose must not email anybody at 3am about being off.
#
# OFFLINE *is* included, and that is the interesting half: the fast sweep
# has to keep evaluating a router the slow 15-minute sweep has already
# demoted, or a site that went down before this feature existed could never
# be seen to come back.
REACHABILITY_ELIGIBLE_STATUSES = frozenset(
    {RouterStatus.ONLINE.value, RouterStatus.OFFLINE.value}
)


def reachability_candidate_statement(*, now: datetime):
    """Every router this sweep may judge, paired with the most recent
    moment any of its agent credentials was actually used.

    Extracted from the repository for the same reason
    ``stale_heartbeat_statement`` is -- the suite drives ``RouterService``
    through an in-memory fake, so a predicate living only inside the real
    method is executed by no test, and this one carries two guarantees
    worth pinning down.

    **The join is to ``router_agent_credentials.last_used_at``, not to
    ``routers.last_seen_at``.** ``CurrentAgent`` stamps ``last_used_at`` on
    every device-authenticated request, and the agent scheduler's
    ``GET /agent/authorized-macs`` poll runs every 60 seconds against the
    5-minute heartbeat -- so this column is five times fresher than
    ``last_seen_at`` and it has been ticking on the real fleet all along.
    Nothing had ever read it as a liveness signal.

    **A router with no usable credential is excluded, not defaulted to
    silent.** A revoked or expired credential makes ``CurrentAgent`` raise
    ``AgentCredentialRevoked``/``AgentCredentialExpired`` *before* it stamps
    anything, so such a router would look permanently
    silent and would be alerted on forever -- with copy blaming the venue's
    power for what is actually our credential lifecycle. Excluding it
    leaves ``reachability_state`` untouched (never alertable) and is the
    honest answer: we do not know, because we made it impossible to know.
    """
    newest_use = (
        select(
            RouterAgentCredential.router_id.label("router_id"),
            func.max(RouterAgentCredential.last_used_at).label("last_agent_contact_at"),
        )
        .where(
            RouterAgentCredential.is_deleted.is_(False),
            RouterAgentCredential.revoked_at.is_(None),
            RouterAgentCredential.expires_at > now,
        )
        .group_by(RouterAgentCredential.router_id)
        .subquery()
    )
    return (
        select(Router, newest_use.c.last_agent_contact_at)
        .join(newest_use, newest_use.c.router_id == Router.id)
        .where(
            Router.is_deleted.is_(False),
            Router.status.in_(sorted(REACHABILITY_ELIGIBLE_STATUSES)),
            newest_use.c.last_agent_contact_at.is_not(None),
        )
    )


class RouterRepositoryProtocol(Protocol):
    async def get_by_id(
        self, router_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Router | None: ...

    async def get_by_serial_number(self, serial_number: str) -> Router | None: ...

    async def get_by_mac_address(self, mac_address: str) -> Router | None: ...

    async def count_integrations_referencing_router(
        self, router_id: uuid.UUID
    ) -> int: ...

    async def integrations_for_routers(
        self, router_ids: Sequence[uuid.UUID]
    ) -> dict[uuid.UUID, NetworkIntegration]: ...

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

    async def list_reachability_candidates(
        self, *, now: datetime
    ) -> list[tuple[Router, datetime]]: ...

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

    async def count_integrations_referencing_router(
        self, router_id: uuid.UUID
    ) -> int:
        """How many live network integrations point at this fleet row.

        Read-only cross-domain read, the same shape as the
        ``RouterAgentCredential`` import above: this repository never writes a
        ``NetworkIntegration``.

        Exists for one question -- may this row's ``vendor`` still be
        changed. An integration's provider decides the vendor string
        (``ROUTER_VENDOR_BY_PROVIDER``), and ``guest_sessions.router_id`` is
        NOT NULL, so a live integration whose fleet row claims a different
        vendor is a row disagreeing with the row that depends on it. Counted
        rather than fetched because the caller needs a yes/no and has no use
        for the integration itself.
        """
        result = await self.session.execute(
            select(func.count())
            .select_from(NetworkIntegration)
            .where(
                NetworkIntegration.router_id == router_id,
                NetworkIntegration.is_deleted.is_(False),
            )
        )
        return int(result.scalar_one())

    async def integrations_for_routers(
        self, router_ids: Sequence[uuid.UUID]
    ) -> dict[uuid.UUID, NetworkIntegration]:
        """The live network integration for each of these fleet rows.

        ONE query for a whole page, not one per row. The ``.in_()`` batch is
        this codebase's established anti-N+1 shape (see
        ``analytics.get_wireguard_peers_by_router_ids``, which exists to
        replace exactly such a loop), and the column is indexed
        (``ix_network_integrations_router_id``).

        Same cross-domain read-only posture as
        :meth:`count_integrations_referencing_router` above.

        **Not scoped by organization, deliberately** -- the caller has
        already established its right to these router rows, and adding an
        org parameter here would be the path-id-versus-header defect shape
        one layer down. Mirrors ``find_integration_for_router``'s own note.

        ``ix_network_integrations_router_id`` is NOT unique, so a row could
        in principle carry two. The newest wins, matching
        ``find_integration_for_router``'s ``ORDER BY created_at DESC LIMIT
        1`` -- two derivations of "the integration for this router" that
        disagreed would be the defect this whole field exists to remove.

        Disabled integrations ARE returned: ``disabled`` is a state, and
        dropping the row here would make it indistinguishable from
        ``not_registered``.
        """
        if not router_ids:
            return {}
        result = await self.session.execute(
            select(NetworkIntegration)
            .where(
                NetworkIntegration.router_id.in_(list(router_ids)),
                NetworkIntegration.is_deleted.is_(False),
            )
            .order_by(NetworkIntegration.created_at.desc())
        )
        found: dict[uuid.UUID, NetworkIntegration] = {}
        for integration in result.scalars().all():
            key = integration.router_id
            if key is not None:
                found.setdefault(key, integration)
        return found

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

    async def list_reachability_candidates(
        self, *, now: datetime
    ) -> list[tuple[Router, datetime]]:
        """``(router, last_agent_contact_at)`` for every router the
        reachability sweep may judge -- see
        ``reachability_candidate_statement`` for the predicate and why it
        joins where it does."""
        result = await self.session.execute(
            reachability_candidate_statement(now=now)
        )
        return [(row[0], row[1]) for row in result.all()]

    async def soft_delete_provisioning_token(
        self, token: RouterProvisioningToken
    ) -> RouterProvisioningToken:
        """``GenericRepository.update()`` deliberately refuses to set
        ``is_deleted``/``deleted_at`` -- only this dedicated
        ``soft_delete()`` path actually flips them, mirroring
        ``app.domains.guest.repository.GuestRepository
        .soft_delete_nas_client``'s identical convention."""
        return await self.provisioning_tokens.soft_delete(token)
