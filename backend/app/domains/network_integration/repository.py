"""Data access layer for the Network Integration domain.

Mirrors ``app.domains.mac_authorization.repository``'s shape: a
``Protocol`` describing every operation the service layer needs
(``NetworkIntegrationRepositoryProtocol``) and a concrete,
``GenericRepository``-backed implementation.

## Where hand-written SQL is used, and why

``GenericRepository`` covers equality/IN filters, pagination and soft
delete, and that is what almost every method here uses. Four things it
cannot express, so they are written out:

* **``list_due_for_sync``** needs ``last_sync_at IS NULL OR last_sync_at <
  now() - interval sync_interval_seconds`` -- a comparison against *the
  row's own column*, not a constant. There is no way to say that with an
  equality filter map, and doing it in Python would mean loading every
  enabled integration on the platform on every 60-second tick.
* **``search_integrations``** needs a case-insensitive ``q`` across three
  columns *combined with* equality filters. ``GenericRepository.search``
  supports the ILIKE half but returns a plain list with no pagination
  metadata, and the platform list is paginated.
* **``list_integrations_with_names``** needs a LEFT JOIN onto
  ``organizations``/``locations`` to render ``organization_name``. Doing
  it as N+1 lookups per page is the obvious alternative and is a page load
  of 25 extra queries.
* **``platform_summary``** is five aggregates. It is one query.

The same precedent ``app.domains.rbac.repository
.search_audit_log_entries`` sets, and for the same reason.

## The tenant filter is a parameter, never a default

Every list method takes ``requesting_organization_id`` and applies it when
it is not ``None``. That is this codebase's established convention and it
is also its known trap: ``None`` means "no filter", so a caller that
forgets to pass it reads every tenant. This layer does **not** try to fix
that by refusing ``None`` -- the platform (Master console) reads genuinely
need the unfiltered query, and a repository that cannot express them would
just get bypassed. The decision about whether ``None`` is legitimate is
made one layer up, in ``service.py``, where the caller's scope is known:
customer paths raise, platform paths ask by name. See
``service.NetworkIntegrationService._require_organization``.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Protocol

from sqlalchemy import Select, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import DEFAULT_SORT_FIELD, SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PageParams, PaginationMeta

from .constants import (
    AuthorizationStatus,
    IntegrationStatus,
)
from .models import (
    NetworkIntegration,
    NetworkIntegrationAuthorization,
    NetworkIntegrationEvent,
)

__all__ = [
    "NetworkIntegrationRepository",
    "NetworkIntegrationRepositoryProtocol",
    "PlatformSummaryRow",
]


class PlatformSummaryRow(Protocol):
    """Structural shape of ``platform_summary``'s return value.

    A Protocol rather than a dataclass so the service layer can be handed
    a ``SimpleNamespace`` by a test without importing anything from here.
    """

    tenant_count: int
    integration_count: int
    connected_count: int
    error_count: int
    disabled_count: int
    device_count: int
    client_count: int
    active_authorization_count: int
    last_sync_at: datetime | None


class NetworkIntegrationRepositoryProtocol(Protocol):
    # -- integrations ------------------------------------------------------
    async def create_integration(self, **fields: object) -> NetworkIntegration: ...

    async def get_integration_by_id(
        self, integration_id: uuid.UUID, *, include_deleted: bool = False
    ) -> NetworkIntegration | None: ...

    async def update_integration(
        self, integration: NetworkIntegration, data: dict[str, object]
    ) -> NetworkIntegration: ...

    async def soft_delete_integration(
        self, integration: NetworkIntegration
    ) -> NetworkIntegration: ...

    async def list_integrations(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        provider: str | None = None,
        status: str | None = None,
        query: str | None = None,
        page: int,
        page_size: int,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[NetworkIntegration], PaginationMeta]: ...

    async def resolve_display_names(
        self, integrations: list[NetworkIntegration]
    ) -> dict[uuid.UUID, tuple[str | None, str | None]]: ...

    async def find_live_integration(
        self,
        *,
        organization_id: uuid.UUID,
        provider: str,
        base_url: str,
        external_site_id: str | None,
        exclude_id: uuid.UUID | None = None,
    ) -> NetworkIntegration | None: ...

    async def find_enabled_integration_for_location(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID,
        provider: str,
    ) -> NetworkIntegration | None: ...

    async def find_integration_for_router(
        self, router_id: uuid.UUID
    ) -> NetworkIntegration | None: ...

    async def list_due_for_sync(
        self, *, now: datetime, limit: int
    ) -> list[NetworkIntegration]: ...

    # -- events ------------------------------------------------------------
    async def create_event(self, **fields: object) -> NetworkIntegrationEvent: ...

    async def list_events(
        self,
        *,
        integration_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        page: int,
        page_size: int,
    ) -> tuple[list[NetworkIntegrationEvent], PaginationMeta]: ...

    # -- authorizations ----------------------------------------------------
    async def create_authorization(
        self, **fields: object
    ) -> NetworkIntegrationAuthorization: ...

    async def update_authorization(
        self,
        authorization: NetworkIntegrationAuthorization,
        data: dict[str, object],
    ) -> NetworkIntegrationAuthorization: ...

    async def count_active_authorizations(
        self,
        *,
        integration_id: uuid.UUID | None = None,
        organization_id: uuid.UUID | None = None,
        now: datetime | None = None,
    ) -> int: ...

    async def find_active_authorization(
        self, *, integration_id: uuid.UUID, client_mac: str
    ) -> NetworkIntegrationAuthorization | None: ...

    # -- platform ----------------------------------------------------------
    async def platform_summary(self) -> PlatformSummaryRow: ...


class NetworkIntegrationRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``NetworkIntegrationRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.integrations = GenericRepository(NetworkIntegration, session)
        self.events = GenericRepository(NetworkIntegrationEvent, session)
        self.authorizations = GenericRepository(
            NetworkIntegrationAuthorization, session
        )

    # -- integrations ------------------------------------------------------

    async def create_integration(self, **fields: object) -> NetworkIntegration:
        return await self.integrations.create(fields)

    async def get_integration_by_id(
        self, integration_id: uuid.UUID, *, include_deleted: bool = False
    ) -> NetworkIntegration | None:
        return await self.integrations.get_by_id(
            integration_id, include_deleted=include_deleted
        )

    async def update_integration(
        self, integration: NetworkIntegration, data: dict[str, object]
    ) -> NetworkIntegration:
        return await self.integrations.update(integration, data)

    async def soft_delete_integration(
        self, integration: NetworkIntegration
    ) -> NetworkIntegration:
        return await self.integrations.soft_delete(integration)

    def _live(self) -> Select[tuple[NetworkIntegration]]:
        return select(NetworkIntegration).where(
            NetworkIntegration.is_deleted.is_(False)
        )

    async def list_integrations(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        provider: str | None = None,
        status: str | None = None,
        query: str | None = None,
        page: int,
        page_size: int,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[NetworkIntegration], PaginationMeta]:
        """Paginated list, tenant-filtered when an organization is given.

        ``requesting_organization_id=None`` performs an **unfiltered,
        cross-tenant** read. That is correct for the Master console and
        catastrophic for a customer route; see this module's docstring for
        why the decision is made in ``service.py`` and not here.
        """
        statement = self._live()
        if requesting_organization_id is not None:
            statement = statement.where(
                NetworkIntegration.organization_id == requesting_organization_id
            )
        if location_id is not None:
            statement = statement.where(
                NetworkIntegration.location_id == location_id
            )
        if provider is not None:
            statement = statement.where(NetworkIntegration.provider == provider)
        if status is not None:
            statement = statement.where(NetworkIntegration.status == status)
        if query:
            # Escape the ILIKE metacharacters before interpolating a
            # caller-supplied string. Without this, a `q` of "%" matches
            # every row -- harmless here since it is already scoped -- but
            # a `q` of "_" silently means "any single character", which
            # makes the search return results the user did not ask for and
            # cannot explain.
            pattern = (
                query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            )
            like = f"%{pattern}%"
            statement = statement.where(
                or_(
                    NetworkIntegration.name.ilike(like, escape="\\"),
                    NetworkIntegration.base_url.ilike(like, escape="\\"),
                    NetworkIntegration.external_site_name.ilike(like, escape="\\"),
                )
            )

        params = PageParams(page=page, page_size=page_size)
        count_statement = select(func.count()).select_from(
            statement.order_by(None).subquery()
        )
        total_items = int((await self.session.execute(count_statement)).scalar_one())

        column = getattr(NetworkIntegration, sort_by, NetworkIntegration.created_at)
        ordered = statement.order_by(
            column.desc() if sort_order == SortOrder.DESC else column.asc()
        )
        ordered = ordered.limit(params.page_size).offset(
            (params.page - 1) * params.page_size
        )
        rows = list((await self.session.execute(ordered)).scalars().all())
        return rows, PaginationMeta.from_total(params, total_items)

    async def resolve_display_names(
        self, integrations: list[NetworkIntegration]
    ) -> dict[uuid.UUID, tuple[str | None, str | None]]:
        """``{integration_id: (organization_name, location_name)}``.

        Two ``IN`` queries for a whole page rather than a join on the main
        list query, and rather than N+1 lookups. The join would force the
        list query to return rows instead of ORM entities (or to carry
        eager-load machinery for two columns), and N+1 is 50 extra
        round trips per page of 25.

        Imported locally: ``app.domains.organization.models`` and
        ``app.domains.location.models`` are other domains' concretes, and
        a module-level import of them here would put this domain in their
        import graph for the sake of two display strings.
        """
        if not integrations:
            return {}
        from app.domains.location.models import Location  # noqa: PLC0415
        from app.domains.organization.models import Organization  # noqa: PLC0415

        org_ids = {i.organization_id for i in integrations}
        location_ids = {i.location_id for i in integrations if i.location_id}

        org_rows = await self.session.execute(
            select(Organization.id, Organization.name).where(
                Organization.id.in_(org_ids)
            )
        )
        org_names = {row[0]: row[1] for row in org_rows}

        location_names: dict[uuid.UUID, str] = {}
        if location_ids:
            location_rows = await self.session.execute(
                select(Location.id, Location.name).where(Location.id.in_(location_ids))
            )
            location_names = {row[0]: row[1] for row in location_rows}

        return {
            integration.id: (
                org_names.get(integration.organization_id),
                location_names.get(integration.location_id)
                if integration.location_id
                else None,
            )
            for integration in integrations
        }

    async def find_live_integration(
        self,
        *,
        organization_id: uuid.UUID,
        provider: str,
        base_url: str,
        external_site_id: str | None,
        exclude_id: uuid.UUID | None = None,
    ) -> NetworkIntegration | None:
        """The row the partial unique index would collide with, if any.

        A pre-check so the API returns a 409 with a useful message rather
        than letting Postgres raise an ``IntegrityError`` that surfaces as
        a 500. The index is still the real guarantee -- this check races,
        and losing the race gives the database's own error, which is the
        correct outcome and is why the index exists rather than only this.
        """
        statement = self._live().where(
            NetworkIntegration.organization_id == organization_id,
            NetworkIntegration.provider == provider,
            NetworkIntegration.base_url == base_url,
        )
        if external_site_id is None:
            statement = statement.where(
                NetworkIntegration.external_site_id.is_(None)
            )
        else:
            statement = statement.where(
                NetworkIntegration.external_site_id == external_site_id
            )
        if exclude_id is not None:
            statement = statement.where(NetworkIntegration.id != exclude_id)
        return (await self.session.execute(statement.limit(1))).scalars().first()

    async def find_enabled_integration_for_location(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID,
        provider: str,
    ) -> NetworkIntegration | None:
        """The integration a portal authorization for this venue should use.

        Both ``organization_id`` **and** ``location_id`` are required, and
        both are in the WHERE clause. Resolving by location alone would be
        one column short of a tenant check on the most security-sensitive
        read in the domain -- the portal endpoint is unauthenticated, so
        the request body is entirely attacker-controlled and the pair must
        be verified together.

        Ordered by ``created_at DESC`` and limited to one: a venue with two
        enabled integrations for the same provider is a misconfiguration
        this method cannot resolve, and picking the most recently created
        is at least deterministic and explicable. The service layer writes
        an event row when it happens rather than silently choosing.
        """
        statement = (
            self._live()
            .where(
                NetworkIntegration.organization_id == organization_id,
                NetworkIntegration.location_id == location_id,
                NetworkIntegration.provider == provider,
                NetworkIntegration.is_enabled.is_(True),
            )
            .order_by(NetworkIntegration.created_at.desc())
            .limit(1)
        )
        return (await self.session.execute(statement)).scalars().first()

    async def find_integration_for_router(
        self, router_id: uuid.UUID
    ) -> NetworkIntegration | None:
        """The integration a controller-managed fleet row belongs to.

        The inverse of ``NetworkIntegration.router_id``, and the only read
        ``app.domains.readiness`` needs from this domain -- so it lives
        here rather than making that domain query this table itself.

        **Deliberately not scoped by organization.** The caller
        (``ReadinessService._check_controller_integration``) has already
        resolved the router through its own org-scoped
        ``router_lookup.get_router``, and ``network_integrations.router_id``
        is written only by ``create_integration_with_fleet_device``, in one
        transaction, from the same organization. Adding an org parameter
        that the query then compared against the *caller's* header rather
        than the router's owner would be the path-id scoping shape this
        codebase has found across a number of handlers: permission checked
        on one thing, row read by another.

        Disabled integrations are returned. "Switched off" is an answer the
        readiness item has to be able to give -- filtering them out here
        would make a deliberately-disabled venue indistinguishable from one
        that was never linked at all, and send an operator to create a
        second integration.
        """
        statement = (
            self._live()
            .where(NetworkIntegration.router_id == router_id)
            .order_by(NetworkIntegration.created_at.desc())
            .limit(1)
        )
        return (await self.session.execute(statement)).scalars().first()

    async def list_due_for_sync(
        self, *, now: datetime, limit: int
    ) -> list[NetworkIntegration]:
        """Enabled, non-deleted integrations whose own interval has elapsed.

        The interval comparison is per-row -- ``last_sync_at`` older than
        ``now - sync_interval_seconds`` *of that row* -- which is why this
        is hand-written SQL rather than a filter map. See this module's
        docstring.

        A row that has never synced (``last_sync_at IS NULL``) is always
        due, so a newly created integration is picked up on the next tick
        rather than waiting a full interval for a value it does not have.

        Never returns a disabled or soft-deleted row. ``is_deleted`` is in
        the WHERE clause explicitly rather than relying on
        ``GenericRepository``'s default, because this is the one query in
        the domain that runs with no user in the request and therefore has
        nothing else standing between it and a tenant's controller.

        Backoff on consecutive failures is applied by multiplying the
        effective interval, read from ``provider_metadata``. Postgres
        cannot index a JSONB-derived multiplier usefully, so the SQL
        selects on the *base* interval and ``tasks.py`` skips a row whose
        backoff has not yet elapsed. That means the query can return rows
        the sweep then skips -- bounded by ``limit`` and cheap, and the
        alternative (a real ``next_sync_due_at`` column maintained on
        every write) is a denormalization that can go stale. Stated here
        rather than left as a surprise to whoever reads the sweep's skip
        counter.
        """
        interval = func.make_interval(
            0, 0, 0, 0, 0, 0, NetworkIntegration.sync_interval_seconds
        )
        statement = (
            self._live()
            .where(
                NetworkIntegration.is_enabled.is_(True),
                or_(
                    NetworkIntegration.last_sync_at.is_(None),
                    NetworkIntegration.last_sync_at <= (now - interval),
                ),
            )
            .order_by(NetworkIntegration.last_sync_at.asc().nullsfirst())
            .limit(limit)
        )
        return list((await self.session.execute(statement)).scalars().all())

    # -- events ------------------------------------------------------------

    async def create_event(self, **fields: object) -> NetworkIntegrationEvent:
        return await self.events.create(fields)

    async def list_events(
        self,
        *,
        integration_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        page: int,
        page_size: int,
    ) -> tuple[list[NetworkIntegrationEvent], PaginationMeta]:
        """One integration's feed, newest first.

        ``integration_id`` alone would be enough to scope this *if* the
        caller had already been proven to own that integration -- which
        ``service.py`` does. The organization filter is applied anyway:
        it costs nothing (the composite index covers it), and it means
        this method is safe on its own terms rather than safe only in
        combination with a check somewhere else. Defence in depth on the
        exact read this codebase has leaked across tenants before.
        """
        filters: dict[str, object] = {"integration_id": integration_id}
        if requesting_organization_id is not None:
            filters["organization_id"] = requesting_organization_id
        return await self.events.paginate(
            page=page,
            page_size=page_size,
            filters=filters,
            sort_by="created_at",
            sort_order=SortOrder.DESC,
        )

    # -- authorizations ----------------------------------------------------

    async def create_authorization(
        self, **fields: object
    ) -> NetworkIntegrationAuthorization:
        return await self.authorizations.create(fields)

    async def update_authorization(
        self,
        authorization: NetworkIntegrationAuthorization,
        data: dict[str, object],
    ) -> NetworkIntegrationAuthorization:
        return await self.authorizations.update(authorization, data)

    async def count_active_authorizations(
        self,
        *,
        integration_id: uuid.UUID | None = None,
        organization_id: uuid.UUID | None = None,
        now: datetime | None = None,
    ) -> int:
        """How many authorizations are currently believed live.

        "Believed" is load-bearing: ``expires_at > now`` is what *this
        platform asked for*, not what the controller is currently
        enforcing. See ``models.NetworkIntegrationAuthorization``'s "not a
        mirror of controller state" docstring. A count derived from it is
        an upper bound on reality, and any UI presenting it as a live
        session count is overstating what is known.
        """
        statement = select(func.count()).select_from(
            NetworkIntegrationAuthorization
        ).where(
            NetworkIntegrationAuthorization.is_deleted.is_(False),
            NetworkIntegrationAuthorization.status
            == AuthorizationStatus.AUTHORIZED.value,
        )
        if integration_id is not None:
            statement = statement.where(
                NetworkIntegrationAuthorization.integration_id == integration_id
            )
        if organization_id is not None:
            statement = statement.where(
                NetworkIntegrationAuthorization.organization_id == organization_id
            )
        if now is not None:
            statement = statement.where(
                or_(
                    NetworkIntegrationAuthorization.expires_at.is_(None),
                    NetworkIntegrationAuthorization.expires_at > now,
                )
            )
        return int((await self.session.execute(statement)).scalar_one())

    async def find_active_authorization(
        self, *, integration_id: uuid.UUID, client_mac: str
    ) -> NetworkIntegrationAuthorization | None:
        statement = (
            select(NetworkIntegrationAuthorization)
            .where(
                NetworkIntegrationAuthorization.is_deleted.is_(False),
                NetworkIntegrationAuthorization.integration_id == integration_id,
                NetworkIntegrationAuthorization.client_mac == client_mac,
                NetworkIntegrationAuthorization.status
                == AuthorizationStatus.AUTHORIZED.value,
            )
            .order_by(NetworkIntegrationAuthorization.created_at.desc())
            .limit(1)
        )
        return (await self.session.execute(statement)).scalars().first()

    # -- platform ----------------------------------------------------------

    async def platform_summary(self) -> Any:
        """Platform-wide aggregates for the Master console.

        **Deliberately unscoped.** This is the one method in this module
        that reads every tenant by design and cannot be tenant-filtered at
        all -- it is a count of tenants. It is therefore reachable only
        from ``service.get_platform_summary``, whose route carries
        ``RequirePermission(..., scope=ScopeType.GLOBAL)``: an
        organization-scoped role, however privileged within its own
        tenant, cannot satisfy a GLOBAL check. That gate is the whole
        access control on this query.

        ``device_count``/``client_count`` are summed out of
        ``provider_metadata`` rather than counted from tables this domain
        owns, because this domain does not store devices or clients -- they
        are live read-throughs (see ``__init__.py``: "not a second
        analytics stack"). The numbers are therefore as fresh as the last
        successful sync of each integration and no fresher, which is why
        ``last_sync_at`` is returned alongside them rather than left for
        the reader to wonder about.
        """
        from types import SimpleNamespace  # noqa: PLC0415

        live = NetworkIntegration.is_deleted.is_(False)
        error_statuses = (
            IntegrationStatus.AUTH_FAILED.value,
            IntegrationStatus.CONNECTION_FAILED.value,
            IntegrationStatus.SYNC_ERROR.value,
        )
        row = (
            await self.session.execute(
                select(
                    func.count(func.distinct(NetworkIntegration.organization_id)),
                    func.count(NetworkIntegration.id),
                    func.count(NetworkIntegration.id).filter(
                        NetworkIntegration.status
                        == IntegrationStatus.CONNECTED.value
                    ),
                    func.count(NetworkIntegration.id).filter(
                        NetworkIntegration.status.in_(error_statuses)
                    ),
                    func.count(NetworkIntegration.id).filter(
                        NetworkIntegration.is_enabled.is_(False)
                    ),
                    func.coalesce(
                        func.sum(
                            func.coalesce(
                                NetworkIntegration.provider_metadata[
                                    "device_count"
                                ].as_integer(),
                                0,
                            )
                        ),
                        0,
                    ),
                    func.coalesce(
                        func.sum(
                            func.coalesce(
                                NetworkIntegration.provider_metadata[
                                    "client_count"
                                ].as_integer(),
                                0,
                            )
                        ),
                        0,
                    ),
                    func.max(NetworkIntegration.last_sync_at),
                ).where(live)
            )
        ).one()

        active_authorizations = await self.count_active_authorizations()
        return SimpleNamespace(
            tenant_count=int(row[0] or 0),
            integration_count=int(row[1] or 0),
            connected_count=int(row[2] or 0),
            error_count=int(row[3] or 0),
            disabled_count=int(row[4] or 0),
            device_count=int(row[5] or 0),
            client_count=int(row[6] or 0),
            active_authorization_count=active_authorizations,
            last_sync_at=row[7],
        )
