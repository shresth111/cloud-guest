"""Data access layer for the ISP Management domain.

Mirrors ``app.domains.queue_management.repository``'s shape: a ``Protocol``
describing every operation the service layer needs
(``IspRepositoryProtocol``), and a concrete, ``GenericRepository``-backed
implementation (``IspRepository``) bundling both of this module's tables
behind one repository object, plus a handful of hand-written statements for
the few queries ``GenericRepository``'s equality/IN-filter support
genuinely can't express (the platform-wide health-check sweep's own "every
enabled link, across every router/organization" query).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Protocol

from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import DEFAULT_SORT_FIELD, SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PageParams, PaginationMeta

from .constants import HealthStatus, IspLinkRole
from .models import IspHealthCheck, IspLink


class IspRepositoryProtocol(Protocol):
    # -- links -------------------------------------------------------------------
    async def create_link(self, **fields: object) -> IspLink: ...

    async def get_link_by_id(
        self, link_id: uuid.UUID, *, include_deleted: bool = False
    ) -> IspLink | None: ...

    async def get_link_for_update(self, link_id: uuid.UUID) -> IspLink | None: ...

    async def update_link(self, link: IspLink, data: dict[str, object]) -> IspLink: ...

    async def soft_delete_link(self, link: IspLink) -> IspLink: ...

    async def list_links(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[IspLink], PaginationMeta]: ...

    async def list_links_for_router(self, router_id: uuid.UUID) -> list[IspLink]: ...

    async def get_active_uplink_for_router(
        self, router_id: uuid.UUID
    ) -> IspLink | None: ...

    async def get_primary_link_for_router(
        self, router_id: uuid.UUID
    ) -> IspLink | None: ...

    async def list_backup_links_for_router(
        self, router_id: uuid.UUID
    ) -> list[IspLink]: ...

    async def list_enabled_links_for_sweep(self) -> list[IspLink]: ...

    # -- health checks -------------------------------------------------------------
    async def create_health_check(self, **fields: object) -> IspHealthCheck: ...

    async def list_health_checks_for_link(
        self,
        link_id: uuid.UUID,
        *,
        page: int,
        page_size: int,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> tuple[list[IspHealthCheck], PaginationMeta]: ...

    async def list_recent_health_checks_for_link(
        self, link_id: uuid.UUID, *, limit: int
    ) -> list[IspHealthCheck]: ...

    async def bucketed_health_checks_for_link(
        self,
        link_id: uuid.UUID,
        *,
        start: datetime,
        end: datetime,
        bucket_unit: str,
    ) -> list[
        tuple[
            datetime,
            int,
            int,
            int,
            int,
            float | None,
            float | None,
            float | None,
            float | None,
            float | None,
        ]
    ]: ...


class IspRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``IspRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.links = GenericRepository(IspLink, session)
        self.health_checks = GenericRepository(IspHealthCheck, session)

    # -- links -------------------------------------------------------------------

    async def create_link(self, **fields: object) -> IspLink:
        return await self.links.create(fields)

    async def get_link_by_id(
        self, link_id: uuid.UUID, *, include_deleted: bool = False
    ) -> IspLink | None:
        return await self.links.get_by_id(link_id, include_deleted=include_deleted)

    async def get_link_for_update(self, link_id: uuid.UUID) -> IspLink | None:
        """Real row-level lock (``SELECT ... FOR UPDATE``) on this single
        ``IspLink`` -- used by ``IspService.record_health_check_result``
        immediately before it computes/writes the traffic-counter delta
        and ``consecutive_unhealthy_count``, both of which are read-then-
        incremented against the row's own *previous* value. Without this,
        a manual "Check health now" racing the automated 60s sweep on the
        exact same link (two independent DB sessions/transactions, each
        with its own in-memory snapshot of the link) is a genuine
        last-write-wins lost-update: whichever request's plain UPDATE
        commits last silently discards the other's counter/streak state.
        ``with_for_update()`` makes the second transaction to reach this
        link block until the first commits, then read that first
        transaction's *committed* result -- real serialization, not a
        fixed sleep/retry guess. ``populate_existing=True`` guards the
        (same-session) case where this link was already loaded earlier in
        the same request, so this always reflects the row's current
        committed values rather than a stale identity-mapped object."""
        statement = (
            select(IspLink)
            .where(IspLink.id == link_id, IspLink.is_deleted.is_(False))
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        result = await self.session.execute(statement)
        return result.scalar_one_or_none()

    async def update_link(self, link: IspLink, data: dict[str, object]) -> IspLink:
        return await self.links.update(link, data)

    async def soft_delete_link(self, link: IspLink) -> IspLink:
        return await self.links.soft_delete(link)

    async def list_links(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[IspLink], PaginationMeta]:
        filters: dict[str, object] = {}
        if requesting_organization_id is not None:
            filters["organization_id"] = requesting_organization_id
        if router_id is not None:
            filters["router_id"] = router_id
        return await self.links.paginate(
            page=page,
            page_size=page_size,
            filters=filters or None,
            sort_by=sort_by,
            sort_order=sort_order,
        )

    async def list_links_for_router(self, router_id: uuid.UUID) -> list[IspLink]:
        return await self.links.get_all(
            filters={"router_id": router_id},
            sort_by="priority",
            sort_order=SortOrder.ASC,
        )

    async def get_active_uplink_for_router(
        self, router_id: uuid.UUID
    ) -> IspLink | None:
        results = await self.links.get_all(
            filters={"router_id": router_id, "is_active_uplink": True}, limit=1
        )
        return results[0] if results else None

    async def get_primary_link_for_router(self, router_id: uuid.UUID) -> IspLink | None:
        results = await self.links.get_all(
            filters={"router_id": router_id, "role": IspLinkRole.PRIMARY.value},
            limit=1,
        )
        return results[0] if results else None

    async def list_backup_links_for_router(self, router_id: uuid.UUID) -> list[IspLink]:
        return await self.links.get_all(
            filters={"router_id": router_id, "role": IspLinkRole.BACKUP.value},
            sort_by="priority",
            sort_order=SortOrder.ASC,
        )

    async def list_enabled_links_for_sweep(self) -> list[IspLink]:
        """Every enabled ``IspLink`` across every router/organization --
        the platform-wide "who needs a health check this tick" query the
        Celery Beat sweep drives. A plain equality-filtered
        ``GenericRepository.get_all`` already expresses this; no
        hand-written SQL needed (unlike a genuinely cross-table
        aggregate)."""
        return await self.links.get_all(filters={"is_enabled": True})

    # -- health checks -------------------------------------------------------------

    async def create_health_check(self, **fields: object) -> IspHealthCheck:
        return await self.health_checks.create(fields)

    async def list_health_checks_for_link(
        self,
        link_id: uuid.UUID,
        *,
        page: int,
        page_size: int,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> tuple[list[IspHealthCheck], PaginationMeta]:
        if start is None and end is None:
            return await self.health_checks.paginate(
                page=page,
                page_size=page_size,
                filters={"isp_link_id": link_id},
                sort_by="checked_at",
                sort_order=SortOrder.DESC,
            )
        # A ``start``/``end`` range needs a ``>=``/``<=`` comparison --
        # ``GenericRepository.paginate``'s ``filters`` dict only ever
        # expresses equality/IN (see ``app.database.utils.filters
        # .apply_filters``), so this one call is hand-rolled directly
        # against the model, same "small, hand-written escape hatch"
        # precedent this file's own module docstring already flags for
        # the sweep's own cross-router query above.
        conditions = [
            IspHealthCheck.is_deleted.is_(False),
            IspHealthCheck.isp_link_id == link_id,
        ]
        if start is not None:
            conditions.append(IspHealthCheck.checked_at >= start)
        if end is not None:
            conditions.append(IspHealthCheck.checked_at <= end)
        params = PageParams(page=page, page_size=page_size)
        count_statement = (
            select(func.count()).select_from(IspHealthCheck).where(*conditions)
        )
        total_result = await self.session.execute(count_statement)
        total_items = int(total_result.scalar_one())
        statement = (
            select(IspHealthCheck)
            .where(*conditions)
            .order_by(IspHealthCheck.checked_at.desc())
            .limit(params.page_size)
            .offset(params.offset)
        )
        result = await self.session.execute(statement)
        rows = list(result.scalars().all())
        return rows, PaginationMeta.from_total(params, total_items)

    async def list_recent_health_checks_for_link(
        self, link_id: uuid.UUID, *, limit: int
    ) -> list[IspHealthCheck]:
        """DESC-ordered, unpaginated (capped at ``limit``) -- backs
        ``IspService.compute_unhealthy_since``'s own "how far back does
        the current unhealthy streak go" scan. Deliberately separate from
        ``list_health_checks_for_link`` (paginated, client-facing): this
        is an internal computation that needs a plain ordered slice, not
        a ``PaginationMeta``-wrapped page."""
        return await self.health_checks.get_all(
            filters={"isp_link_id": link_id},
            sort_by="checked_at",
            sort_order=SortOrder.DESC,
            limit=limit,
        )

    async def bucketed_health_checks_for_link(
        self,
        link_id: uuid.UUID,
        *,
        start: datetime,
        end: datetime,
        bucket_unit: str,
    ) -> list[
        tuple[
            datetime,
            int,
            int,
            int,
            int,
            float | None,
            float | None,
            float | None,
            float | None,
            float | None,
        ]
    ]:
        """One aggregated ``(bucket_start, total, healthy, degraded,
        unhealthy, avg_latency_ms, avg_packet_loss_percentage,
        avg_download_mbps, avg_upload_mbps, max_download_mbps)`` row per
        real ``bucket_unit`` ("hour"/"day") time bucket in ``[start,
        end]`` that has at least one health-check row -- the query behind
        the "Internet Connection" history dialog's uptime chart (and, for
        the new Mbps columns, its bandwidth-history view). SQL does the
        aggregation so a 30-day window at the sweep's real 60-second
        cadence (tens of thousands of rows) comes back as ~30 rows, never
        as individual checks. The Mbps aggregates are computed with plain
        SQL ``AVG``/``MAX``, which already skip ``NULL`` rows (ticks where
        the health check itself failed and no traffic sample could be
        taken) -- a bucket where every check failed reports ``NULL``
        (surfaced as ``None`` below), never a fabricated ``0``."""
        bucket = func.date_trunc(bucket_unit, IspHealthCheck.checked_at)
        healthy_expr = func.sum(
            case((IspHealthCheck.status == HealthStatus.HEALTHY.value, 1), else_=0)
        )
        degraded_expr = func.sum(
            case((IspHealthCheck.status == HealthStatus.DEGRADED.value, 1), else_=0)
        )
        unhealthy_expr = func.sum(
            case((IspHealthCheck.status == HealthStatus.UNHEALTHY.value, 1), else_=0)
        )
        statement = (
            select(
                bucket.label("bucket_start"),
                func.count().label("total"),
                healthy_expr.label("healthy"),
                degraded_expr.label("degraded"),
                unhealthy_expr.label("unhealthy"),
                func.avg(IspHealthCheck.latency_ms).label("avg_latency"),
                func.avg(IspHealthCheck.packet_loss_percentage).label("avg_loss"),
                func.avg(IspHealthCheck.download_mbps).label("avg_download"),
                func.avg(IspHealthCheck.upload_mbps).label("avg_upload"),
                func.max(IspHealthCheck.download_mbps).label("max_download"),
            )
            .where(
                IspHealthCheck.is_deleted.is_(False),
                IspHealthCheck.isp_link_id == link_id,
                IspHealthCheck.checked_at >= start,
                IspHealthCheck.checked_at <= end,
            )
            .group_by(bucket)
            .order_by(bucket.asc())
        )
        result = await self.session.execute(statement)
        return [
            (
                row.bucket_start,
                int(row.total),
                int(row.healthy),
                int(row.degraded),
                int(row.unhealthy),
                float(row.avg_latency) if row.avg_latency is not None else None,
                float(row.avg_loss) if row.avg_loss is not None else None,
                float(row.avg_download) if row.avg_download is not None else None,
                float(row.avg_upload) if row.avg_upload is not None else None,
                float(row.max_download) if row.max_download is not None else None,
            )
            for row in result.all()
        ]


__all__ = ["IspRepositoryProtocol", "IspRepository"]
