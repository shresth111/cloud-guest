"""Router CPU over time, for the customer dashboard's "Router load" card.

``GET /analytics/venue-insights/router-cpu`` -- one request per dashboard
load. For each MikroTik router at the venue it returns a downsampled CPU
(and memory) series over the requested window, plus the latest reading.

## Where the numbers come from

``router_health_snapshots`` only (``RouterHealthSnapshot``). Two sweeps
write it: the RouterOS-API sweep every 600s (``/system/resource``) and the
SNMP sweep every 300s. Nothing is estimated or interpolated: a bucket with
no snapshot is absent from ``points`` and the chart shows a gap.

## MikroTik only (owner decision, 2026-11-12)

TP-Link Omada and Aruba Instant On rows never write a health snapshot --
no agent runs on them and nothing polls their CPU -- so they are left out
entirely rather than listed as "not reported". The read is narrowed with
``agent_managed_only`` and then to ``vendor = 'mikrotik'`` (or NULL, the
column's own default; see ``vendor_capabilities.vendor_of``). A venue with
no MikroTik gets ``routers: []`` and the card does not render.

## Downsampling

Buckets are fixed-width on the UTC epoch, with the width picked from
``BUCKET_LADDER_SECONDS`` so that a window yields at most
``MAX_POINTS`` buckets (24h -> 30 min, 7d -> 3h, 30d -> 12h). Each bucket
carries the mean and the peak CPU and the mean memory of the snapshots in
it, so a short spike is not averaged out of sight.

## Tenant scoping

Same rule as the rest of ``venue_insights``: the organization id is the
one ``RequireOrganization`` resolved, the location is first proved to
belong to it (404 otherwise, indistinguishable from "no such location"),
and every SQL statement filters on both ids anyway.

Read-only: no audit rows, no caches, nothing sent to any device.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol

from sqlalchemy import and_, func, literal_column, or_, select

from app.domains.location.exceptions import LocationNotFoundError
from app.domains.router.enums import RouterStatus
from app.domains.router.fleet_scope import agent_managed_only
from app.domains.router.models import Router
from app.domains.router_provisioning.models import RouterHealthSnapshot

from .venue_insight_schemas import (
    RouterCpuItem,
    RouterCpuLatest,
    RouterCpuPoint,
    RouterCpuResponse,
)
from .venue_insights import LocationContext, VenueInsightsRepository

MIKROTIK_VENDOR = "mikrotik"

#: At most this many buckets per router per window.
MAX_POINTS = 60

#: Candidate bucket widths, smallest first. 300s is the fastest sweep, so a
#: narrower bucket would only add empty ones.
BUCKET_LADDER_SECONDS: tuple[int, ...] = (
    300,
    600,
    900,
    1800,
    3600,
    7200,
    10800,
    21600,
    43200,
    86400,
)

#: A latest reading older than this is reported as not current. Three
#: missed RouterOS-API sweeps (600s each).
STALE_AFTER_SECONDS = 1800

#: How far back the "latest reading" lookup reaches, independent of the
#: chart window, so a router that stopped reporting yesterday still shows
#: when it last did.
LATEST_LOOKBACK = timedelta(days=30)

#: The card's warning threshold. Served so the UI does not hard-code it.
HIGH_CPU_PERCENT = 80.0


def bucket_seconds_for(start: datetime, end: datetime) -> int:
    span = (end - start).total_seconds()
    for width in BUCKET_LADDER_SECONDS:
        if span / width <= MAX_POINTS:
            return width
    return BUCKET_LADDER_SECONDS[-1]


def _round(value: float | None) -> float | None:
    return None if value is None else round(float(value), 1)


@dataclass(frozen=True)
class MikrotikRouterRow:
    router_id: uuid.UUID
    name: str
    status: str


@dataclass(frozen=True)
class CpuBucketRow:
    router_id: uuid.UUID
    bucket_index: int
    cpu_avg: float | None
    cpu_max: float | None
    memory_avg: float | None


@dataclass(frozen=True)
class LatestReadingRow:
    router_id: uuid.UUID
    recorded_at: datetime
    cpu_usage_percent: float | None
    memory_usage_percent: float | None


class RouterCpuRepositoryProtocol(Protocol):
    async def get_location_context(
        self, *, organization_id: uuid.UUID, location_id: uuid.UUID
    ) -> LocationContext | None: ...

    async def list_mikrotik_routers(
        self, *, organization_id: uuid.UUID, location_id: uuid.UUID
    ) -> list[MikrotikRouterRow]: ...

    async def get_cpu_buckets(
        self,
        *,
        router_ids: list[uuid.UUID],
        start: datetime,
        end: datetime,
        bucket_seconds: int,
    ) -> list[CpuBucketRow]: ...

    async def get_latest_readings(
        self, *, router_ids: list[uuid.UUID], since: datetime, until: datetime
    ) -> dict[uuid.UUID, LatestReadingRow]: ...


class RouterCpuRepository(VenueInsightsRepository):
    """Reuses ``get_location_context`` (the tenant proof) from the venue
    insights repository; adds the three reads this card needs."""

    async def list_mikrotik_routers(
        self, *, organization_id: uuid.UUID, location_id: uuid.UUID
    ) -> list[MikrotikRouterRow]:
        statement = agent_managed_only(
            select(Router.id, Router.name, Router.status)
            .where(
                Router.organization_id == organization_id,
                Router.location_id == location_id,
                Router.is_deleted.is_(False),
                Router.status != RouterStatus.DECOMMISSIONED.value,
                or_(Router.vendor.is_(None), Router.vendor == MIKROTIK_VENDOR),
            )
            .order_by(Router.name.asc())
        )
        rows = (await self.session.execute(statement)).all()
        return [
            MikrotikRouterRow(router_id=rid, name=name, status=str(status))
            for rid, name, status in rows
        ]

    async def get_cpu_buckets(
        self,
        *,
        router_ids: list[uuid.UUID],
        start: datetime,
        end: datetime,
        bucket_seconds: int,
    ) -> list[CpuBucketRow]:
        if not router_ids:
            return []
        # The divisor is inlined (an int this module chose, never caller
        # text) and the GROUP BY names the label: with a bound parameter,
        # SELECT and GROUP BY would each get their own placeholder and
        # Postgres would reject them as different expressions.
        width = literal_column(str(int(bucket_seconds)))
        bucket = func.floor(
            func.extract("epoch", RouterHealthSnapshot.recorded_at) / width
        ).label("bucket")
        bucket_ref = literal_column("bucket")
        statement = (
            select(
                RouterHealthSnapshot.router_id,
                bucket,
                func.avg(RouterHealthSnapshot.cpu_usage_percent),
                func.max(RouterHealthSnapshot.cpu_usage_percent),
                func.avg(RouterHealthSnapshot.memory_usage_percent),
            )
            .where(
                RouterHealthSnapshot.router_id.in_(router_ids),
                RouterHealthSnapshot.is_deleted.is_(False),
                RouterHealthSnapshot.recorded_at >= start,
                RouterHealthSnapshot.recorded_at < end,
                or_(
                    RouterHealthSnapshot.cpu_usage_percent.is_not(None),
                    RouterHealthSnapshot.memory_usage_percent.is_not(None),
                ),
            )
            .group_by(RouterHealthSnapshot.router_id, bucket_ref)
            .order_by(RouterHealthSnapshot.router_id, bucket_ref)
        )
        rows = (await self.session.execute(statement)).all()
        return [
            CpuBucketRow(
                router_id=rid,
                bucket_index=int(idx),
                cpu_avg=cpu_avg,
                cpu_max=cpu_max,
                memory_avg=mem_avg,
            )
            for rid, idx, cpu_avg, cpu_max, mem_avg in rows
        ]

    async def get_latest_readings(
        self, *, router_ids: list[uuid.UUID], since: datetime, until: datetime
    ) -> dict[uuid.UUID, LatestReadingRow]:
        if not router_ids:
            return {}
        statement = (
            select(
                RouterHealthSnapshot.router_id,
                RouterHealthSnapshot.recorded_at,
                RouterHealthSnapshot.cpu_usage_percent,
                RouterHealthSnapshot.memory_usage_percent,
            )
            .where(
                and_(
                    RouterHealthSnapshot.router_id.in_(router_ids),
                    RouterHealthSnapshot.is_deleted.is_(False),
                    RouterHealthSnapshot.recorded_at >= since,
                    RouterHealthSnapshot.recorded_at <= until,
                    RouterHealthSnapshot.cpu_usage_percent.is_not(None),
                )
            )
            .distinct(RouterHealthSnapshot.router_id)
            .order_by(
                RouterHealthSnapshot.router_id,
                RouterHealthSnapshot.recorded_at.desc(),
            )
        )
        rows = (await self.session.execute(statement)).all()
        return {
            rid: LatestReadingRow(
                router_id=rid,
                recorded_at=at,
                cpu_usage_percent=cpu,
                memory_usage_percent=mem,
            )
            for rid, at, cpu, mem in rows
        }


class RouterCpuService:
    def __init__(self, repository: RouterCpuRepositoryProtocol) -> None:
        self.repository = repository

    async def get_router_cpu(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID,
        start: datetime,
        end: datetime,
        now: datetime | None = None,
    ) -> RouterCpuResponse:
        context = await self.repository.get_location_context(
            organization_id=organization_id, location_id=location_id
        )
        if context is None:
            raise LocationNotFoundError(location_id)

        width = bucket_seconds_for(start, end)
        routers = await self.repository.list_mikrotik_routers(
            organization_id=organization_id, location_id=location_id
        )
        ids = [r.router_id for r in routers]
        moment = now or datetime.now(UTC)
        buckets = await self.repository.get_cpu_buckets(
            router_ids=ids, start=start, end=end, bucket_seconds=width
        )
        latest = await self.repository.get_latest_readings(
            router_ids=ids, since=moment - LATEST_LOOKBACK, until=moment
        )

        points: dict[uuid.UUID, list[RouterCpuPoint]] = {rid: [] for rid in ids}
        for row in buckets:
            if row.router_id not in points:
                continue
            points[row.router_id].append(
                RouterCpuPoint(
                    bucket_start=datetime.fromtimestamp(
                        row.bucket_index * width, tz=UTC
                    ).isoformat(),
                    cpu_avg=_round(row.cpu_avg),
                    cpu_max=_round(row.cpu_max),
                    memory_avg=_round(row.memory_avg),
                )
            )

        items: list[RouterCpuItem] = []
        for router in routers:
            reading = latest.get(router.router_id)
            current = None
            if reading is not None:
                age = (moment - reading.recorded_at).total_seconds()
                current = RouterCpuLatest(
                    recorded_at=reading.recorded_at.isoformat(),
                    cpu_usage_percent=_round(reading.cpu_usage_percent),
                    memory_usage_percent=_round(reading.memory_usage_percent),
                    is_stale=age > STALE_AFTER_SECONDS,
                )
            items.append(
                RouterCpuItem(
                    router_id=router.router_id,
                    router_name=router.name,
                    status=router.status,
                    latest=current,
                    points=sorted(
                        points[router.router_id], key=lambda p: p.bucket_start
                    ),
                )
            )

        return RouterCpuResponse(
            location_id=location_id,
            window_start=start.isoformat(),
            window_end=end.isoformat(),
            bucket_seconds=width,
            stale_after_seconds=STALE_AFTER_SECONDS,
            high_cpu_percent=HIGH_CPU_PERCENT,
            routers=items,
        )


__all__ = [
    "BUCKET_LADDER_SECONDS",
    "HIGH_CPU_PERCENT",
    "MAX_POINTS",
    "STALE_AFTER_SECONDS",
    "CpuBucketRow",
    "LatestReadingRow",
    "MikrotikRouterRow",
    "RouterCpuRepository",
    "RouterCpuService",
    "bucket_seconds_for",
]
