"""Geo Location: storage and the by-country summary service.

Kept out of ``service.py`` on purpose: this is a fourth independent list
(after devices, destinations and services) with its own table, and nothing
here reads or writes the other three.

* :class:`TrafficFlowGeoRepository` -- the country-bucket statements.
* :class:`GeoWindowWriter` -- what ingest calls for each NEW window.
* :class:`TrafficFlowGeoService` -- one venue or router over a range.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from fastapi import status
from sqlalchemy import delete, func, literal, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings

from .constants import (
    CUSTOMER_MIN_DEVICES_FOR_DESTINATIONS,
    DEFAULT_QUERY_WINDOW_SECONDS,
    MAX_QUERY_WINDOW_DAYS,
    WINDOW_SECONDS,
)
from .destinations import DestinationScope
from .geo import (
    DEFAULT_GEO_COUNTRIES,
    DEFAULT_GEO_NETWORKS,
    MAX_GEO_COUNTRIES,
    MAX_GEO_NETWORKS,
    UNKNOWN_COUNTRY,
    UNKNOWN_NETWORK_ASN,
    GeoCountryRow,
    GeoLookup,
    build_geo_summary,
    geo_rows,
)
from .models import TrafficFlowCountryBucket, TrafficFlowWindow
from .service import SummaryScope, TrafficFlowError

__all__ = [
    "CustomerGeoService",
    "GeoScope",
    "GeoWindowWriter",
    "TrafficFlowGeoRepository",
    "TrafficFlowGeoService",
    "country_bucket_insert_statement",
    "country_rows_statement",
    "windows_looked_up_statement",
]

#: Country buckets deleted per retention sweep. Up to about 70 rows per
#: window, so a larger (still bounded) batch than windows.
GEO_RETENTION_BATCH = 100_000


@dataclass(frozen=True, slots=True)
class GeoScope:
    """Whose rows a statement may read. ``SummaryScope`` plus the two things
    a customer route adds: the caller's organisation on every statement, and
    the small-venue rule for networks."""

    router_id: uuid.UUID | None = None
    location_id: uuid.UUID | None = None
    #: The caller's organisation on a customer route; ``None`` for Master.
    organization_id: uuid.UUID | None = None
    #: Small-venue rule for networks. 0 (Master) withholds nothing.
    min_devices: int = 0

    def conditions(self, model: Any) -> list[Any]:
        out = SummaryScope(self.router_id, self.location_id).conditions(model)
        if self.organization_id is not None:
            out.append(model.organization_id == self.organization_id)
        return out

    def shown(self, model: Any) -> Any | None:
        """The condition "this bucket's window had enough devices", or
        ``None`` when no rule applies. It IS the Destinations condition
        (``DestinationScope.visible``), not a copy: one rule for both, and it
        fails closed the same way (a bucket whose window row is missing is
        not shown)."""
        if self.min_devices <= 0 or self.location_id is None:
            return None
        (condition,) = DestinationScope(
            location_id=self.location_id, min_devices=self.min_devices
        ).visible(model)
        return condition


def country_bucket_insert_statement(rows: list[dict[str, Any]]) -> Any:
    return (
        pg_insert(TrafficFlowCountryBucket)
        .values(rows)
        .on_conflict_do_nothing(constraint="uq_traffic_flow_country_buckets_key")
    )


def _in_range(
    model: Any, scope: SummaryScope | GeoScope, since: datetime, until: datetime
) -> Any:
    return (
        model.window_start >= since,
        model.window_start < until,
        *scope.conditions(model),
    )


def country_rows_statement(
    scope: SummaryScope | GeoScope, *, since: datetime, until: datetime
) -> Any:
    """Country buckets in range, summed per (country, network). The scope
    conditions are the only thing between one venue's rows and another's.

    Under the small-venue rule three more columns carry the same sums over
    only the windows with enough devices: the country total stays whole, the
    network breakdown is built from these."""
    bucket = TrafficFlowCountryBucket
    columns = [
        bucket.country_code,
        bucket.asn,
        func.max(bucket.network_name),
        func.coalesce(func.sum(bucket.bytes_up), 0),
        func.coalesce(func.sum(bucket.bytes_down), 0),
        func.coalesce(func.sum(bucket.flows), 0),
    ]
    shown = scope.shown(bucket) if isinstance(scope, GeoScope) else None
    if shown is not None:
        columns += [
            func.coalesce(func.sum(bucket.bytes_up).filter(shown), 0),
            func.coalesce(func.sum(bucket.bytes_down).filter(shown), 0),
            func.coalesce(func.sum(bucket.flows).filter(shown), 0),
        ]
    return (
        select(*columns)
        .where(*_in_range(bucket, scope, since, until))
        .group_by(bucket.country_code, bucket.asn)
    )


def windows_looked_up_statement(
    scope: SummaryScope | GeoScope, *, since: datetime, until: datetime
) -> Any:
    """How many windows in range were looked up: exactly one "unknown" row is
    written per looked-up window (``geo.py``), so counting those counts
    windows. The second column is how many of them the small-venue rule
    withholds networks for (0 when no rule applies)."""
    bucket = TrafficFlowCountryBucket
    shown = scope.shown(bucket) if isinstance(scope, GeoScope) else None
    withheld = func.count().filter(~shown) if shown is not None else literal(0)
    return select(func.count(), withheld).where(
        bucket.country_code == UNKNOWN_COUNTRY,
        bucket.asn == UNKNOWN_NETWORK_ASN,
        *_in_range(bucket, scope, since, until),
    )


class TrafficFlowGeoRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def insert_country_buckets(self, rows: list[dict[str, Any]]) -> None:
        if rows:
            await self.session.execute(country_bucket_insert_statement(rows))

    async def delete_country_buckets_before(
        self, cutoff: datetime, *, limit: int
    ) -> int:
        """Retention, bounded like ``delete_service_buckets_before``."""
        ids = (
            select(TrafficFlowCountryBucket.id)
            .where(TrafficFlowCountryBucket.window_start < cutoff)
            .limit(limit)
            .scalar_subquery()
        )
        result = await self.session.execute(
            delete(TrafficFlowCountryBucket).where(TrafficFlowCountryBucket.id.in_(ids))
        )
        return int(result.rowcount or 0)

    async def window_count(
        self, scope: GeoScope, *, since: datetime, until: datetime
    ) -> int:
        stmt = select(func.count()).where(
            *_in_range(TrafficFlowWindow, scope, since, until)
        )
        return int((await self.session.execute(stmt)).scalar_one() or 0)

    async def data_bounds(
        self, scope: GeoScope
    ) -> tuple[datetime | None, datetime | None]:
        stmt = select(
            func.min(TrafficFlowWindow.window_start),
            func.max(TrafficFlowWindow.window_start),
        ).where(*scope.conditions(TrafficFlowWindow))
        oldest, newest = (await self.session.execute(stmt)).one()
        return oldest, newest

    async def windows_looked_up(
        self, scope: GeoScope, *, since: datetime, until: datetime
    ) -> tuple[int, int]:
        """(windows looked up, of those: windows whose networks are withheld)."""
        stmt = windows_looked_up_statement(scope, since=since, until=until)
        looked_up, withheld = (await self.session.execute(stmt)).one()
        return int(looked_up or 0), int(withheld or 0)

    async def country_rows(
        self, scope: GeoScope, *, since: datetime, until: datetime
    ) -> list[GeoCountryRow]:
        stmt = country_rows_statement(scope, since=since, until=until)
        out: list[GeoCountryRow] = []
        for country, asn, name, up, down, n, *shown in (
            await self.session.execute(stmt)
        ).all():
            out.append(
                GeoCountryRow(
                    str(country),
                    int(asn),
                    name,
                    int(up),
                    int(down),
                    int(n),
                    *(int(value) for value in shown),
                )
            )
        return out


class GeoWindowWriter:
    """Ingest side. ``TrafficFlowIngestService`` calls :meth:`write_window`
    once for each window row it really inserted, so a re-pulled window adds
    nothing (and the table's unique key would refuse it anyway)."""

    def __init__(self, repository: TrafficFlowGeoRepository, lookup: GeoLookup) -> None:
        self.repository = repository
        self.lookup = lookup

    async def write_window(
        self, identity: Mapping[str, Any], destinations: Mapping[str, Sequence[int]]
    ) -> int:
        rows = geo_rows(destinations, self.lookup)
        await self.repository.insert_country_buckets(
            [{**identity, **row} for row in rows]
        )
        return len(rows)

    async def prune(self, cutoff: datetime) -> int:
        return await self.repository.delete_country_buckets_before(
            cutoff, limit=GEO_RETENTION_BATCH
        )


def _aware(moment: datetime) -> datetime:
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=UTC)


class TrafficFlowGeoService:
    def __init__(
        self,
        repository: TrafficFlowGeoRepository,
        settings: Settings,
        lookup: GeoLookup,
        *,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.repository = repository
        self.settings = settings
        self.lookup = lookup
        self.now = now

    async def by_country(
        self,
        *,
        router_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        since: datetime | None,
        until: datetime | None,
        limit: int | None = None,
        networks: int | None = None,
        organization_id: uuid.UUID | None = None,
        min_devices: int = 0,
    ) -> dict[str, Any]:
        """Same range rules and error codes as ``/summary``: a scope is
        required, and a range over 7 days is refused, never shortened.

        ``organization_id`` and ``min_devices`` are a customer caller's:
        set by ``CustomerGeoService``, never by a route."""
        if router_id is None and location_id is None:
            raise TrafficFlowError(
                "Give a router_id or a location_id.",
                code="TRAFFIC_FLOW_SCOPE_REQUIRED",
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            )
        until = _aware(until) if until else self.now()
        since = (
            _aware(since)
            if since
            else until - timedelta(seconds=DEFAULT_QUERY_WINDOW_SECONDS)
        )
        if since >= until:
            raise TrafficFlowError(
                "since must be before until.",
                code="TRAFFIC_FLOW_BAD_RANGE",
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            )
        if until - since > timedelta(days=MAX_QUERY_WINDOW_DAYS):
            raise TrafficFlowError(
                f"The range may not be longer than {MAX_QUERY_WINDOW_DAYS} days.",
                code="TRAFFIC_FLOW_WINDOW_TOO_LARGE",
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            )
        size = max(1, min(limit or DEFAULT_GEO_COUNTRIES, MAX_GEO_COUNTRIES))
        per_country = max(1, min(networks or DEFAULT_GEO_NETWORKS, MAX_GEO_NETWORKS))
        common: dict[str, Any] = {
            "geo_available": self.lookup.available,
            "source": self.lookup.describe(),
            "since": since,
            "until": until,
            "window_seconds": WINDOW_SECONDS,
            "limit": size,
            "networks": per_country,
            "networks_min_devices": max(0, int(min_devices)),
        }
        if not self.settings.traffic_flow_enabled:
            # Not a query that comes back empty and reads as "no traffic".
            return build_geo_summary(
                feature_enabled=False,
                windows=0,
                windows_measured=0,
                rows=[],
                data_oldest=None,
                data_newest=None,
                **common,
            )
        scope = GeoScope(
            router_id=router_id,
            location_id=location_id,
            organization_id=organization_id,
            min_devices=max(0, int(min_devices)),
        )
        oldest, newest = await self.repository.data_bounds(scope)
        windows = await self.repository.window_count(scope, since=since, until=until)
        looked_up, withheld = (
            await self.repository.windows_looked_up(scope, since=since, until=until)
            if windows
            else (0, 0)
        )
        rows = (
            await self.repository.country_rows(scope, since=since, until=until)
            if looked_up
            else []
        )
        return build_geo_summary(
            feature_enabled=True,
            windows=windows,
            windows_measured=min(looked_up, windows),
            rows=rows,
            data_oldest=oldest,
            data_newest=newest,
            networks_withheld_windows=withheld,
            **common,
        )


class VenueCheck(Protocol):
    async def own_location(
        self, location_id: uuid.UUID, organization_id: uuid.UUID
    ) -> uuid.UUID: ...


class CustomerGeoService:
    """The by-country read for a customer caller.

    What a customer route must never be able to leave out is fixed here, as
    in ``CustomerDestinationService``: the venue check (organisation and the
    caller's venue grants), the organisation on every statement, and the
    small-venue rule -- the Destinations threshold, applied to networks.
    Country totals are always shown: a country is too coarse to be one
    person's."""

    def __init__(self, geo: TrafficFlowGeoService, venues: VenueCheck) -> None:
        self.geo = geo
        self.venues = venues

    async def by_country(
        self,
        location_id: uuid.UUID,
        *,
        organization_id: uuid.UUID,
        since: datetime | None,
        until: datetime | None,
        limit: int | None = None,
        networks: int | None = None,
        router_id: uuid.UUID | None = None,
    ) -> dict[str, Any]:
        own = await self.venues.own_location(location_id, organization_id)
        # ``location_id=own`` is always part of the filter. A ``router_id``
        # only narrows within it: a router of another venue matches no row.
        data = await self.geo.by_country(
            router_id=router_id,
            location_id=own,
            since=since,
            until=until,
            limit=limit,
            networks=networks,
            organization_id=organization_id,
            min_devices=CUSTOMER_MIN_DEVICES_FOR_DESTINATIONS,
        )
        # The platform switch is not a customer's to know about.
        data.pop("feature_enabled", None)
        return {"location_id": str(own), **data}
