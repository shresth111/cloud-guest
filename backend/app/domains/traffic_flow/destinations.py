"""Destinations: search, CSV download and the service drill-down.

Reads ``traffic_flow_dest_buckets`` (``destination_buckets.py``): one
row per (router, 5-minute window, outside address, protocol, outside port).
Everything here is venue-level and device-free. No statement in this module
selects a device address, a MAC, a guest or a session, and no response model
has such a field (``tests/unit/test_traffic_flow_destinations.py`` asserts
both).

Three reads, each of which writes an audit row:

* :meth:`DestinationService.search` -- one capped page of records for a
  venue and range, filtered and sorted in the database, with the number of
  matching records and the database time.
* :meth:`DestinationService.export_csv` -- the same filters as a CSV.
* :meth:`DestinationService.service_destinations` -- for one service
  (protocol and outside port), its top outside addresses with shares.

Two things a caller can never widen from the request:

* ``organization_id`` -- when given (a customer caller), the venue must
  belong to it, and every statement also filters on the scoping column.
* ``min_devices`` -- when above zero (a customer caller), a window in which
  fewer devices were seen contributes nothing at all. Only that one *count*
  per window is read from ``traffic_flow_windows``; no device is.

Accuracy, which every response states rather than leaves to the reader:
per window only the top ``TOP_DESTINATION_SERVICES_STORED`` triples are
kept and the rest is an explicit "other" row per protocol. So per-address
figures over a range are lower bounds, while sums that include the "other"
rows are exact.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from fastapi import status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import and_, cast, exists, func, literal, not_, select
from sqlalchemy.dialects.postgresql import CIDR
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.logging import get_logger
from app.domains.location.models import Location

from .constants import (
    DEFAULT_LIST_LIMIT,
    DEFAULT_QUERY_WINDOW_SECONDS,
    MAX_LIST_LIMIT,
    MAX_QUERY_WINDOW_DAYS,
    OTHER_SERVICE_PORT,
    RETENTION_DAYS,
    WINDOW_SECONDS,
)
from .destination_buckets import (
    TOP_DESTINATION_SERVICES_STORED,
    TrafficFlowDestinationBucket,
)
from .models import TrafficFlowServiceBucket, TrafficFlowWindow
from .service import TrafficFlowError
from .summary import protocol_name, service_name

logger = get_logger(__name__)

__all__ = [
    "AUDIT_ACTION_DESTINATIONS_EXPORTED",
    "AUDIT_ACTION_DESTINATIONS_SEARCHED",
    "AUDIT_ACTION_SERVICE_DESTINATIONS_VIEWED",
    "CSV_COLUMNS",
    "DESTINATION_CSV_MAX_ROWS",
    "DESTINATION_SEARCH_LIMIT",
    "RESPONSE_MODELS",
    "CsvExport",
    "DestinationFilters",
    "DestinationRepository",
    "DestinationScope",
    "DestinationSearchResponse",
    "DestinationService",
    "ServiceDestinationsResponse",
    "parse_filters",
    "resolve_range",
]

#: Records on the one page a search returns. There is no second page.
DESTINATION_SEARCH_LIMIT = 1000
#: Records in one CSV download. Built in memory on a small server, so
#: bounded; a cut download is said in a response header.
DESTINATION_CSV_MAX_ROWS = 50_000
#: A range may start this much before the retention edge: the screen
#: computes "7 days ago" on a clock that is not the server's.
RETENTION_SLACK = timedelta(minutes=15)

AUDIT_ACTION_DESTINATIONS_SEARCHED = "traffic_flow_destinations_searched"
AUDIT_ACTION_DESTINATIONS_EXPORTED = "traffic_flow_destinations_exported"
AUDIT_ACTION_SERVICE_DESTINATIONS_VIEWED = "traffic_flow_service_destinations_viewed"

DIRECTIONS = ("any", "up", "down")
SORT_KEYS = (
    "time",
    "address",
    "protocol",
    "port",
    "bytes",
    "bytes_up",
    "bytes_down",
    "flows",
)
ORDERS = ("desc", "asc")

CSV_COLUMNS = (
    "window_start",
    "window_end",
    "remote_address",
    "protocol",
    "protocol_name",
    "remote_port",
    "service_name",
    "bytes_up",
    "bytes_down",
    "flows",
)


# ---------------------------------------------------------------------------
# request side: range, filters, scope
# ---------------------------------------------------------------------------


def _bad_filter(field: str, message: str) -> TrafficFlowError:
    error = TrafficFlowError(
        message,
        code="TRAFFIC_FLOW_BAD_FILTER",
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
    )
    error.data["field"] = field
    return error


def _aware(moment: datetime) -> datetime:
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=UTC)


def resolve_range(
    since: datetime | None, until: datetime | None, *, now: datetime
) -> tuple[datetime, datetime]:
    """The range a request means, or a refusal. Never a silently shortened
    range: that would be read as the whole range that was asked for."""
    end = _aware(until) if until else now
    start = (
        _aware(since)
        if since
        else end - timedelta(seconds=DEFAULT_QUERY_WINDOW_SECONDS)
    )
    if start >= end:
        raise TrafficFlowError(
            "since must be before until.",
            code="TRAFFIC_FLOW_BAD_RANGE",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
    if end - start > timedelta(days=MAX_QUERY_WINDOW_DAYS):
        raise TrafficFlowError(
            f"The range may not be longer than {MAX_QUERY_WINDOW_DAYS} days.",
            code="TRAFFIC_FLOW_WINDOW_TOO_LARGE",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
    earliest = now - timedelta(days=RETENTION_DAYS)
    if start < earliest - RETENTION_SLACK:
        error = TrafficFlowError(
            f"Traffic data is kept for {RETENTION_DAYS} days. The range may "
            f"not start before {earliest.isoformat(timespec='minutes')}.",
            code="TRAFFIC_FLOW_RANGE_OUTSIDE_RETENTION",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
        error.data["earliest"] = earliest.isoformat()
        raise error
    return start, end


@dataclass(frozen=True, slots=True)
class DestinationFilters:
    #: An outside address is the one-address network (/32 or /128).
    address: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
    protocol: int | None = None
    port: int | None = None
    direction: str = "any"

    @property
    def address_text(self) -> str | None:
        if self.address is None:
            return None
        if self.address.prefixlen == self.address.max_prefixlen:
            return str(self.address.network_address)
        return str(self.address)

    def as_dict(self) -> dict[str, Any]:
        return {
            "address": self.address_text,
            "protocol": self.protocol,
            "port": self.port,
            "direction": self.direction,
        }

    @property
    def unlisted_is_knowable(self) -> bool:
        """The "other" rows carry a protocol and nothing else, so how much
        of them would match an address, port or direction filter cannot be
        said."""
        return self.address is None and self.port is None and self.direction == "any"


def parse_filters(
    *,
    address: str | None = None,
    protocol: int | None = None,
    port: int | None = None,
    direction: str | None = None,
) -> DestinationFilters:
    network = None
    if address is not None and address.strip():
        try:
            network = ipaddress.ip_network(address.strip(), strict=False)
        except ValueError as exc:
            raise _bad_filter(
                "address",
                "address must be an IP address or a prefix such as 203.0.113.0/24.",
            ) from exc
    if protocol is not None and not 0 <= protocol <= 255:
        raise _bad_filter("protocol", "protocol must be between 0 and 255.")
    if port is not None and not 0 <= port <= 65535:
        raise _bad_filter("port", "port must be between 0 and 65535.")
    chosen = (direction or "any").strip().lower()
    if chosen not in DIRECTIONS:
        raise _bad_filter("direction", "direction must be any, up or down.")
    return DestinationFilters(
        address=network, protocol=protocol, port=port, direction=chosen
    )


def _parse_sort(sort: str | None, order: str | None) -> tuple[str, str]:
    key = (sort or "time").strip().lower()
    if key not in SORT_KEYS:
        raise _bad_filter("sort", "sort must be one of: " + ", ".join(SORT_KEYS) + ".")
    way = (order or "desc").strip().lower()
    if way not in ORDERS:
        raise _bad_filter("order", "order must be desc or asc.")
    return key, way


@dataclass(frozen=True, slots=True)
class DestinationScope:
    """Whose records a statement may read. Built by the service from the
    route's own venue check, never from request filters."""

    location_id: uuid.UUID
    router_id: uuid.UUID | None = None
    #: The caller's organisation on a customer route; ``None`` for Master.
    organization_id: uuid.UUID | None = None
    #: Small-venue rule. 0 (Master) withholds nothing.
    min_devices: int = 0

    def conditions(self, model: Any) -> list[Any]:
        out: list[Any] = [model.location_id == self.location_id]
        if self.router_id is not None:
            out.append(model.router_id == self.router_id)
        if self.organization_id is not None:
            out.append(model.organization_id == self.organization_id)
        return out

    def visible(self, model: Any) -> list[Any]:
        """Rows of ``model`` (a per-window bucket table) whose window had
        enough devices. Fails closed: a bucket whose window row is missing
        is not shown. Reads ``talker_count`` -- a count -- and nothing else
        of the window."""
        if self.min_devices <= 0:
            return []
        window = TrafficFlowWindow
        return [
            exists().where(
                window.router_id == model.router_id,
                window.source == model.source,
                window.window_start == model.window_start,
                window.talker_count >= self.min_devices,
            )
        ]


# ---------------------------------------------------------------------------
# statements (module-level so they can be compiled without a database)
# ---------------------------------------------------------------------------

_BUCKET = TrafficFlowDestinationBucket


def _in_range(model: Any, since: datetime, until: datetime) -> list[Any]:
    return [model.window_start >= since, model.window_start < until]


def matching_records(
    scope: DestinationScope,
    filters: DestinationFilters,
    *,
    since: datetime,
    until: datetime,
) -> Any:
    """Records matching the filters, one per (window, outside address,
    protocol, port) for the venue: several routers of one venue are added
    together. "Other" rows are never a record."""
    conditions = [
        *_in_range(_BUCKET, since, until),
        *scope.conditions(_BUCKET),
        *scope.visible(_BUCKET),
        _BUCKET.remote_port != OTHER_SERVICE_PORT,
    ]
    if filters.address is not None:
        conditions.append(
            _BUCKET.remote_address.op("<<=")(cast(literal(str(filters.address)), CIDR))
        )
    if filters.protocol is not None:
        conditions.append(_BUCKET.protocol == filters.protocol)
    if filters.port is not None:
        conditions.append(_BUCKET.remote_port == filters.port)
    bytes_up = func.sum(_BUCKET.bytes_up)
    bytes_down = func.sum(_BUCKET.bytes_down)
    statement = (
        select(
            _BUCKET.window_start.label("window_start"),
            func.max(_BUCKET.window_seconds).label("window_seconds"),
            _BUCKET.remote_address.label("remote_address"),
            _BUCKET.protocol.label("protocol"),
            _BUCKET.remote_port.label("remote_port"),
            bytes_up.label("bytes_up"),
            bytes_down.label("bytes_down"),
            func.sum(_BUCKET.flows).label("flows"),
        )
        .where(*conditions)
        .group_by(
            _BUCKET.window_start,
            _BUCKET.remote_address,
            _BUCKET.protocol,
            _BUCKET.remote_port,
        )
    )
    if filters.direction == "up":
        statement = statement.having(bytes_up > 0)
    elif filters.direction == "down":
        statement = statement.having(bytes_down > 0)
    return statement


def search_page_statement(
    scope: DestinationScope,
    filters: DestinationFilters,
    *,
    since: datetime,
    until: datetime,
    sort: str,
    order: str,
    limit: int,
) -> Any:
    records = matching_records(scope, filters, since=since, until=until).subquery()
    c = records.c
    total_bytes = c.bytes_up + c.bytes_down
    column = {
        "time": c.window_start,
        "address": c.remote_address,
        "protocol": c.protocol,
        "port": c.remote_port,
        "bytes": total_bytes,
        "bytes_up": c.bytes_up,
        "bytes_down": c.bytes_down,
        "flows": c.flows,
    }[sort]
    primary = column.asc() if order == "asc" else column.desc()
    # A total order, so the same search returns the same page every time.
    return (
        select(records)
        .order_by(
            primary,
            c.window_start.desc(),
            total_bytes.desc(),
            c.remote_address,
            c.protocol,
            c.remote_port,
        )
        .limit(limit)
    )


def search_totals_statement(
    scope: DestinationScope,
    filters: DestinationFilters,
    *,
    since: datetime,
    until: datetime,
) -> Any:
    records = matching_records(scope, filters, since=since, until=until).subquery()
    c = records.c
    return select(
        func.count(),
        func.coalesce(func.sum(c.bytes_up), 0),
        func.coalesce(func.sum(c.bytes_down), 0),
        func.coalesce(func.sum(c.flows), 0),
    ).select_from(records)


def unlisted_statement(
    scope: DestinationScope,
    *,
    since: datetime,
    until: datetime,
    protocol: int | None,
) -> Any:
    """Traffic outside each window's stored top: the "other" rows."""
    conditions = [
        *_in_range(_BUCKET, since, until),
        *scope.conditions(_BUCKET),
        *scope.visible(_BUCKET),
        _BUCKET.remote_port == OTHER_SERVICE_PORT,
    ]
    if protocol is not None:
        conditions.append(_BUCKET.protocol == protocol)
    return select(
        func.coalesce(func.sum(_BUCKET.bytes_up), 0),
        func.coalesce(func.sum(_BUCKET.bytes_down), 0),
        func.coalesce(func.sum(_BUCKET.flows), 0),
    ).where(*conditions)


def window_stats_statement(
    scope: DestinationScope, *, since: datetime, until: datetime
) -> Any:
    """How many windows the range has, how many carry destination records,
    and how many the small-venue rule withholds. Three counts; no list of
    the window is read."""
    window = TrafficFlowWindow
    withheld = (
        func.count().filter(window.talker_count < scope.min_devices)
        if scope.min_devices > 0
        else literal(0)
    )
    return select(
        func.count(),
        func.count().filter(window.services_measured.is_(True)),
        withheld,
    ).where(*_in_range(window, since, until), *scope.conditions(window))


def data_bounds_statement(scope: DestinationScope) -> Any:
    window = TrafficFlowWindow
    return select(func.min(window.window_start), func.max(window.window_start)).where(
        *scope.conditions(window)
    )


def service_total_statement(
    scope: DestinationScope,
    *,
    since: datetime,
    until: datetime,
    protocol: int,
    port: int,
) -> Any:
    """The service's own total from the service buckets -- the figure the
    services list shows -- and in how many windows the service may have been
    folded into that window's "other" row (then the total is a lower
    bound)."""
    bucket = TrafficFlowServiceBucket
    is_service = bucket.remote_port == port
    per_window = (
        select(
            func.coalesce(func.sum(bucket.bytes_up).filter(is_service), 0).label("up"),
            func.coalesce(func.sum(bucket.bytes_down).filter(is_service), 0).label(
                "down"
            ),
            func.coalesce(func.sum(bucket.flows).filter(is_service), 0).label("flows"),
            func.bool_or(is_service).label("has_service"),
            func.bool_or(bucket.remote_port == OTHER_SERVICE_PORT).label("has_other"),
        )
        .where(
            *_in_range(bucket, since, until),
            *scope.conditions(bucket),
            *scope.visible(bucket),
            bucket.protocol == protocol,
            bucket.remote_port.in_((port, OTHER_SERVICE_PORT)),
        )
        .group_by(bucket.router_id, bucket.source, bucket.window_start)
        .subquery()
    )
    c = per_window.c
    return select(
        func.coalesce(func.sum(c.up), 0),
        func.coalesce(func.sum(c.down), 0),
        func.coalesce(func.sum(c.flows), 0),
        func.count().filter(and_(c.has_other, not_(c.has_service))),
    ).select_from(per_window)


def _service_destinations(
    scope: DestinationScope,
    *,
    since: datetime,
    until: datetime,
    protocol: int,
    port: int,
) -> Any:
    return (
        select(
            _BUCKET.remote_address.label("remote_address"),
            func.sum(_BUCKET.bytes_up).label("bytes_up"),
            func.sum(_BUCKET.bytes_down).label("bytes_down"),
            func.sum(_BUCKET.flows).label("flows"),
        )
        .where(
            *_in_range(_BUCKET, since, until),
            *scope.conditions(_BUCKET),
            *scope.visible(_BUCKET),
            _BUCKET.protocol == protocol,
            _BUCKET.remote_port == port,
        )
        .group_by(_BUCKET.remote_address)
        .subquery()
    )


def service_destinations_statement(
    scope: DestinationScope,
    *,
    since: datetime,
    until: datetime,
    protocol: int,
    port: int,
    limit: int,
) -> Any:
    listed = _service_destinations(
        scope, since=since, until=until, protocol=protocol, port=port
    )
    c = listed.c
    return (
        select(listed)
        .order_by((c.bytes_up + c.bytes_down).desc(), c.remote_address)
        .limit(limit)
    )


def service_destination_totals_statement(
    scope: DestinationScope,
    *,
    since: datetime,
    until: datetime,
    protocol: int,
    port: int,
) -> Any:
    listed = _service_destinations(
        scope, since=since, until=until, protocol=protocol, port=port
    )
    c = listed.c
    return select(
        func.count(),
        func.coalesce(func.sum(c.bytes_up), 0),
        func.coalesce(func.sum(c.bytes_down), 0),
        func.coalesce(func.sum(c.flows), 0),
    ).select_from(listed)


# ---------------------------------------------------------------------------
# repository
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RecordRow:
    window_start: datetime
    window_seconds: int
    remote_address: str
    protocol: int
    remote_port: int
    bytes_up: int
    bytes_down: int
    flows: int


@dataclass(frozen=True, slots=True)
class Totals:
    count: int = 0
    bytes_up: int = 0
    bytes_down: int = 0
    flows: int = 0

    @property
    def bytes(self) -> int:
        return self.bytes_up + self.bytes_down


@dataclass(frozen=True, slots=True)
class WindowStats:
    windows: int = 0
    measured: int = 0
    withheld: int = 0


@dataclass(frozen=True, slots=True)
class ServiceTotal:
    bytes_up: int = 0
    bytes_down: int = 0
    flows: int = 0
    #: Windows in which the service may sit in the "other" service row.
    windows_maybe_folded: int = 0


@dataclass(frozen=True, slots=True)
class AddressRow:
    remote_address: str
    bytes_up: int
    bytes_down: int
    flows: int


@dataclass(frozen=True, slots=True)
class Venue:
    location_id: uuid.UUID
    organization_id: uuid.UUID | None


class DestinationRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def venue(self, location_id: uuid.UUID) -> Venue | None:
        row = (
            await self.session.execute(
                select(Location.id, Location.organization_id).where(
                    Location.id == location_id, Location.is_deleted.is_(False)
                )
            )
        ).first()
        return Venue(location_id=row[0], organization_id=row[1]) if row else None

    async def window_stats(
        self, scope: DestinationScope, *, since: datetime, until: datetime
    ) -> WindowStats:
        row = (
            await self.session.execute(
                window_stats_statement(scope, since=since, until=until)
            )
        ).one()
        return WindowStats(int(row[0] or 0), int(row[1] or 0), int(row[2] or 0))

    async def data_bounds(
        self, scope: DestinationScope
    ) -> tuple[datetime | None, datetime | None]:
        oldest, newest = (
            await self.session.execute(data_bounds_statement(scope))
        ).one()
        return oldest, newest

    async def search_page(
        self,
        scope: DestinationScope,
        filters: DestinationFilters,
        *,
        since: datetime,
        until: datetime,
        sort: str,
        order: str,
        limit: int,
    ) -> list[RecordRow]:
        statement = search_page_statement(
            scope,
            filters,
            since=since,
            until=until,
            sort=sort,
            order=order,
            limit=limit,
        )
        return [
            RecordRow(
                window_start=row.window_start,
                window_seconds=int(row.window_seconds),
                remote_address=str(row.remote_address),
                protocol=int(row.protocol),
                remote_port=int(row.remote_port),
                bytes_up=int(row.bytes_up),
                bytes_down=int(row.bytes_down),
                flows=int(row.flows),
            )
            for row in (await self.session.execute(statement)).all()
        ]

    async def search_totals(
        self,
        scope: DestinationScope,
        filters: DestinationFilters,
        *,
        since: datetime,
        until: datetime,
    ) -> Totals:
        row = (
            await self.session.execute(
                search_totals_statement(scope, filters, since=since, until=until)
            )
        ).one()
        return Totals(int(row[0]), int(row[1]), int(row[2]), int(row[3]))

    async def unlisted(
        self,
        scope: DestinationScope,
        *,
        since: datetime,
        until: datetime,
        protocol: int | None,
    ) -> Totals:
        row = (
            await self.session.execute(
                unlisted_statement(scope, since=since, until=until, protocol=protocol)
            )
        ).one()
        return Totals(0, int(row[0]), int(row[1]), int(row[2]))

    async def service_total(
        self,
        scope: DestinationScope,
        *,
        since: datetime,
        until: datetime,
        protocol: int,
        port: int,
    ) -> ServiceTotal:
        row = (
            await self.session.execute(
                service_total_statement(
                    scope, since=since, until=until, protocol=protocol, port=port
                )
            )
        ).one()
        return ServiceTotal(int(row[0]), int(row[1]), int(row[2]), int(row[3]))

    async def service_destinations(
        self,
        scope: DestinationScope,
        *,
        since: datetime,
        until: datetime,
        protocol: int,
        port: int,
        limit: int,
    ) -> list[AddressRow]:
        statement = service_destinations_statement(
            scope, since=since, until=until, protocol=protocol, port=port, limit=limit
        )
        return [
            AddressRow(
                remote_address=str(row.remote_address),
                bytes_up=int(row.bytes_up),
                bytes_down=int(row.bytes_down),
                flows=int(row.flows),
            )
            for row in (await self.session.execute(statement)).all()
        ]

    async def service_destination_totals(
        self,
        scope: DestinationScope,
        *,
        since: datetime,
        until: datetime,
        protocol: int,
        port: int,
    ) -> Totals:
        row = (
            await self.session.execute(
                service_destination_totals_statement(
                    scope, since=since, until=until, protocol=protocol, port=port
                )
            )
        ).one()
        return Totals(int(row[0]), int(row[1]), int(row[2]), int(row[3]))


# ---------------------------------------------------------------------------
# response models
# ---------------------------------------------------------------------------


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ByteTotals(_Model):
    bytes_up: int
    bytes_down: int
    bytes: int
    flows: int


class FiltersOut(_Model):
    address: str | None
    protocol: int | None
    port: int | None
    direction: str


class DestinationRecord(_Model):
    """This venue, this window, this outside address and service. No field
    says which device."""

    window_start: str
    window_end: str
    address: str
    protocol: int
    protocol_name: str
    port: int
    service_name: str | None
    bytes_up: int
    bytes_down: int
    bytes: int
    flows: int


class _RangeModel(_Model):
    feature_enabled: bool
    measured: bool
    location_id: str
    router_id: str | None
    since: str
    until: str
    window_seconds: int
    windows: int
    windows_measured: int
    data_oldest: str | None
    data_newest: str | None
    per_window_top_n: int
    #: The small-venue threshold in force, or ``None`` when nothing is
    #: withheld (Master). A threshold, not an identifier.
    min_devices: int | None
    windows_withheld: int


class DestinationSearchResponse(_RangeModel):
    retention_days: int
    filters: FiltersOut
    sort: str
    order: str
    limit: int
    total: int
    returned: int
    truncated: bool
    query_ms: int
    totals: ByteTotals | None
    unlisted: ByteTotals | None
    rows: list[DestinationRecord]


class ServiceOut(ByteTotals):
    protocol: int
    protocol_name: str
    port: int
    service_name: str | None
    exact: bool


class ServiceDestinationItem(_Model):
    address: str
    bytes_up: int
    bytes_down: int
    bytes: int
    flows: int
    share: float


class ServiceDestinationsResponse(_RangeModel):
    service: ServiceOut | None
    lower_bound: bool
    destinations_listed: int
    listed_bytes: int
    unlisted_bytes: int
    unlisted_share: float
    items: list[ServiceDestinationItem]


#: Every model a route in this change can return, for the privacy test.
RESPONSE_MODELS: tuple[type[BaseModel], ...] = (
    DestinationSearchResponse,
    ServiceDestinationsResponse,
    DestinationRecord,
    ServiceDestinationItem,
    ServiceOut,
    ByteTotals,
    FiltersOut,
)


@dataclass(frozen=True, slots=True)
class CsvExport:
    text: str
    filename: str
    total: int
    rows: int
    truncated: bool


# ---------------------------------------------------------------------------
# service
# ---------------------------------------------------------------------------


class AuditWriter(Protocol):
    async def create_audit_log_entry(self, **kwargs: Any) -> Any: ...


def _iso(moment: datetime | None) -> str | None:
    return moment.isoformat() if moment else None


def _share(part: int, whole: int) -> float:
    return round(part / whole, 4) if whole > 0 else 0.0


def _byte_totals(totals: Totals) -> ByteTotals:
    return ByteTotals(
        bytes_up=totals.bytes_up,
        bytes_down=totals.bytes_down,
        bytes=totals.bytes,
        flows=totals.flows,
    )


def _record(row: RecordRow) -> DestinationRecord:
    return DestinationRecord(
        window_start=row.window_start.isoformat(),
        window_end=(
            row.window_start + timedelta(seconds=row.window_seconds)
        ).isoformat(),
        address=row.remote_address,
        protocol=row.protocol,
        protocol_name=protocol_name(row.protocol),
        port=row.remote_port,
        service_name=service_name(row.remote_port),
        bytes_up=row.bytes_up,
        bytes_down=row.bytes_down,
        bytes=row.bytes_up + row.bytes_down,
        flows=row.flows,
    )


def records_csv(rows: list[RecordRow]) -> str:
    """The download. One line per record, the columns of ``CSV_COLUMNS``.
    Every cell is a timestamp, an address, a number or a name from a fixed
    table, so there is nothing a spreadsheet could run as a formula."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for row in rows:
        writer.writerow(
            (
                row.window_start.isoformat(),
                (row.window_start + timedelta(seconds=row.window_seconds)).isoformat(),
                row.remote_address,
                row.protocol,
                protocol_name(row.protocol),
                row.remote_port,
                service_name(row.remote_port) or "",
                row.bytes_up,
                row.bytes_down,
                row.flows,
            )
        )
    return buffer.getvalue()


@dataclass(frozen=True, slots=True)
class _Request:
    """A request after the checks every read shares."""

    venue: Venue
    scope: DestinationScope
    since: datetime
    until: datetime
    actor_user_id: uuid.UUID | None


class DestinationService:
    def __init__(
        self,
        repository: DestinationRepository,
        settings: Settings,
        *,
        audit_writer: AuditWriter,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.repository = repository
        self.settings = settings
        # Not optional: there is no unaudited way to read these records.
        self.audit_writer = audit_writer
        self.now = now

    # -- shared -----------------------------------------------------------
    async def _prepare(
        self,
        *,
        location_id: uuid.UUID,
        router_id: uuid.UUID | None,
        since: datetime | None,
        until: datetime | None,
        actor_user_id: uuid.UUID | None,
        organization_id: uuid.UUID | None,
        min_devices: int,
    ) -> _Request:
        start, end = resolve_range(since, until, now=self.now())
        venue = await self.repository.venue(location_id)
        if venue is None or (
            organization_id is not None and venue.organization_id != organization_id
        ):
            # Another organisation's venue reads exactly like one that does
            # not exist.
            raise TrafficFlowError(
                "Venue not found.",
                code="TRAFFIC_FLOW_VENUE_NOT_FOUND",
                status_code=status.HTTP_404_NOT_FOUND,
            )
        return _Request(
            venue=venue,
            scope=DestinationScope(
                location_id=venue.location_id,
                router_id=router_id,
                organization_id=organization_id,
                min_devices=max(0, int(min_devices)),
            ),
            since=start,
            until=end,
            actor_user_id=actor_user_id,
        )

    async def _audit(
        self,
        request: _Request,
        *,
        action: str,
        what: str,
        row_count: int,
        details: dict[str, Any],
    ) -> None:
        scope = request.scope
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=request.actor_user_id,
            action=action,
            entity_type="location",
            entity_id=scope.location_id,
            description=(
                f"Traffic Lens {what} for venue {scope.location_id}: "
                f"{row_count} record(s)"
            ),
            event_metadata={
                "console": "customer" if scope.organization_id else "master",
                "router_id": str(scope.router_id) if scope.router_id else None,
                "since": request.since.isoformat(),
                "until": request.until.isoformat(),
                "row_count": row_count,
                **details,
            },
            organization_id=request.venue.organization_id,
            location_id=scope.location_id,
        )
        logger.info(
            action,
            extra={
                "location_id": str(scope.location_id),
                "row_count": row_count,
                "console": "customer" if scope.organization_id else "master",
            },
        )

    async def _range_fields(self, request: _Request) -> dict[str, Any]:
        """The fields both responses share. Reads nothing while the feature
        is off: an empty table would read as "no traffic"."""
        scope = request.scope
        enabled = bool(self.settings.traffic_flow_enabled)
        stats = WindowStats()
        oldest: datetime | None = None
        newest: datetime | None = None
        if enabled:
            stats = await self.repository.window_stats(
                scope, since=request.since, until=request.until
            )
            oldest, newest = await self.repository.data_bounds(scope)
        return {
            "feature_enabled": enabled,
            "measured": stats.windows > 0,
            "location_id": str(scope.location_id),
            "router_id": str(scope.router_id) if scope.router_id else None,
            "since": request.since.isoformat(),
            "until": request.until.isoformat(),
            "window_seconds": WINDOW_SECONDS,
            "windows": stats.windows,
            "windows_measured": stats.measured,
            "data_oldest": _iso(oldest),
            "data_newest": _iso(newest),
            "per_window_top_n": TOP_DESTINATION_SERVICES_STORED,
            "min_devices": scope.min_devices or None,
            "windows_withheld": stats.withheld,
        }

    # -- search -----------------------------------------------------------
    async def search(
        self,
        *,
        location_id: uuid.UUID,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        address: str | None = None,
        protocol: int | None = None,
        port: int | None = None,
        direction: str | None = None,
        sort: str | None = None,
        order: str | None = None,
        organization_id: uuid.UUID | None = None,
        min_devices: int = 0,
    ) -> DestinationSearchResponse:
        filters = parse_filters(
            address=address, protocol=protocol, port=port, direction=direction
        )
        sort_key, sort_order = _parse_sort(sort, order)
        request = await self._prepare(
            location_id=location_id,
            router_id=router_id,
            since=since,
            until=until,
            actor_user_id=actor_user_id,
            organization_id=organization_id,
            min_devices=min_devices,
        )
        fields = await self._range_fields(request)
        rows: list[RecordRow] = []
        totals: Totals | None = None
        unlisted: Totals | None = None
        query_ms = 0
        if fields["measured"]:
            started = time.perf_counter()
            totals = await self.repository.search_totals(
                request.scope, filters, since=request.since, until=request.until
            )
            rows = await self.repository.search_page(
                request.scope,
                filters,
                since=request.since,
                until=request.until,
                sort=sort_key,
                order=sort_order,
                limit=DESTINATION_SEARCH_LIMIT,
            )
            if filters.unlisted_is_knowable:
                unlisted = await self.repository.unlisted(
                    request.scope,
                    since=request.since,
                    until=request.until,
                    protocol=filters.protocol,
                )
            query_ms = int((time.perf_counter() - started) * 1000)
        total = totals.count if totals else 0
        await self._audit(
            request,
            action=AUDIT_ACTION_DESTINATIONS_SEARCHED,
            what="destination search",
            row_count=total,
            details={
                "filters": filters.as_dict(),
                "sort": sort_key,
                "order": sort_order,
                "returned": len(rows),
            },
        )
        return DestinationSearchResponse(
            **fields,
            retention_days=RETENTION_DAYS,
            filters=FiltersOut(**filters.as_dict()),
            sort=sort_key,
            order=sort_order,
            limit=DESTINATION_SEARCH_LIMIT,
            total=total,
            returned=len(rows),
            truncated=total > len(rows),
            query_ms=query_ms,
            totals=_byte_totals(totals) if totals else None,
            unlisted=_byte_totals(unlisted) if unlisted else None,
            rows=[_record(row) for row in rows],
        )

    # -- download ---------------------------------------------------------
    async def export_csv(
        self,
        *,
        location_id: uuid.UUID,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        address: str | None = None,
        protocol: int | None = None,
        port: int | None = None,
        direction: str | None = None,
        sort: str | None = None,
        order: str | None = None,
        organization_id: uuid.UUID | None = None,
        min_devices: int = 0,
    ) -> CsvExport:
        filters = parse_filters(
            address=address, protocol=protocol, port=port, direction=direction
        )
        sort_key, sort_order = _parse_sort(sort, order)
        request = await self._prepare(
            location_id=location_id,
            router_id=router_id,
            since=since,
            until=until,
            actor_user_id=actor_user_id,
            organization_id=organization_id,
            min_devices=min_devices,
        )
        rows: list[RecordRow] = []
        total = 0
        if self.settings.traffic_flow_enabled:
            total = (
                await self.repository.search_totals(
                    request.scope, filters, since=request.since, until=request.until
                )
            ).count
            if total:
                rows = await self.repository.search_page(
                    request.scope,
                    filters,
                    since=request.since,
                    until=request.until,
                    sort=sort_key,
                    order=sort_order,
                    limit=DESTINATION_CSV_MAX_ROWS,
                )
        await self._audit(
            request,
            action=AUDIT_ACTION_DESTINATIONS_EXPORTED,
            what="destination download",
            row_count=len(rows),
            details={
                "filters": filters.as_dict(),
                "sort": sort_key,
                "order": sort_order,
                "total": total,
                "truncated": total > len(rows),
            },
        )
        stamp = "%Y%m%dT%H%MZ"
        return CsvExport(
            text=records_csv(rows),
            filename=(
                "traffic-lens-destinations-"
                f"{request.since.astimezone(UTC).strftime(stamp)}-"
                f"{request.until.astimezone(UTC).strftime(stamp)}.csv"
            ),
            total=total,
            rows=len(rows),
            truncated=total > len(rows),
        )

    # -- drill-down -------------------------------------------------------
    async def service_destinations(
        self,
        *,
        location_id: uuid.UUID,
        actor_user_id: uuid.UUID | None,
        protocol: int,
        port: int,
        router_id: uuid.UUID | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int | None = None,
        organization_id: uuid.UUID | None = None,
        min_devices: int = 0,
    ) -> ServiceDestinationsResponse:
        chosen = parse_filters(protocol=protocol, port=port)
        assert chosen.protocol is not None and chosen.port is not None  # noqa: S101
        size = max(1, min(limit or DEFAULT_LIST_LIMIT, MAX_LIST_LIMIT))
        request = await self._prepare(
            location_id=location_id,
            router_id=router_id,
            since=since,
            until=until,
            actor_user_id=actor_user_id,
            organization_id=organization_id,
            min_devices=min_devices,
        )
        fields = await self._range_fields(request)
        service: ServiceOut | None = None
        items: list[ServiceDestinationItem] = []
        listed = Totals()
        unlisted_bytes = 0
        if fields["measured"]:
            where = {
                "since": request.since,
                "until": request.until,
                "protocol": chosen.protocol,
                "port": chosen.port,
            }
            own = await self.repository.service_total(request.scope, **where)
            listed = await self.repository.service_destination_totals(
                request.scope, **where
            )
            rows = await self.repository.service_destinations(
                request.scope, **where, limit=size
            )
            exact = own.windows_maybe_folded == 0
            up, down, flows = own.bytes_up, own.bytes_down, own.flows
            if listed.bytes > up + down:
                # Only possible when the service was folded into "other" in
                # the service buckets while one of its destinations was
                # still listed here. Both are lower bounds; use the larger.
                up, down, flows = listed.bytes_up, listed.bytes_down, listed.flows
                exact = False
            whole = up + down
            unlisted_bytes = max(0, whole - listed.bytes)
            service = ServiceOut(
                protocol=chosen.protocol,
                protocol_name=protocol_name(chosen.protocol),
                port=chosen.port,
                service_name=service_name(chosen.port),
                bytes_up=up,
                bytes_down=down,
                bytes=whole,
                flows=flows,
                exact=exact,
            )
            items = [
                ServiceDestinationItem(
                    address=row.remote_address,
                    bytes_up=row.bytes_up,
                    bytes_down=row.bytes_down,
                    bytes=row.bytes_up + row.bytes_down,
                    flows=row.flows,
                    share=_share(row.bytes_up + row.bytes_down, whole),
                )
                for row in rows
            ]
        await self._audit(
            request,
            action=AUDIT_ACTION_SERVICE_DESTINATIONS_VIEWED,
            what="service drill-down",
            row_count=len(items),
            details={
                "service": {"protocol": chosen.protocol, "port": chosen.port},
                "limit": size,
            },
        )
        return ServiceDestinationsResponse(
            **fields,
            service=service,
            lower_bound=True,
            destinations_listed=listed.count,
            listed_bytes=listed.bytes,
            unlisted_bytes=unlisted_bytes,
            unlisted_share=_share(unlisted_bytes, service.bytes if service else 0),
            items=items,
        )
