"""Traffic flow: destination buckets, the Destinations search and download,
and the service drill-down.

Everything under test is venue-level and device-free: a record says which
outside address and service a *venue* exchanged bytes with in a 5-minute
window, never which device did. ``TestNoDeviceAnywhere`` holds that line for
the table, the response models, the statements and real responses.

Two backends run the behaviour tests (``backend`` fixture):

* ``memory`` -- always. A small Python model of the three tables. It checks
  the service layer for real (cap, total, range, scoping, withholding,
  audit) and states what each filter must return.
* ``postgres`` -- only when ``TRAFFIC_FLOW_TEST_DSN`` names a scratch
  database (CI has no database server, so it is skipped there). It builds
  the tables from the real migrations and runs the real statements against
  the same expectations. Without it, the SQL is checked only as compiled
  text (``TestStatements``).
"""

from __future__ import annotations

import csv
import importlib.util
import io
import ipaddress
import os
import pathlib
import re
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.domains.rbac.enums import ScopeType
from app.domains.traffic_flow import destinations as dest
from app.domains.traffic_flow.constants import OTHER_SERVICE_PORT
from app.domains.traffic_flow.destination_buckets import (
    OTHER_DESTINATION_ADDRESS,
    TOP_DESTINATION_SERVICES_STORED,
    TrafficFlowDestinationBucket,
    destination_bucket_delete_statement,
    destination_bucket_insert_statement,
    destination_rows,
)
from app.domains.traffic_flow.destinations import (
    CSV_COLUMNS,
    DESTINATION_CSV_MAX_ROWS,
    DESTINATION_SEARCH_LIMIT,
    RESPONSE_MODELS,
    AddressRow,
    DestinationFilters,
    DestinationRepository,
    DestinationScope,
    DestinationService,
    RecordRow,
    ServiceTotal,
    Totals,
    Venue,
    WindowStats,
    parse_filters,
    resolve_range,
)
from app.domains.traffic_flow.ingest import reduce_window, service_rows
from app.domains.traffic_flow.models import TrafficFlowWindow
from app.domains.traffic_flow.service import (
    TrafficFlowError,
    TrafficFlowIngestService,
    service_bucket_insert_statement,
)
from app.domains.traffic_flow.tasks import pull_once
from tests.unit.test_traffic_flow import FakeRepo

NOW = datetime(2026, 10, 12, 14, 10, tzinfo=UTC)
W1 = NOW - timedelta(minutes=15)
W2 = NOW - timedelta(minutes=10)
W3 = NOW - timedelta(minutes=5)
HOUR_AGO = NOW - timedelta(hours=1)

ORG_A = uuid.UUID("aaaaaaaa-0000-4000-8000-00000000000a")
ORG_B = uuid.UUID("bbbbbbbb-0000-4000-8000-00000000000b")
LOC_A = uuid.UUID("aaaaaaaa-0000-4000-8000-0000000000a1")
LOC_B = uuid.UUID("bbbbbbbb-0000-4000-8000-0000000000b1")
ROUTER_A = uuid.UUID("aaaaaaaa-0000-4000-8000-0000000000a2")
ROUTER_A2 = uuid.UUID("aaaaaaaa-0000-4000-8000-0000000000a3")
ROUTER_B = uuid.UUID("bbbbbbbb-0000-4000-8000-0000000000b2")
USER = uuid.UUID("cccccccc-0000-4000-8000-00000000000c")

EXPORTER = "10.20.0.31"
SOURCE = "mikrotik_ipfix"
VERSIONS = pathlib.Path("alembic/versions")
MIGRATION = "0159_traffic_flow_dest_buckets.py"

# The venue's devices. They exist in the collector rows the tests feed in,
# and must appear in nothing that comes out.
C1, C2, C3, C4, C5 = (f"192.168.88.{n}" for n in (11, 12, 13, 14, 15))
C6 = "fd00::16"
DEVICES = (C1, C2, C3, C4, C5, C6)

GOOGLE = "142.250.193.14"
GOOGLE_QUIC = "142.250.80.1"
DNS = "8.8.8.8"
ONE = "1.1.1.1"
V6 = "2404:6800:4003::200e"
PLAIN_WEB = "93.184.216.34"
ELSEWHERE = "9.9.9.9"


@pytest.fixture(autouse=True)
def _info_logging(caplog: pytest.LogCaptureFixture) -> None:
    """INFO on, as in CI: a logger ``extra`` key that collides with a
    LogRecord attribute only raises when the record is actually built."""
    caplog.set_level("INFO", logger="app.domains.traffic_flow")


def _settings(**over: Any) -> Any:
    return SimpleNamespace(**{"traffic_flow_enabled": True, **over})


def flow(
    device: str,
    remote: str,
    protocol: int,
    port: int,
    *,
    up: int = 0,
    down: int = 0,
) -> list[dict[str, Any]]:
    """Collector rows for one device talking to one outside service: one row
    per direction that carried bytes, as nfacctd emits them."""
    rows: list[dict[str, Any]] = []
    if up:
        rows.append(
            {
                "peer_ip_src": EXPORTER,
                "ip_src": device,
                "ip_dst": remote,
                "ip_proto": protocol,
                "port_src": 50000,
                "port_dst": port,
                "bytes": up,
                "packets": 1,
                "flows": 1,
            }
        )
    if down:
        rows.append(
            {
                "peer_ip_src": EXPORTER,
                "ip_src": remote,
                "ip_dst": device,
                "ip_proto": protocol,
                "port_src": port,
                "port_dst": 50000,
                "bytes": down,
                "packets": 1,
                "flows": 1,
            }
        )
    return rows


def _w1() -> list[dict[str, Any]]:
    """Six devices. Client traffic 2685 bytes."""
    return [
        *flow(C1, GOOGLE, 6, 443, up=100, down=1000),
        *flow(C2, GOOGLE, 6, 443, up=50, down=500),
        *flow(C3, GOOGLE_QUIC, 17, 443, down=700),
        *flow(C4, DNS, 17, 53, up=10, down=20),
        *flow(C5, ONE, 6, 443, up=5),
        *flow(C6, V6, 6, 443, down=300),
    ]


def _w2() -> list[dict[str, Any]]:
    """Six devices. Client traffic 2603 bytes."""
    return [
        *flow(C1, GOOGLE, 6, 443, up=200, down=2000),
        *flow(C2, DNS, 17, 53, up=1, down=2),
        *flow(C3, GOOGLE_QUIC, 17, 443, down=100),
        *flow(C4, GOOGLE_QUIC, 17, 443, down=100),
        *flow(C5, GOOGLE_QUIC, 17, 443, down=100),
        *flow(C6, GOOGLE_QUIC, 17, 443, down=100),
    ]


def _w3() -> list[dict[str, Any]]:
    """Two devices only: a small-venue window. Client traffic 9440 bytes."""
    return [
        *flow(C1, GOOGLE, 6, 443, down=9000),
        *flow(C2, PLAIN_WEB, 6, 80, up=40, down=400),
    ]


# ---------------------------------------------------------------------------
# backends
# ---------------------------------------------------------------------------


def _address_key(address: str) -> tuple[int, int]:
    parsed = ipaddress.ip_address(address)
    return parsed.version, int(parsed)


class MemoryRepository:
    """The semantics the SQL statements are meant to have, in Python."""

    def __init__(self, backend: MemoryBackend) -> None:
        self.b = backend

    async def venue(self, location_id: uuid.UUID) -> Venue | None:
        if location_id not in self.b.venues:
            return None
        return Venue(
            location_id=location_id, organization_id=self.b.venues[location_id]
        )

    def _scoped(
        self, rows: list[dict[str, Any]], scope: DestinationScope
    ) -> list[dict[str, Any]]:
        return [
            r
            for r in rows
            if r["location_id"] == scope.location_id
            and (scope.router_id is None or r["router_id"] == scope.router_id)
            and (
                scope.organization_id is None
                or r["organization_id"] == scope.organization_id
            )
        ]

    def _ranged(
        self,
        rows: list[dict[str, Any]],
        scope: DestinationScope,
        since: datetime,
        until: datetime,
    ) -> list[dict[str, Any]]:
        return [
            r for r in self._scoped(rows, scope) if since <= r["window_start"] < until
        ]

    def _visible(
        self, rows: list[dict[str, Any]], scope: DestinationScope
    ) -> list[dict[str, Any]]:
        if scope.min_devices <= 0:
            return rows
        enough = {
            (w["router_id"], w["source"], w["window_start"])
            for w in self.b.windows
            if w["talker_count"] >= scope.min_devices
        }
        return [
            r
            for r in rows
            if (r["router_id"], r["source"], r["window_start"]) in enough
        ]

    async def window_stats(
        self, scope: DestinationScope, *, since: datetime, until: datetime
    ) -> WindowStats:
        windows = self._ranged(self.b.windows, scope, since, until)
        return WindowStats(
            windows=len(windows),
            measured=sum(1 for w in windows if w["services_measured"]),
            withheld=(
                sum(1 for w in windows if w["talker_count"] < scope.min_devices)
                if scope.min_devices > 0
                else 0
            ),
        )

    async def data_bounds(self, scope: DestinationScope) -> tuple[Any, Any]:
        starts = [w["window_start"] for w in self._scoped(self.b.windows, scope)]
        return (min(starts), max(starts)) if starts else (None, None)

    def _records(
        self,
        scope: DestinationScope,
        filters: DestinationFilters,
        since: datetime,
        until: datetime,
    ) -> list[RecordRow]:
        grouped: dict[tuple[Any, ...], list[int]] = {}
        for r in self._visible(
            self._ranged(self.b.destinations, scope, since, until), scope
        ):
            if r["remote_port"] == OTHER_SERVICE_PORT:
                continue
            if filters.address is not None:
                address = ipaddress.ip_address(r["remote_address"])
                if (
                    address.version != filters.address.version
                    or address not in filters.address
                ):
                    continue
            if filters.protocol is not None and r["protocol"] != filters.protocol:
                continue
            if filters.port is not None and r["remote_port"] != filters.port:
                continue
            key = (
                r["window_start"],
                r["remote_address"],
                r["protocol"],
                r["remote_port"],
            )
            sums = grouped.setdefault(key, [0, 0, 0])
            sums[0] += r["bytes_up"]
            sums[1] += r["bytes_down"]
            sums[2] += r["flows"]
        out = [
            RecordRow(start, 300, address, protocol, port, up, down, flows)
            for (start, address, protocol, port), (up, down, flows) in grouped.items()
        ]
        if filters.direction == "up":
            out = [r for r in out if r.bytes_up > 0]
        elif filters.direction == "down":
            out = [r for r in out if r.bytes_down > 0]
        return out

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
        self.b.page_limits.append(limit)
        rows = self._records(scope, filters, since, until)
        primary = {
            "time": lambda r: r.window_start,
            "address": lambda r: _address_key(r.remote_address),
            "protocol": lambda r: r.protocol,
            "port": lambda r: r.remote_port,
            "bytes": lambda r: r.bytes_up + r.bytes_down,
            "bytes_up": lambda r: r.bytes_up,
            "bytes_down": lambda r: r.bytes_down,
            "flows": lambda r: r.flows,
        }[sort]
        # Stable sorts, least significant key first: the statement's order.
        rows.sort(
            key=lambda r: (_address_key(r.remote_address), r.protocol, r.remote_port)
        )
        rows.sort(key=lambda r: r.bytes_up + r.bytes_down, reverse=True)
        rows.sort(key=lambda r: r.window_start, reverse=True)
        rows.sort(key=primary, reverse=order == "desc")
        return rows[:limit]

    async def search_totals(
        self,
        scope: DestinationScope,
        filters: DestinationFilters,
        *,
        since: datetime,
        until: datetime,
    ) -> Totals:
        rows = self._records(scope, filters, since, until)
        return Totals(
            len(rows),
            sum(r.bytes_up for r in rows),
            sum(r.bytes_down for r in rows),
            sum(r.flows for r in rows),
        )

    async def unlisted(
        self,
        scope: DestinationScope,
        *,
        since: datetime,
        until: datetime,
        protocol: int | None,
    ) -> Totals:
        rows = [
            r
            for r in self._visible(
                self._ranged(self.b.destinations, scope, since, until), scope
            )
            if r["remote_port"] == OTHER_SERVICE_PORT
            and (protocol is None or r["protocol"] == protocol)
        ]
        return Totals(
            0,
            sum(r["bytes_up"] for r in rows),
            sum(r["bytes_down"] for r in rows),
            sum(r["flows"] for r in rows),
        )

    async def service_total(
        self,
        scope: DestinationScope,
        *,
        since: datetime,
        until: datetime,
        protocol: int,
        port: int,
    ) -> ServiceTotal:
        rows = [
            r
            for r in self._visible(
                self._ranged(self.b.services, scope, since, until), scope
            )
            if r["protocol"] == protocol
        ]
        own = [r for r in rows if r["remote_port"] == port]
        with_service = {(r["router_id"], r["window_start"]) for r in own}
        with_other = {
            (r["router_id"], r["window_start"])
            for r in rows
            if r["remote_port"] == OTHER_SERVICE_PORT
        }
        return ServiceTotal(
            sum(r["bytes_up"] for r in own),
            sum(r["bytes_down"] for r in own),
            sum(r["flows"] for r in own),
            len(with_other - with_service),
        )

    def _addresses(
        self,
        scope: DestinationScope,
        since: datetime,
        until: datetime,
        protocol: int,
        port: int,
    ) -> list[AddressRow]:
        merged: dict[str, list[int]] = {}
        for r in self._visible(
            self._ranged(self.b.destinations, scope, since, until), scope
        ):
            if r["protocol"] != protocol or r["remote_port"] != port:
                continue
            sums = merged.setdefault(r["remote_address"], [0, 0, 0])
            sums[0] += r["bytes_up"]
            sums[1] += r["bytes_down"]
            sums[2] += r["flows"]
        rows = [AddressRow(a, *sums) for a, sums in merged.items()]
        rows.sort(key=lambda r: _address_key(r.remote_address))
        rows.sort(key=lambda r: r.bytes_up + r.bytes_down, reverse=True)
        return rows

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
        return self._addresses(scope, since, until, protocol, port)[:limit]

    async def service_destination_totals(
        self,
        scope: DestinationScope,
        *,
        since: datetime,
        until: datetime,
        protocol: int,
        port: int,
    ) -> Totals:
        rows = self._addresses(scope, since, until, protocol, port)
        return Totals(
            len(rows),
            sum(r.bytes_up for r in rows),
            sum(r.bytes_down for r in rows),
            sum(r.flows for r in rows),
        )


def _reduced(rows: list[dict[str, Any]]) -> Any:
    return reduce_window(rows)[EXPORTER]


class MemoryBackend:
    name = "memory"

    def __init__(self) -> None:
        self.venues: dict[uuid.UUID, uuid.UUID] = {}
        self.windows: list[dict[str, Any]] = []
        self.destinations: list[dict[str, Any]] = []
        self.services: list[dict[str, Any]] = []
        self.page_limits: list[int] = []

    def repository(self) -> Any:
        return MemoryRepository(self)

    async def add_venue(self, location_id: uuid.UUID, organization_id: uuid.UUID):
        self.venues[location_id] = organization_id

    async def add_window(
        self,
        *,
        router_id: uuid.UUID,
        location_id: uuid.UUID,
        organization_id: uuid.UUID,
        start: datetime,
        rows: list[dict[str, Any]],
        top_n: int = TOP_DESTINATION_SERVICES_STORED,
        service_top_n: int = 50,
    ) -> None:
        reduced = _reduced(rows)
        identity = {
            "router_id": router_id,
            "organization_id": organization_id,
            "location_id": location_id,
            "source": SOURCE,
            "window_start": start,
            "window_seconds": 300,
        }
        self.windows.append(
            {
                **identity,
                "services_measured": reduced.services_measured,
                "talker_count": len(reduced.talkers),
            }
        )
        self.destinations.extend(
            {**identity, **row} for row in destination_rows(reduced, limit=top_n)
        )
        self.services.extend(
            {**identity, **row} for row in service_rows(reduced, limit=service_top_n)
        )


def _migration(filename: str) -> Any:
    spec = importlib.util.spec_from_file_location(
        filename.removesuffix(".py"), VERSIONS / filename
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _statements(filename: str, fn: str = "upgrade") -> list[str]:
    """The DDL a revision issues, captured instead of executed."""
    statements: list[str] = []

    class _Op:
        def execute(self, sql: Any) -> None:
            statements.append(" ".join(str(sql).split()))

        def __getattr__(self, name: str) -> Any:
            raise AssertionError(f"op.{name} is not guarded; use op.execute")

    module = _migration(filename)
    module.op = _Op()
    getattr(module, fn)()
    return statements


class PostgresBackend:
    """A scratch database built from the real revisions, with stub parent
    tables (only their ids are needed)."""

    name = "postgres"
    TABLES = (
        "traffic_flow_dest_buckets",
        "traffic_flow_service_buckets",
        "router_traffic_flow_export",
        "traffic_flow_ingest_state",
        "traffic_flow_windows",
        "routers",
        "locations",
        "organizations",
    )

    def __init__(self, session: Any) -> None:
        self.session = session
        self.page_limits: list[int] = []

    @classmethod
    async def build(cls, connection: Any) -> None:
        for table in cls.TABLES:
            await connection.execute(text(f"DROP TABLE IF EXISTS {table} CASCADE"))
        await connection.execute(
            text("CREATE TABLE organizations (id UUID PRIMARY KEY)")
        )
        await connection.execute(
            text(
                "CREATE TABLE locations (id UUID PRIMARY KEY, organization_id UUID, "
                "is_deleted BOOLEAN NOT NULL DEFAULT false)"
            )
        )
        await connection.execute(text("CREATE TABLE routers (id UUID PRIMARY KEY)"))
        for filename in (
            "0156_create_traffic_flow_tables.py",
            "0157_traffic_flow_services_export.py",
            MIGRATION,
        ):
            for statement in _statements(filename):
                await connection.execute(text(statement))
        # A second run of the new revision must be a no-op.
        for statement in _statements(MIGRATION):
            await connection.execute(text(statement))

    def repository(self) -> Any:
        return DestinationRepository(self.session)

    async def add_venue(self, location_id: uuid.UUID, organization_id: uuid.UUID):
        await self.session.execute(
            text("INSERT INTO organizations VALUES (:o) ON CONFLICT DO NOTHING"),
            {"o": organization_id},
        )
        await self.session.execute(
            text("INSERT INTO locations VALUES (:l, :o) ON CONFLICT DO NOTHING"),
            {"l": location_id, "o": organization_id},
        )

    async def add_window(
        self,
        *,
        router_id: uuid.UUID,
        location_id: uuid.UUID,
        organization_id: uuid.UUID,
        start: datetime,
        rows: list[dict[str, Any]],
        top_n: int = TOP_DESTINATION_SERVICES_STORED,
        service_top_n: int = 50,
    ) -> None:
        reduced = _reduced(rows)
        await self.session.execute(
            text("INSERT INTO routers VALUES (:r) ON CONFLICT DO NOTHING"),
            {"r": router_id},
        )
        identity = {
            "router_id": router_id,
            "organization_id": organization_id,
            "location_id": location_id,
            "source": SOURCE,
            "window_start": start,
            "window_seconds": 300,
        }
        await self.session.execute(
            pg_insert(TrafficFlowWindow).values(
                id=uuid.uuid4(),
                **identity,
                exporter_address=EXPORTER,
                bytes_total=reduced.bytes_total,
                packets_total=reduced.packets_total,
                flows_total=reduced.flows_total,
                bytes_up=reduced.bytes_up,
                bytes_down=reduced.bytes_down,
                services_measured=reduced.services_measured,
                bytes_internal=0,
                bytes_unclassified=0,
                bytes_other_talkers=0,
                bytes_other_destinations=0,
                talker_count=len(reduced.talkers),
                destination_count=len(reduced.destinations),
                # Real device addresses sit in this column, as in production.
                top_talkers=[{"ip": ip} for ip in reduced.talkers],
                top_destinations=[],
                received_at=NOW,
            )
        )
        buckets = [
            {**identity, **row} for row in destination_rows(reduced, limit=top_n)
        ]
        services = [
            {**identity, **row} for row in service_rows(reduced, limit=service_top_n)
        ]
        # Twice: the second insert of a window's buckets must change nothing.
        for _ in range(2):
            if buckets:
                await self.session.execute(destination_bucket_insert_statement(buckets))
            if services:
                await self.session.execute(service_bucket_insert_statement(services))
        await self.session.flush()


@pytest_asyncio.fixture(params=["memory", "postgres"])
async def backend(request: pytest.FixtureRequest) -> Any:
    if request.param == "memory":
        yield MemoryBackend()
        return
    dsn = os.environ.get("TRAFFIC_FLOW_TEST_DSN")
    if not dsn:
        pytest.skip("TRAFFIC_FLOW_TEST_DSN is not set (no database server in CI)")
    from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
    from sqlalchemy.pool import NullPool

    engine = create_async_engine(dsn, poolclass=NullPool)
    async with engine.begin() as connection:
        await PostgresBackend.build(connection)
    async with AsyncSession(engine, expire_on_commit=False) as session:
        yield PostgresBackend(session)
        await session.rollback()
    await engine.dispose()


async def seed(backend: Any) -> None:
    """Venue A (three windows, the last one with two devices only) and
    another organisation's venue B."""
    await backend.add_venue(LOC_A, ORG_A)
    await backend.add_venue(LOC_B, ORG_B)
    for start, rows in ((W1, _w1()), (W2, _w2()), (W3, _w3())):
        await backend.add_window(
            router_id=ROUTER_A,
            location_id=LOC_A,
            organization_id=ORG_A,
            start=start,
            rows=rows,
        )
    await backend.add_window(
        router_id=ROUTER_B,
        location_id=LOC_B,
        organization_id=ORG_B,
        start=W2,
        rows=[row for d in DEVICES for row in flow(d, ELSEWHERE, 6, 443, down=111)],
    )


class Audit:
    def __init__(self, *, fail: bool = False) -> None:
        self.entries: list[dict[str, Any]] = []
        self.fail = fail

    async def create_audit_log_entry(self, **fields: Any) -> None:
        if self.fail:
            raise RuntimeError("audit store down")
        self.entries.append(fields)


def _service(backend: Any, audit: Audit | None = None, **settings: Any) -> Any:
    return DestinationService(
        backend.repository(),
        _settings(**settings),
        audit_writer=audit or Audit(),
        now=lambda: NOW,
    )


def _keys(rows: list[Any]) -> list[tuple[str, str, int, int]]:
    return [(r.window_start, r.address, r.protocol, r.port) for r in rows]


# ---------------------------------------------------------------------------
# reduction: bucket sums and the "other" row
# ---------------------------------------------------------------------------


class TestBuckets:
    def test_rows_add_up_to_the_windows_client_traffic(self) -> None:
        reduced = _reduced(_w1())
        rows = destination_rows(reduced)
        assert sum(r["bytes_up"] + r["bytes_down"] for r in rows) == 2685
        assert reduced.bytes_up + reduced.bytes_down == 2685
        assert all(r["remote_port"] != OTHER_SERVICE_PORT for r in rows)
        by_key = {
            (r["remote_address"], r["protocol"], r["remote_port"]): r for r in rows
        }
        # Two devices to one address and service are ONE venue-level row.
        assert by_key[(GOOGLE, 6, 443)] == {
            "remote_address": GOOGLE,
            "protocol": 6,
            "remote_port": 443,
            "bytes_up": 150,
            "bytes_down": 1500,
            "flows": 4,
        }

    def test_everything_below_the_cut_is_an_explicit_other_row_per_protocol(
        self,
    ) -> None:
        reduced = _reduced(_w1())
        rows = destination_rows(reduced, limit=2)
        kept = [r for r in rows if r["remote_port"] != OTHER_SERVICE_PORT]
        other = [r for r in rows if r["remote_port"] == OTHER_SERVICE_PORT]
        assert [(r["remote_address"], r["protocol"]) for r in kept] == [
            (GOOGLE, 6),
            (GOOGLE_QUIC, 17),
        ]
        assert [
            (r["remote_address"], r["protocol"], r["bytes_up"], r["bytes_down"])
            for r in other
        ] == [
            (OTHER_DESTINATION_ADDRESS, 6, 5, 300),
            (OTHER_DESTINATION_ADDRESS, 17, 10, 20),
        ]
        # Exact: nothing dropped, in total and per protocol.
        assert sum(r["bytes_up"] + r["bytes_down"] for r in rows) == 2685
        assert sum(r["flows"] for r in rows) == reduced.flows_total
        per_protocol: dict[int, int] = {}
        for r in rows:
            per_protocol[r["protocol"]] = (
                per_protocol.get(r["protocol"], 0) + r["bytes_up"] + r["bytes_down"]
            )
        from_services: dict[int, int] = {}
        for s in service_rows(reduced):
            from_services[s["protocol"]] = (
                from_services.get(s["protocol"], 0) + s["bytes_up"] + s["bytes_down"]
            )
        assert per_protocol == from_services == {6: 1955, 17: 730}

    def test_the_default_cut_is_fifty(self) -> None:
        many = [
            row
            for n in range(60)
            for row in flow(C1, f"142.250.1.{n + 1}", 6, 443, down=1000 - n)
        ]
        rows = destination_rows(_reduced(many))
        assert TOP_DESTINATION_SERVICES_STORED == 50
        assert len(rows) == 51 and rows[-1]["remote_port"] == OTHER_SERVICE_PORT
        assert rows[-1]["bytes_down"] == sum(1000 - n for n in range(50, 60))

    def test_the_other_address_can_never_be_a_real_outside_address(self) -> None:
        from app.domains.traffic_flow.ingest import is_local_address

        assert is_local_address(OTHER_DESTINATION_ADDRESS) is True

    def test_a_window_without_ports_has_no_rows_rather_than_a_partial_list(
        self,
    ) -> None:
        rows = [
            {
                "peer_ip_src": EXPORTER,
                "ip_src": C1,
                "ip_dst": GOOGLE,
                "bytes": 10,
                "packets": 1,
                "flows": 1,
            }
        ]
        assert destination_rows(_reduced(rows)) == []

    def test_internal_traffic_is_not_a_destination(self) -> None:
        rows = [
            *flow(C1, "192.168.88.1", 17, 53, up=10, down=10),
            *flow(C1, GOOGLE, 6, 443, down=5),
        ]
        assert [r["remote_address"] for r in destination_rows(_reduced(rows))] == [
            GOOGLE
        ]

    def test_two_spellings_of_one_address_are_one_row(self) -> None:
        rows = [
            *flow(C6, "2404:6800:4003:0:0:0:0:200e", 6, 443, down=1),
            *flow(C6, V6, 6, 443, down=2),
        ]
        out = destination_rows(_reduced(rows))
        assert len(out) == 1 and out[0]["remote_address"] == V6
        assert out[0]["bytes_down"] == 3

    def test_no_row_carries_a_device_address(self) -> None:
        rows = destination_rows(_reduced(_w1())) + destination_rows(
            _reduced(_w1()), limit=1
        )
        flat = repr(rows)
        for device in DEVICES:
            assert device not in flat


# ---------------------------------------------------------------------------
# ingest: written once, pruned with the window
# ---------------------------------------------------------------------------


class TestIngest:
    async def test_re_ingesting_a_window_adds_no_rows(self) -> None:
        repo = FakeRepo()
        service = TrafficFlowIngestService(repo)  # type: ignore[arg-type]
        for _ in range(2):
            await service.ingest_window(window_start=W1, window_seconds=300, rows=_w1())
        assert len(repo.inserted) == 1
        assert len(repo.destination_rows) == 5
        assert (
            sum(r["bytes_up"] + r["bytes_down"] for r in repo.destination_rows) == 2685
        )
        row = repo.destination_rows[0]
        # The scoping and idempotency columns of the service buckets.
        assert set(row) == {
            c.name for c in TrafficFlowDestinationBucket.__table__.c
        } - {"id"}

    def test_the_insert_is_idempotent_on_the_unique_key(self) -> None:
        row = {
            "router_id": ROUTER_A,
            "organization_id": None,
            "location_id": None,
            "source": SOURCE,
            "window_start": W1,
            "window_seconds": 300,
            "remote_address": GOOGLE,
            "protocol": 6,
            "remote_port": 443,
            "bytes_up": 1,
            "bytes_down": 2,
            "flows": 1,
        }
        sql = _sql(destination_bucket_insert_statement([row]))
        assert "ON CONFLICT ON CONSTRAINT uq_traffic_flow_dest_buckets_key" in sql
        assert "DO NOTHING" in sql
        unique = {
            tuple(c.name for c in constraint.columns)
            for constraint in TrafficFlowDestinationBucket.__table__.constraints
            if constraint.__class__.__name__ == "UniqueConstraint"
        }
        assert unique == {
            (
                "router_id",
                "source",
                "window_start",
                "remote_address",
                "protocol",
                "remote_port",
            )
        }

    async def test_the_sweep_prunes_them_on_the_same_cutoff(self) -> None:
        repo = FakeRepo()

        async def fetch(after: int) -> dict[str, Any]:
            return {
                "windows": [
                    {
                        "window_start": int(W1.timestamp()),
                        "window_seconds": 300,
                        "rows": _w1(),
                    }
                ]
            }

        async def commit() -> None:
            return None

        result = await pull_once(
            repository=repo,  # type: ignore[arg-type]
            settings=_settings(
                traffic_flow_agent_url="http://hub.invalid:9094",
                traffic_flow_agent_secret="s3cret",  # noqa: S106
            ),
            fetch_windows=fetch,
            commit=commit,
            now=lambda: NOW,
        )
        assert result["written"] == 1 and result["pruned_destination_buckets"] == 0
        assert repo.destination_pruned_before == NOW - timedelta(days=7)
        assert len(repo.destination_rows) == 5
        sql = _sql(destination_bucket_delete_statement(NOW, limit=100))
        assert "window_start <" in sql and "LIMIT" in sql


# ---------------------------------------------------------------------------
# search
# ---------------------------------------------------------------------------


class TestSearch:
    async def test_every_record_of_the_range_with_exact_totals(self, backend) -> None:
        await seed(backend)
        out = await _service(backend).search(location_id=LOC_A, actor_user_id=USER)
        assert out.measured is True and out.feature_enabled is True
        assert (out.windows, out.windows_measured) == (3, 3)
        assert (out.total, out.returned, out.truncated) == (10, 10, False)
        assert out.limit == DESTINATION_SEARCH_LIMIT == 1000
        assert out.totals is not None and out.totals.bytes == 2685 + 2603 + 9440
        # Nothing was outside a window's top 50, and that is known.
        assert out.unlisted is not None and out.unlisted.bytes == 0
        assert out.since == HOUR_AGO.isoformat() and out.until == NOW.isoformat()
        assert (out.data_oldest, out.data_newest) == (W1.isoformat(), W3.isoformat())
        assert out.query_ms >= 0 and out.per_window_top_n == 50
        assert (out.min_devices, out.windows_withheld) == (None, 0)
        first = out.rows[0]
        # Default order: newest window first, then largest.
        assert first.model_dump() == {
            "window_start": W3.isoformat(),
            "window_end": NOW.isoformat(),
            "address": GOOGLE,
            "protocol": 6,
            "protocol_name": "tcp",
            "port": 443,
            "service_name": "https",
            "bytes_up": 0,
            "bytes_down": 9000,
            "bytes": 9000,
            "flows": 1,
        }

    async def test_two_devices_to_one_service_are_one_venue_record(
        self, backend
    ) -> None:
        await seed(backend)
        out = await _service(backend).search(
            location_id=LOC_A,
            actor_user_id=USER,
            address=GOOGLE,
            since=W1,
            until=W2,
        )
        assert out.total == 1
        assert (out.rows[0].bytes_up, out.rows[0].bytes_down) == (150, 1500)
        assert out.rows[0].flows == 4

    async def test_other_rows_are_reported_as_unlisted_so_sums_stay_exact(
        self, backend
    ) -> None:
        await backend.add_venue(LOC_A, ORG_A)
        await backend.add_window(
            router_id=ROUTER_A,
            location_id=LOC_A,
            organization_id=ORG_A,
            start=W1,
            rows=_w1(),
            top_n=2,
        )
        service = _service(backend)
        out = await service.search(location_id=LOC_A, actor_user_id=USER)
        assert out.total == 2
        assert {r.address for r in out.rows} == {GOOGLE, GOOGLE_QUIC}
        assert out.unlisted is not None
        assert (out.unlisted.bytes_up, out.unlisted.bytes_down) == (15, 320)
        assert out.totals is not None
        assert out.totals.bytes + out.unlisted.bytes == 2685
        udp = await service.search(location_id=LOC_A, actor_user_id=USER, protocol=17)
        assert udp.unlisted is not None and udp.unlisted.bytes == 30
        # How much of "other" would match an address, port or direction
        # cannot be known: null, never zero.
        for narrowed in ({"address": GOOGLE}, {"port": 443}, {"direction": "up"}):
            answer = await service.search(
                location_id=LOC_A, actor_user_id=USER, **narrowed
            )
            assert answer.unlisted is None, narrowed

    @pytest.mark.parametrize(
        ("filters", "expected", "echo"),
        [
            ({"address": GOOGLE}, 3, GOOGLE),
            ({"address": "142.250.0.0/16"}, 5, "142.250.0.0/16"),
            # Host bits set: rounded down to the network and echoed that way.
            ({"address": "142.250.193.14/16"}, 5, "142.250.0.0/16"),
            ({"address": "2404:6800::/32"}, 1, "2404:6800::/32"),
            ({"address": V6}, 1, V6),
            ({"address": "0.0.0.0/0"}, 9, "0.0.0.0/0"),
            ({"address": "10.0.0.0/8"}, 0, "10.0.0.0/8"),
        ],
    )
    async def test_address_and_prefix_filter(
        self, backend, filters, expected, echo
    ) -> None:
        await seed(backend)
        out = await _service(backend).search(
            location_id=LOC_A, actor_user_id=USER, **filters
        )
        assert out.total == expected == len(out.rows)
        assert out.filters.address == echo

    @pytest.mark.parametrize(
        ("filters", "expected"),
        [
            ({"protocol": 17}, 4),
            ({"protocol": 6}, 6),
            ({"port": 53}, 2),
            ({"port": 80}, 1),
            ({"protocol": 6, "port": 443}, 5),
            ({"protocol": 17, "port": 443, "address": "142.250.0.0/16"}, 2),
            ({"direction": "up"}, 6),
            ({"direction": "down"}, 9),
            ({"direction": "any"}, 10),
            ({"direction": "up", "protocol": 17}, 2),
            ({"protocol": 1}, 0),
        ],
    )
    async def test_protocol_port_and_direction_filters(
        self, backend, filters, expected
    ) -> None:
        await seed(backend)
        out = await _service(backend).search(
            location_id=LOC_A, actor_user_id=USER, **filters
        )
        assert out.total == expected == len(out.rows)
        for row in out.rows:
            if "protocol" in filters:
                assert row.protocol == filters["protocol"]
            if "port" in filters:
                assert row.port == filters["port"]
            if filters.get("direction") == "up":
                assert row.bytes_up > 0
            if filters.get("direction") == "down":
                assert row.bytes_down > 0
        assert out.filters.direction == filters.get("direction", "any")

    async def test_nothing_matching_is_zero_records_not_unmeasured(
        self, backend
    ) -> None:
        await seed(backend)
        out = await _service(backend).search(
            location_id=LOC_A, actor_user_id=USER, port=65000
        )
        assert out.measured is True and out.windows_measured == 3
        assert out.total == 0 and out.rows == []
        assert out.totals is not None and out.totals.bytes == 0

    @pytest.mark.parametrize(
        ("field", "kwargs"),
        [
            ("address", {"address": "not-an-address"}),
            ("address", {"address": "142.250.0.0/40"}),
            ("direction", {"direction": "sideways"}),
            ("sort", {"sort": "device"}),
            ("order", {"order": "random"}),
            ("protocol", {"protocol": 256}),
            ("port", {"port": 70000}),
        ],
    )
    async def test_a_bad_filter_is_refused_and_named(
        self, backend, field, kwargs
    ) -> None:
        await seed(backend)
        audit = Audit()
        with pytest.raises(TrafficFlowError) as caught:
            await _service(backend, audit).search(
                location_id=LOC_A, actor_user_id=USER, **kwargs
            )
        assert caught.value.code == "TRAFFIC_FLOW_BAD_FILTER"
        assert caught.value.status_code == 422
        assert caught.value.data["field"] == field
        assert audit.entries == []

    @pytest.mark.parametrize(
        ("sort", "order", "first", "last"),
        [
            ("time", "desc", (W3, GOOGLE), (W1, ONE)),
            ("time", "asc", (W1, GOOGLE), (W3, PLAIN_WEB)),
            ("bytes", "desc", (W3, GOOGLE), (W2, DNS)),
            ("bytes", "asc", (W2, DNS), (W3, GOOGLE)),
            ("bytes_up", "desc", (W2, GOOGLE), (W1, V6)),
            ("bytes_down", "desc", (W3, GOOGLE), (W1, ONE)),
            ("flows", "desc", (W2, GOOGLE_QUIC), (W1, ONE)),
            ("address", "asc", (W1, ONE), (W1, V6)),
            ("address", "desc", (W1, V6), (W1, ONE)),
            ("port", "asc", (W2, DNS), (W1, ONE)),
            ("protocol", "desc", (W2, GOOGLE_QUIC), (W1, ONE)),
        ],
    )
    async def test_sorting(self, backend, sort, order, first, last) -> None:
        await seed(backend)
        out = await _service(backend).search(
            location_id=LOC_A, actor_user_id=USER, sort=sort, order=order
        )
        assert (out.sort, out.order) == (sort, order)
        assert (out.rows[0].window_start, out.rows[0].address) == (
            first[0].isoformat(),
            first[1],
        )
        assert (out.rows[-1].window_start, out.rows[-1].address) == (
            last[0].isoformat(),
            last[1],
        )

    async def test_the_page_is_capped_and_the_total_is_not(
        self, backend, monkeypatch
    ) -> None:
        await seed(backend)
        monkeypatch.setattr(dest, "DESTINATION_SEARCH_LIMIT", 4)
        out = await _service(backend).search(
            location_id=LOC_A, actor_user_id=USER, sort="bytes"
        )
        assert (out.limit, out.returned, out.total, out.truncated) == (4, 4, 10, True)
        assert len(out.rows) == 4
        # Totals describe every matching record, not the page.
        assert out.totals is not None and out.totals.bytes == 14728
        assert [r.bytes for r in out.rows] == [9000, 2200, 1650, 700]

    async def test_the_real_cap_is_what_the_database_is_asked_for(self) -> None:
        memory = MemoryBackend()
        await seed(memory)
        await _service(memory).search(location_id=LOC_A, actor_user_id=USER)
        assert memory.page_limits == [1000]

    async def test_a_router_filter_narrows_and_several_routers_add_up(
        self, backend
    ) -> None:
        await seed(backend)
        await backend.add_window(
            router_id=ROUTER_A2,
            location_id=LOC_A,
            organization_id=ORG_A,
            start=W1,
            rows=[
                row
                for device in DEVICES
                for row in flow(device, GOOGLE, 6, 443, down=10)
            ],
        )
        service = _service(backend)
        venue = await service.search(
            location_id=LOC_A, actor_user_id=USER, address=GOOGLE, since=W1, until=W2
        )
        assert venue.total == 1 and venue.rows[0].bytes_down == 1500 + 60
        assert venue.windows == 2
        one = await service.search(
            location_id=LOC_A,
            actor_user_id=USER,
            address=GOOGLE,
            since=W1,
            until=W2,
            router_id=ROUTER_A2,
        )
        assert one.rows[0].bytes_down == 60 and one.router_id == str(ROUTER_A2)
        # A router of another venue simply matches nothing.
        foreign = await service.search(
            location_id=LOC_A, actor_user_id=USER, router_id=ROUTER_B
        )
        assert foreign.measured is False and foreign.total == 0


# ---------------------------------------------------------------------------
# honest states
# ---------------------------------------------------------------------------


class TestStates:
    async def test_no_window_in_range_is_not_measured_and_not_zero(
        self, backend
    ) -> None:
        await seed(backend)
        out = await _service(backend).search(
            location_id=LOC_A,
            actor_user_id=USER,
            since=NOW - timedelta(hours=5),
            until=NOW - timedelta(hours=4),
        )
        assert out.measured is False and out.windows == 0
        assert out.totals is None and out.unlisted is None and out.rows == []
        # ...and the screen can say where data does start.
        assert out.data_oldest == W1.isoformat()

    async def test_windows_without_ports_are_said_to_be_unmeasured(
        self, backend
    ) -> None:
        await backend.add_venue(LOC_A, ORG_A)
        await backend.add_window(
            router_id=ROUTER_A,
            location_id=LOC_A,
            organization_id=ORG_A,
            start=W1,
            rows=[
                {
                    "peer_ip_src": EXPORTER,
                    "ip_src": C1,
                    "ip_dst": GOOGLE,
                    "bytes": 10,
                    "packets": 1,
                    "flows": 1,
                }
            ],
        )
        out = await _service(backend).search(location_id=LOC_A, actor_user_id=USER)
        assert (out.measured, out.windows, out.windows_measured) == (True, 1, 0)
        assert out.total == 0

    async def test_the_table_is_not_read_while_the_feature_is_off(self) -> None:
        class OnlyVenue:
            async def venue(self, location_id: uuid.UUID) -> Venue:
                return Venue(location_id=location_id, organization_id=ORG_A)

            def __getattr__(self, name: str) -> Any:
                raise AssertionError(f"{name} read while the feature is off")

        audit = Audit()
        service = DestinationService(
            OnlyVenue(),  # type: ignore[arg-type]
            _settings(traffic_flow_enabled=False),
            audit_writer=audit,
            now=lambda: NOW,
        )
        out = await service.search(location_id=LOC_A, actor_user_id=USER)
        assert (out.feature_enabled, out.measured, out.total) == (False, False, 0)
        export = await service.export_csv(location_id=LOC_A, actor_user_id=USER)
        assert export.text.splitlines() == [",".join(CSV_COLUMNS)]
        drill = await service.service_destinations(
            location_id=LOC_A, actor_user_id=USER, protocol=6, port=443
        )
        assert drill.measured is False and drill.service is None
        assert len(audit.entries) == 3

    async def test_a_venue_that_does_not_exist_is_404(self, backend) -> None:
        await seed(backend)
        with pytest.raises(TrafficFlowError) as caught:
            await _service(backend).search(location_id=uuid.uuid4(), actor_user_id=USER)
        assert caught.value.status_code == 404
        assert caught.value.code == "TRAFFIC_FLOW_LOCATION_NOT_FOUND"


# ---------------------------------------------------------------------------
# custom time range
# ---------------------------------------------------------------------------


class TestRange:
    def test_default_is_the_last_hour(self) -> None:
        assert resolve_range(None, None, now=NOW) == (HOUR_AGO, NOW)

    def test_a_minute_precision_custom_range_is_used_as_given(self) -> None:
        since = datetime(2026, 10, 11, 9, 7, tzinfo=UTC)
        until = datetime(2026, 10, 11, 17, 52, tzinfo=UTC)
        assert resolve_range(since, until, now=NOW) == (since, until)

    def test_a_naive_instant_is_read_as_utc(self) -> None:
        since, until = resolve_range(
            datetime(2026, 10, 12, 13, 7), datetime(2026, 10, 12, 13, 52), now=NOW
        )
        assert since.tzinfo is UTC and until - since == timedelta(minutes=45)

    @pytest.mark.parametrize(
        ("since", "until", "code"),
        [
            (NOW, NOW, "TRAFFIC_FLOW_BAD_RANGE"),
            (NOW, NOW - timedelta(minutes=1), "TRAFFIC_FLOW_BAD_RANGE"),
            (
                NOW - timedelta(days=7, minutes=1),
                NOW + timedelta(minutes=1),
                "TRAFFIC_FLOW_WINDOW_TOO_LARGE",
            ),
            (
                NOW - timedelta(days=30),
                NOW - timedelta(days=29),
                "TRAFFIC_FLOW_RANGE_OUTSIDE_RETENTION",
            ),
            (
                NOW - timedelta(days=7, minutes=16),
                NOW - timedelta(days=6),
                "TRAFFIC_FLOW_RANGE_OUTSIDE_RETENTION",
            ),
        ],
    )
    def test_refused_ranges(self, since, until, code) -> None:
        with pytest.raises(TrafficFlowError) as caught:
            resolve_range(since, until, now=NOW)
        assert caught.value.code == code and caught.value.status_code == 422

    def test_the_whole_retention_is_one_allowed_range(self) -> None:
        since = NOW - timedelta(days=7)
        assert resolve_range(since, NOW, now=NOW) == (since, NOW)
        # A screen whose clock is a little behind the server's is not refused.
        late = NOW - timedelta(days=7, minutes=14)
        assert resolve_range(late, NOW - timedelta(minutes=14), now=NOW)[0] == late

    def test_the_retention_refusal_says_the_earliest_start(self) -> None:
        with pytest.raises(TrafficFlowError) as caught:
            resolve_range(NOW - timedelta(days=9), NOW - timedelta(days=8), now=NOW)
        earliest = NOW - timedelta(days=7)
        assert caught.value.data["earliest"] == earliest.isoformat()
        assert "7 days" in caught.value.message
        assert earliest.isoformat(timespec="minutes") in caught.value.message

    async def test_a_custom_range_selects_whole_windows_inside_it(
        self, backend
    ) -> None:
        await seed(backend)
        service = _service(backend)
        # 13:57 to 14:07 holds the 14:00 and 14:05 windows, not 13:55.
        out = await service.search(
            location_id=LOC_A,
            actor_user_id=USER,
            since=NOW - timedelta(minutes=13),
            until=NOW - timedelta(minutes=3),
        )
        assert out.windows == 2
        assert {r.window_start for r in out.rows} == {W2.isoformat(), W3.isoformat()}
        assert out.since == (NOW - timedelta(minutes=13)).isoformat()

    async def test_every_read_refuses_a_bad_range_before_reading(self, backend) -> None:
        await seed(backend)
        audit = Audit()
        service = _service(backend, audit)
        bad = {"since": NOW - timedelta(days=20), "until": NOW - timedelta(days=19)}
        for call in (
            service.search(location_id=LOC_A, actor_user_id=USER, **bad),
            service.export_csv(location_id=LOC_A, actor_user_id=USER, **bad),
            service.service_destinations(
                location_id=LOC_A, actor_user_id=USER, protocol=6, port=443, **bad
            ),
        ):
            with pytest.raises(TrafficFlowError) as caught:
                await call
            assert caught.value.code == "TRAFFIC_FLOW_RANGE_OUTSIDE_RETENTION"
        assert audit.entries == []


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------


class TestCsv:
    async def test_shape(self, backend) -> None:
        await seed(backend)
        export = await _service(backend).export_csv(
            location_id=LOC_A, actor_user_id=USER, sort="bytes"
        )
        lines = list(csv.reader(io.StringIO(export.text)))
        assert (
            tuple(lines[0])
            == CSV_COLUMNS
            == (
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
        )
        assert len(lines) == 11 and all(len(line) == 10 for line in lines)
        assert lines[1] == [
            W3.isoformat(),
            NOW.isoformat(),
            GOOGLE,
            "6",
            "tcp",
            "443",
            "https",
            "0",
            "9000",
            "1",
        ]
        assert (export.total, export.rows, export.truncated) == (10, 10, False)
        assert export.filename == (
            "traffic-lens-destinations-20261012T1310Z-20261012T1410Z.csv"
        )
        # A port without an IANA name is an empty cell, not the word None.
        assert "None" not in export.text
        for device in DEVICES:
            assert device not in export.text

    async def test_same_filters_as_the_search(self, backend) -> None:
        await seed(backend)
        service = _service(backend)
        filters = {"address": "142.250.0.0/16", "protocol": 17, "direction": "down"}
        page = await service.search(location_id=LOC_A, actor_user_id=USER, **filters)
        export = await service.export_csv(
            location_id=LOC_A, actor_user_id=USER, **filters
        )
        body = list(csv.reader(io.StringIO(export.text)))[1:]
        assert [(line[0], line[2], int(line[3]), int(line[5])) for line in body] == (
            _keys(page.rows)
        )
        assert export.total == page.total == 2

    async def test_a_cut_download_says_so(self, backend, monkeypatch) -> None:
        await seed(backend)
        monkeypatch.setattr(dest, "DESTINATION_CSV_MAX_ROWS", 3)
        export = await _service(backend).export_csv(
            location_id=LOC_A, actor_user_id=USER
        )
        assert (export.total, export.rows, export.truncated) == (10, 3, True)
        assert len(export.text.splitlines()) == 4
        assert DESTINATION_CSV_MAX_ROWS == 50_000

    async def test_nothing_measured_is_a_header_only_file(self, backend) -> None:
        await seed(backend)
        export = await _service(backend).export_csv(
            location_id=LOC_A,
            actor_user_id=USER,
            since=NOW - timedelta(hours=5),
            until=NOW - timedelta(hours=4),
        )
        assert export.text == ",".join(CSV_COLUMNS) + "\n"
        assert (export.total, export.rows) == (0, 0)


# ---------------------------------------------------------------------------
# drill-down
# ---------------------------------------------------------------------------


class TestServiceDrillDown:
    async def test_a_services_destinations_with_shares(self, backend) -> None:
        await seed(backend)
        out = await _service(backend).service_destinations(
            location_id=LOC_A, actor_user_id=USER, protocol=6, port=443
        )
        assert out.service is not None
        assert out.service.model_dump() == {
            "protocol": 6,
            "protocol_name": "tcp",
            "port": 443,
            "service_name": "https",
            "bytes_up": 355,
            "bytes_down": 12800,
            "bytes": 13155,
            "flows": 9,
            "exact": True,
        }
        assert [(i.address, i.bytes, i.share) for i in out.items] == [
            (GOOGLE, 12850, round(12850 / 13155, 4)),
            (V6, 300, round(300 / 13155, 4)),
            (ONE, 5, round(5 / 13155, 4)),
        ]
        assert (out.destinations_listed, out.listed_bytes) == (3, 13155)
        assert (out.unlisted_bytes, out.unlisted_share) == (0, 0.0)
        assert out.lower_bound is True

    async def test_limit_shortens_the_list_but_not_the_totals(self, backend) -> None:
        await seed(backend)
        out = await _service(backend).service_destinations(
            location_id=LOC_A, actor_user_id=USER, protocol=6, port=443, limit=1
        )
        assert [i.address for i in out.items] == [GOOGLE]
        assert (out.destinations_listed, out.listed_bytes) == (3, 13155)

    async def test_bytes_to_addresses_below_the_cut_are_reported_as_unlisted(
        self, backend
    ) -> None:
        await backend.add_venue(LOC_A, ORG_A)
        await backend.add_window(
            router_id=ROUTER_A,
            location_id=LOC_A,
            organization_id=ORG_A,
            start=W1,
            rows=_w1(),
            top_n=2,
        )
        out = await _service(backend).service_destinations(
            location_id=LOC_A, actor_user_id=USER, protocol=6, port=443
        )
        assert out.service is not None and out.service.bytes == 1955
        assert out.service.exact is True
        assert [(i.address, i.bytes) for i in out.items] == [(GOOGLE, 1650)]
        assert (out.listed_bytes, out.unlisted_bytes) == (1650, 305)
        assert out.unlisted_share == round(305 / 1955, 4)

    async def test_a_service_folded_into_other_has_an_inexact_total(
        self, backend
    ) -> None:
        await backend.add_venue(LOC_A, ORG_A)
        await backend.add_window(
            router_id=ROUTER_A,
            location_id=LOC_A,
            organization_id=ORG_A,
            start=W1,
            rows=_w1(),
            service_top_n=1,
        )
        out = await _service(backend).service_destinations(
            location_id=LOC_A, actor_user_id=USER, protocol=17, port=53
        )
        # The service buckets hold only "udp other" for this window, while
        # the destination table still lists the resolver: the larger of the
        # two lower bounds is shown, and it is said not to be exact.
        assert out.service is not None
        assert (out.service.bytes, out.service.exact) == (30, False)
        assert [(i.address, i.bytes, i.share) for i in out.items] == [(DNS, 30, 1.0)]

    async def test_a_service_with_no_traffic_is_zeros_not_unmeasured(
        self, backend
    ) -> None:
        await seed(backend)
        out = await _service(backend).service_destinations(
            location_id=LOC_A, actor_user_id=USER, protocol=6, port=22
        )
        assert out.measured is True and out.items == []
        assert out.service is not None
        assert (out.service.bytes, out.service.exact) == (0, True)
        assert out.service.service_name == "ssh"

    async def test_unmeasured_range(self, backend) -> None:
        await seed(backend)
        out = await _service(backend).service_destinations(
            location_id=LOC_A,
            actor_user_id=USER,
            protocol=6,
            port=443,
            since=NOW - timedelta(hours=5),
            until=NOW - timedelta(hours=4),
        )
        assert out.measured is False and out.service is None and out.items == []


# ---------------------------------------------------------------------------
# scoping: another organisation's venue
# ---------------------------------------------------------------------------


class TestScoping:
    async def test_another_organisations_venue_is_404_and_unaudited(
        self, backend
    ) -> None:
        await seed(backend)
        audit = Audit()
        service = _service(backend, audit)
        for call in (
            service.search(
                location_id=LOC_B, actor_user_id=USER, organization_id=ORG_A
            ),
            service.export_csv(
                location_id=LOC_B, actor_user_id=USER, organization_id=ORG_A
            ),
            service.service_destinations(
                location_id=LOC_B,
                actor_user_id=USER,
                protocol=6,
                port=443,
                organization_id=ORG_A,
            ),
        ):
            with pytest.raises(TrafficFlowError) as caught:
                await call
            # Indistinguishable from a venue that does not exist.
            assert caught.value.status_code == 404
            assert caught.value.code == "TRAFFIC_FLOW_LOCATION_NOT_FOUND"
        assert audit.entries == []

    async def test_the_statements_themselves_refuse_a_foreign_venue(
        self, backend
    ) -> None:
        """Defence in depth: even if the venue check were skipped, a scope
        carrying organisation A reads nothing of organisation B's venue."""
        await seed(backend)
        repository = backend.repository()
        crossed = DestinationScope(location_id=LOC_B, organization_id=ORG_A)
        where = {"since": HOUR_AGO, "until": NOW}
        assert await repository.window_stats(crossed, **where) == WindowStats()
        assert await repository.data_bounds(crossed) == (None, None)
        assert (
            await repository.search_totals(crossed, DestinationFilters(), **where)
        ).count == 0
        assert (
            await repository.search_page(
                crossed,
                DestinationFilters(),
                **where,
                sort="time",
                order="desc",
                limit=10,
            )
            == []
        )
        assert (
            await repository.service_destinations(
                crossed, **where, protocol=6, port=443, limit=10
            )
            == []
        )
        assert (
            await repository.service_total(crossed, **where, protocol=6, port=443)
        ) == ServiceTotal()
        # The owner does read it.
        own = DestinationScope(location_id=LOC_B, organization_id=ORG_B)
        assert (
            await repository.search_totals(own, DestinationFilters(), **where)
        ).count == 1

    async def test_one_venue_never_sees_another_venues_destination(
        self, backend
    ) -> None:
        await seed(backend)
        service = _service(backend)
        mine = await service.search(
            location_id=LOC_A, actor_user_id=USER, organization_id=ORG_A
        )
        assert ELSEWHERE not in {r.address for r in mine.rows}
        theirs = await service.search(location_id=LOC_B, actor_user_id=USER)
        assert {r.address for r in theirs.rows} == {ELSEWHERE}

    async def test_the_owner_reads_their_own_venue(self, backend) -> None:
        await seed(backend)
        out = await _service(backend).search(
            location_id=LOC_A, actor_user_id=USER, organization_id=ORG_A
        )
        assert out.total == 10


class TestMasterRoutes:
    ROUTES = (
        ("/destinations", "GET"),
        ("/destinations/export", "GET"),
        ("/services/destinations", "GET"),
    )

    @staticmethod
    def _pin(router: Any, path: str, method: str) -> dict[Any, Any]:
        route = next(r for r in router.routes if r.path == path and method in r.methods)
        closures = [
            {
                type(cell.cell_contents): cell.cell_contents
                for cell in (getattr(d.dependency, "__closure__", None) or ())
            }
            for d in route.dependencies
        ]
        pinned = [c for c in closures if ScopeType in c]
        assert pinned, (path, closures)
        return pinned[0]

    def test_every_route_is_pinned_global_on_traffic_flows_read(self) -> None:
        from app.domains.traffic_flow.destinations_router import (
            traffic_flow_destinations_platform_router as router,
        )

        assert {(r.path, *r.methods) for r in router.routes} == {
            (f"/platform/traffic-flow{path}", method) for path, method in self.ROUTES
        }
        for route in router.routes:
            (method,) = route.methods
            pin = self._pin(router, route.path, method)
            assert pin[ScopeType] == ScopeType.GLOBAL
            assert pin[str] == "traffic_flows.read"

    def test_mounted_under_the_platform_prefix(self) -> None:
        from app.api.v1.router import api_v1_router

        paths = {r.path for r in api_v1_router.routes}
        for path, _method in self.ROUTES:
            assert f"/platform/traffic-flow{path}" in paths

    def test_no_route_takes_a_device_parameter(self) -> None:
        from app.domains.traffic_flow.destinations_router import (
            traffic_flow_destinations_platform_router as router,
        )

        for route in router.routes:
            names = {p.name for p in route.dependant.query_params}
            assert names <= {
                "location_id",
                "router_id",
                "since",
                "until",
                "address",
                "protocol",
                "port",
                "direction",
                "sort",
                "order",
                "limit",
            }, names
            assert "location_id" in names
            required = {p.name for p in route.dependant.query_params if p.required}
            assert "location_id" in required

    def test_over_http(self) -> None:
        """The envelope, the CSV transport and its headers, and an error."""
        import asyncio

        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from app.common.exceptions import register_exception_handlers
        from app.domains.rbac.dependencies import CurrentUser
        from app.domains.traffic_flow import destinations_router as module

        memory = MemoryBackend()
        asyncio.run(seed(memory))
        audit = Audit()
        app = FastAPI()
        register_exception_handlers(app)
        app.include_router(module.traffic_flow_destinations_platform_router)
        user = SimpleNamespace(id=str(USER))
        app.dependency_overrides[module._READ] = lambda: user
        app.dependency_overrides[CurrentUser] = lambda: user
        app.dependency_overrides[module.get_destination_service] = lambda: (
            DestinationService(
                memory.repository(), _settings(), audit_writer=audit, now=lambda: NOW
            )
        )
        client = TestClient(app)
        base = "/platform/traffic-flow"

        missing = client.get(f"{base}/destinations")
        assert missing.status_code == 422  # location_id is required

        found = client.get(
            f"{base}/destinations",
            params={
                "location_id": str(LOC_A),
                "address": "142.250.0.0/16",
                "since": "2026-10-12T13:57:00Z",
                "until": "2026-10-12T14:07:00Z",
            },
        )
        assert found.status_code == 200, found.text
        body = found.json()
        assert body["success"] is True and body["data"]["total"] == 3
        assert body["data"]["since"] == "2026-10-12T13:57:00+00:00"

        export = client.get(
            f"{base}/destinations/export", params={"location_id": str(LOC_A)}
        )
        assert export.status_code == 200
        assert export.headers["content-type"].startswith("text/csv")
        assert export.headers["content-disposition"].startswith(
            'attachment; filename="traffic-lens-destinations-'
        )
        assert export.headers["x-total-rows"] == "10"
        assert export.headers["x-export-rows"] == "10"
        assert "x-export-truncated" not in export.headers
        assert export.text.splitlines()[0] == ",".join(CSV_COLUMNS)

        drill = client.get(
            f"{base}/services/destinations",
            params={"location_id": str(LOC_A), "protocol": 6, "port": 443},
        )
        assert drill.status_code == 200
        assert drill.json()["data"]["items"][0]["address"] == GOOGLE

        old = client.get(
            f"{base}/destinations",
            params={
                "location_id": str(LOC_A),
                "since": "2026-09-01T00:00:00Z",
                "until": "2026-09-02T00:00:00Z",
            },
        )
        assert old.status_code == 422
        assert old.json()["data"]["code"] == "TRAFFIC_FLOW_RANGE_OUTSIDE_RETENTION"

        assert [e["action"] for e in audit.entries] == [
            "traffic_flow_destinations_searched",
            "traffic_flow_destinations_exported",
            "traffic_flow_service_destinations_viewed",
        ]
        assert {e["actor_user_id"] for e in audit.entries} == {USER}


# ---------------------------------------------------------------------------
# customer routes
# ---------------------------------------------------------------------------

LOC_A2 = uuid.UUID("aaaaaaaa-0000-4000-8000-0000000000a9")


class Lookup:
    """Stands in for ``LocationService.get_location``: the real one raises
    for a missing venue and for another organisation's."""

    owner = {LOC_A: ORG_A, LOC_A2: ORG_A, LOC_B: ORG_B}

    async def get_location(self, location_id, *, requesting_organization_id=None):  # noqa: ANN001
        from app.domains.location.exceptions import (
            CrossOrganizationLocationAccessError,
            LocationNotFoundError,
        )

        if location_id not in self.owner:
            raise LocationNotFoundError(location_id)
        if self.owner[location_id] != requesting_organization_id:
            raise CrossOrganizationLocationAccessError()
        return SimpleNamespace(id=location_id, organization_id=self.owner[location_id])


def _customer(
    backend: Any,
    audit: Audit | None = None,
    *,
    confined_to: frozenset[uuid.UUID] | None = None,
) -> Any:
    """The customer service as the route builds it: the REAL venue check of
    the customer venue routes in front of the destination reads."""
    from app.domains.traffic_flow.destinations import CustomerDestinationService
    from app.domains.traffic_flow.service import TrafficFlowCustomerService

    venues = TrafficFlowCustomerService(
        object(),  # type: ignore[arg-type]
        Lookup(),
        _settings(traffic_flow_agent_url="", traffic_flow_agent_secret=""),
        caller_location_scope=confined_to,
        now=lambda: NOW,
    )
    return CustomerDestinationService(_service(backend, audit), venues)


def _dependency_calls(dependant: Any) -> set[Any]:
    calls = {d.call for d in dependant.dependencies}
    for d in dependant.dependencies:
        calls |= _dependency_calls(d)
    return calls


class TestCustomerRoutes:
    PATHS = (
        "/traffic-flow/locations/{location_id}/destinations",
        "/traffic-flow/locations/{location_id}/destinations/export",
        "/traffic-flow/locations/{location_id}/services/destinations",
    )

    @staticmethod
    def _routes() -> list[Any]:
        from app.domains.traffic_flow.destinations_customer_router import (
            traffic_flow_destinations_customer_router as router,
        )

        return list(router.routes)

    def test_read_only_and_only_these_three(self) -> None:
        assert sorted((sorted(r.methods), r.path) for r in self._routes()) == sorted(
            (["GET"], path) for path in self.PATHS
        )

    def test_every_route_carries_the_customer_venue_routes_own_guards(self) -> None:
        """Not three guards that look the same: the very same three objects,
        so the add-on key and the permission cannot drift apart."""
        from app.domains.billing.constants import PlanFeatureKey
        from app.domains.rbac.dependencies import RequireOrganization
        from app.domains.traffic_flow import customer_router

        expected = [g.dependency for g in customer_router._GUARDS]  # noqa: SLF001
        assert len(expected) == 3 and expected[0] is RequireOrganization

        def closure(call: Any) -> list[Any]:
            return [c.cell_contents for c in (getattr(call, "__closure__", None) or ())]

        assert PlanFeatureKey.TRAFFIC_FLOW in closure(expected[1])
        assert "venue_traffic.read" in closure(expected[2])
        assert ScopeType.LOCATION in closure(expected[2])
        for route in self._routes():
            guards = [d.dependency for d in route.dependencies]
            assert len(guards) == 3, route.path
            for mine, theirs in zip(guards, expected, strict=True):
                assert mine is theirs, route.path

    def test_every_route_resolves_organization_location_and_confinement(self) -> None:
        from app.domains.rbac.dependencies import (
            CurrentLocation,
            CurrentOrganization,
            RequireOrganization,
        )
        from app.domains.rbac.location_scope import CallerLocationScope

        for route in self._routes():
            calls = _dependency_calls(route.dependant)
            assert RequireOrganization in calls, route.path
            assert CurrentOrganization in calls, route.path
            assert CurrentLocation in calls, route.path
            assert CallerLocationScope in calls, route.path

    def test_no_route_takes_an_organisation_a_threshold_or_a_device(self) -> None:
        for route in self._routes():
            assert {p.name for p in route.dependant.path_params} == {"location_id"}
            names = {p.name for p in route.dependant.query_params}
            assert names <= {
                "router_id",
                "since",
                "until",
                "address",
                "protocol",
                "port",
                "direction",
                "sort",
                "order",
                "limit",
            }, (route.path, names)
            assert route.dependant.body_params == []

    def test_mounted_outside_the_platform_prefix(self) -> None:
        from app.api.v1.router import api_v1_router

        paths = {r.path for r in api_v1_router.routes}
        for path in self.PATHS:
            assert path in paths

    async def test_the_organisation_and_the_small_venue_rule_are_fixed(
        self, backend
    ) -> None:
        await seed(backend)
        audit = Audit()
        out = await _customer(backend, audit).search(
            LOC_A, organization_id=ORG_A, actor_user_id=USER
        )
        assert (out.min_devices, out.windows, out.windows_withheld) == (5, 3, 1)
        assert out.total == 8
        assert PLAIN_WEB not in {r.address for r in out.rows}
        (entry,) = audit.entries
        assert entry["event_metadata"]["console"] == "customer"
        assert entry["organization_id"] == ORG_A and entry["actor_user_id"] == USER

    async def test_a_route_cannot_switch_the_rule_off_or_name_another_venue(
        self, backend
    ) -> None:
        await seed(backend)
        service = _customer(backend)
        out = await service.search(
            LOC_A,
            organization_id=ORG_A,
            actor_user_id=USER,
            min_devices=0,
        )
        assert (out.min_devices, out.total) == (5, 8)
        with pytest.raises(TypeError):
            await service.search(
                LOC_A, organization_id=ORG_A, actor_user_id=USER, location_id=LOC_B
            )

    async def test_another_organisations_venue_is_a_404_and_nothing_is_read(
        self, backend
    ) -> None:
        from app.domains.traffic_flow.service import TrafficFlowLocationNotFoundError

        await seed(backend)
        audit = Audit()
        service = _customer(backend, audit)
        for call in (
            service.search(LOC_B, organization_id=ORG_A, actor_user_id=USER),
            service.export_csv(LOC_B, organization_id=ORG_A, actor_user_id=USER),
            service.service_destinations(
                LOC_B, organization_id=ORG_A, actor_user_id=USER, protocol=6, port=443
            ),
            # A venue that does not exist gets the same answer.
            service.search(uuid.uuid4(), organization_id=ORG_A, actor_user_id=USER),
        ):
            with pytest.raises(TrafficFlowLocationNotFoundError) as caught:
                await call
            assert caught.value.status_code == 404
            assert caught.value.data["code"] == "TRAFFIC_FLOW_LOCATION_NOT_FOUND"
        assert audit.entries == []

    async def test_a_caller_confined_to_one_venue_cannot_read_a_sibling(
        self, backend
    ) -> None:
        from app.domains.traffic_flow.service import TrafficFlowCrossLocationError

        await seed(backend)
        audit = Audit()
        service = _customer(backend, audit, confined_to=frozenset({LOC_A}))
        assert (
            await service.search(LOC_A, organization_id=ORG_A, actor_user_id=USER)
        ).total == 8
        for call in (
            service.search(LOC_A2, organization_id=ORG_A, actor_user_id=USER),
            service.export_csv(LOC_A2, organization_id=ORG_A, actor_user_id=USER),
            service.service_destinations(
                LOC_A2, organization_id=ORG_A, actor_user_id=USER, protocol=6, port=443
            ),
        ):
            with pytest.raises(TrafficFlowCrossLocationError) as caught:
                await call
            assert caught.value.status_code == 403
        assert len(audit.entries) == 1

    async def test_the_download_and_the_drill_down_follow_the_same_rules(
        self, backend
    ) -> None:
        await seed(backend)
        service = _customer(backend)
        export = await service.export_csv(
            LOC_A, organization_id=ORG_A, actor_user_id=USER
        )
        assert (export.total, export.rows) == (8, 8)
        assert PLAIN_WEB not in export.text
        drill = await service.service_destinations(
            LOC_A, organization_id=ORG_A, actor_user_id=USER, protocol=6, port=443
        )
        assert (drill.min_devices, drill.windows_withheld) == (5, 1)
        assert drill.service is not None and drill.service.bytes == 1955 + 2200

    def test_over_http(self) -> None:
        """What a customer actually receives: no platform switch, none of
        the words that describe how the data is collected, and a header
        naming another venue is refused."""
        import asyncio
        import json

        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from app.common.exceptions import register_exception_handlers
        from app.domains.rbac.dependencies import (
            CurrentLocation,
            CurrentUser,
            RequireOrganization,
        )
        from app.domains.traffic_flow import customer_router
        from app.domains.traffic_flow import destinations_customer_router as module

        memory = MemoryBackend()
        asyncio.run(seed(memory))
        audit = Audit()
        header: dict[str, uuid.UUID | None] = {"location": None}
        app = FastAPI()
        register_exception_handlers(app)
        app.include_router(module.traffic_flow_destinations_customer_router)
        user = SimpleNamespace(id=str(USER))
        for guard in customer_router._GUARDS:  # noqa: SLF001
            app.dependency_overrides[guard.dependency] = lambda: user
        app.dependency_overrides[RequireOrganization] = lambda: ORG_A
        app.dependency_overrides[CurrentLocation] = lambda: header["location"]
        app.dependency_overrides[CurrentUser] = lambda: user
        app.dependency_overrides[module.get_customer_destination_service] = lambda: (
            _customer(memory, audit)
        )
        client = TestClient(app)
        base = f"/traffic-flow/locations/{LOC_A}"

        found = client.get(f"{base}/destinations")
        assert found.status_code == 200, found.text
        data = found.json()["data"]
        assert "feature_enabled" not in data
        assert (data["min_devices"], data["windows_withheld"], data["total"]) == (
            5,
            1,
            8,
        )

        drill = client.get(
            f"{base}/services/destinations", params={"protocol": 6, "port": 443}
        )
        assert (
            drill.status_code == 200 and "feature_enabled" not in drill.json()["data"]
        )

        export = client.get(f"{base}/destinations/export", params={"port": 443})
        assert export.status_code == 200
        assert export.headers["x-total-rows"] == "6"
        assert len(export.text.splitlines()) == 7

        foreign = client.get(f"/traffic-flow/locations/{LOC_B}/destinations")
        assert foreign.status_code == 404
        old = client.get(
            f"{base}/destinations",
            params={"since": "2026-09-01T00:00:00Z", "until": "2026-09-02T00:00:00Z"},
        )
        assert old.status_code == 422
        bad = client.get(f"{base}/destinations", params={"address": "nonsense"})
        assert bad.status_code == 422

        header["location"] = LOC_A2
        crossed = client.get(f"{base}/destinations")
        assert crossed.status_code == 403
        header["location"] = LOC_A
        assert client.get(f"{base}/destinations").status_code == 200

        said = json.dumps(
            [r.json() for r in (found, drill, foreign, old, bad, crossed)]
        ).lower()
        for word in (
            "tunnel",
            "wireguard",
            "exporter",
            "collector",
            "netflow",
            "ipfix",
        ):
            assert word not in said, word
        for device in DEVICES:
            assert device not in said and device not in export.text
        assert len(audit.entries) == 4


# ---------------------------------------------------------------------------
# small-venue withholding
# ---------------------------------------------------------------------------


class TestSmallVenueRule:
    CUSTOMER = {"organization_id": ORG_A, "min_devices": 5}

    async def test_a_window_with_few_devices_contributes_no_record(
        self, backend
    ) -> None:
        await seed(backend)
        out = await _service(backend).search(
            location_id=LOC_A, actor_user_id=USER, **self.CUSTOMER
        )
        assert (out.min_devices, out.windows, out.windows_withheld) == (5, 3, 1)
        assert out.total == 8
        assert W3.isoformat() not in {r.window_start for r in out.rows}
        # The address only the two-device window reached is not shown at all.
        assert PLAIN_WEB not in {r.address for r in out.rows}
        assert out.totals is not None and out.totals.bytes == 2685 + 2603

    async def test_master_withholds_nothing(self, backend) -> None:
        await seed(backend)
        out = await _service(backend).search(location_id=LOC_A, actor_user_id=USER)
        assert (out.min_devices, out.windows_withheld, out.total) == (None, 0, 10)
        assert PLAIN_WEB in {r.address for r in out.rows}

    async def test_all_windows_withheld_is_said_not_shown_as_empty(
        self, backend
    ) -> None:
        await seed(backend)
        out = await _service(backend).search(
            location_id=LOC_A, actor_user_id=USER, since=W3, until=NOW, **self.CUSTOMER
        )
        assert out.measured is True
        assert out.windows == out.windows_withheld == 1
        assert out.total == 0 and out.rows == []
        assert out.totals is not None and out.totals.bytes == 0

    async def test_the_download_and_the_unlisted_figure_follow_the_rule(
        self, backend
    ) -> None:
        await backend.add_venue(LOC_A, ORG_A)
        await backend.add_window(
            router_id=ROUTER_A,
            location_id=LOC_A,
            organization_id=ORG_A,
            start=W3,
            rows=_w3(),
            top_n=1,
        )
        service = _service(backend)
        export = await service.export_csv(
            location_id=LOC_A, actor_user_id=USER, **self.CUSTOMER
        )
        assert export.text == ",".join(CSV_COLUMNS) + "\n" and export.total == 0
        out = await service.search(
            location_id=LOC_A, actor_user_id=USER, **self.CUSTOMER
        )
        assert out.unlisted is not None and out.unlisted.bytes == 0
        master = await service.search(location_id=LOC_A, actor_user_id=USER)
        assert master.unlisted is not None and master.unlisted.bytes == 440

    async def test_the_drill_down_follows_the_rule_and_stays_consistent(
        self, backend
    ) -> None:
        await seed(backend)
        out = await _service(backend).service_destinations(
            location_id=LOC_A, actor_user_id=USER, protocol=6, port=443, **self.CUSTOMER
        )
        assert (out.min_devices, out.windows_withheld) == (5, 1)
        # The service total leaves the withheld window out too, so the
        # shares are shares of what is shown.
        assert out.service is not None and out.service.bytes == 1955 + 2200
        assert out.items[0].address == GOOGLE and out.items[0].bytes == 3850
        assert out.listed_bytes == out.service.bytes
        plain = await _service(backend).service_destinations(
            location_id=LOC_A, actor_user_id=USER, protocol=6, port=80, **self.CUSTOMER
        )
        assert plain.items == [] and plain.service is not None
        assert plain.service.bytes == 0

    def test_the_rule_fails_closed_and_reads_only_a_count(self) -> None:
        scope = DestinationScope(
            location_id=LOC_A, organization_id=ORG_A, min_devices=5
        )
        sql = _sql(
            dest.search_page_statement(
                scope,
                DestinationFilters(),
                since=HOUR_AGO,
                until=NOW,
                sort="time",
                order="desc",
                limit=10,
            )
        )
        # A bucket is shown only if its window row exists AND had enough
        # devices: a bucket whose window row is gone is not shown.
        assert "EXISTS (SELECT" in sql and "NOT EXISTS" not in sql
        assert "traffic_flow_windows.talker_count >=" in sql
        assert "top_talkers" not in sql
        assert "EXISTS" not in _sql(
            dest.search_page_statement(
                DestinationScope(location_id=LOC_A),
                DestinationFilters(),
                since=HOUR_AGO,
                until=NOW,
                sort="time",
                order="desc",
                limit=10,
            )
        )


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------


class TestAudit:
    async def test_a_search_writes_who_which_venue_filters_and_count(
        self, backend
    ) -> None:
        await seed(backend)
        audit = Audit()
        await _service(backend, audit).search(
            location_id=LOC_A,
            actor_user_id=USER,
            address="142.250.0.0/16",
            protocol=6,
            direction="down",
            sort="bytes",
        )
        (entry,) = audit.entries
        assert entry["action"] == "traffic_flow_destinations_searched"
        assert entry["actor_user_id"] == USER
        assert (entry["entity_type"], entry["entity_id"]) == ("location", LOC_A)
        assert entry["location_id"] == LOC_A
        # The venue's organisation, looked up; not something the caller sent.
        assert entry["organization_id"] == ORG_A
        assert entry["event_metadata"] == {
            "console": "master",
            "router_id": None,
            "since": HOUR_AGO.isoformat(),
            "until": NOW.isoformat(),
            "row_count": 3,
            "filters": {
                "address": "142.250.0.0/16",
                "protocol": 6,
                "port": None,
                "direction": "down",
            },
            "sort": "bytes",
            "order": "desc",
            "returned": 3,
        }
        assert "3 record(s)" in entry["description"]
        assert len(entry["action"]) <= 50

    async def test_a_download_writes_its_own_row_with_the_rows_in_the_file(
        self, backend, monkeypatch
    ) -> None:
        await seed(backend)
        monkeypatch.setattr(dest, "DESTINATION_CSV_MAX_ROWS", 3)
        audit = Audit()
        await _service(backend, audit).export_csv(
            location_id=LOC_A, actor_user_id=USER, port=443
        )
        (entry,) = audit.entries
        assert entry["action"] == "traffic_flow_destinations_exported"
        meta = entry["event_metadata"]
        assert (meta["row_count"], meta["total"], meta["truncated"]) == (3, 7, True)
        assert meta["filters"]["port"] == 443

    async def test_a_drill_down_is_audited_with_the_service(self, backend) -> None:
        await seed(backend)
        audit = Audit()
        await _service(backend, audit).service_destinations(
            location_id=LOC_A, actor_user_id=USER, protocol=6, port=443
        )
        (entry,) = audit.entries
        assert entry["action"] == "traffic_flow_service_destinations_viewed"
        assert entry["event_metadata"]["service"] == {"protocol": 6, "port": 443}
        assert entry["event_metadata"]["row_count"] == 3

    async def test_an_empty_or_unmeasured_search_is_still_audited(
        self, backend
    ) -> None:
        await seed(backend)
        audit = Audit()
        await _service(backend, audit).search(
            location_id=LOC_A,
            actor_user_id=USER,
            since=NOW - timedelta(hours=5),
            until=NOW - timedelta(hours=4),
        )
        assert audit.entries[0]["event_metadata"]["row_count"] == 0

    async def test_a_customer_search_is_marked_as_such(self, backend) -> None:
        await seed(backend)
        audit = Audit()
        await _service(backend, audit).search(
            location_id=LOC_A, actor_user_id=USER, organization_id=ORG_A, min_devices=5
        )
        assert audit.entries[0]["event_metadata"]["console"] == "customer"
        assert audit.entries[0]["event_metadata"]["row_count"] == 8

    async def test_no_records_are_returned_if_the_audit_row_cannot_be_written(
        self, backend
    ) -> None:
        await seed(backend)
        service = _service(backend, Audit(fail=True))
        with pytest.raises(RuntimeError, match="audit store down"):
            await service.search(location_id=LOC_A, actor_user_id=USER)
        with pytest.raises(RuntimeError, match="audit store down"):
            await service.export_csv(location_id=LOC_A, actor_user_id=USER)
        with pytest.raises(RuntimeError, match="audit store down"):
            await service.service_destinations(
                location_id=LOC_A, actor_user_id=USER, protocol=6, port=443
            )

    def test_the_audit_writer_is_not_optional(self) -> None:
        with pytest.raises(TypeError):
            DestinationService(MemoryBackend().repository(), _settings())  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# statements (compiled, not executed)
# ---------------------------------------------------------------------------


def _sql(statement: Any) -> str:
    return str(statement.compile(dialect=postgresql.dialect()))


def _all_statements(scope: DestinationScope) -> dict[str, str]:
    filters = parse_filters(
        address="142.250.0.0/16", protocol=6, port=443, direction="up"
    )
    where = {"since": HOUR_AGO, "until": NOW}
    return {
        "page": _sql(
            dest.search_page_statement(
                scope, filters, **where, sort="bytes", order="asc", limit=1000
            )
        ),
        "totals": _sql(dest.search_totals_statement(scope, filters, **where)),
        "unlisted": _sql(dest.unlisted_statement(scope, **where, protocol=6)),
        "windows": _sql(dest.window_stats_statement(scope, **where)),
        "bounds": _sql(dest.data_bounds_statement(scope)),
        "service": _sql(
            dest.service_total_statement(scope, **where, protocol=6, port=443)
        ),
        "addresses": _sql(
            dest.service_destinations_statement(
                scope, **where, protocol=6, port=443, limit=10
            )
        ),
        "address_totals": _sql(
            dest.service_destination_totals_statement(
                scope, **where, protocol=6, port=443
            )
        ),
    }


class TestStatements:
    SCOPE = DestinationScope(
        location_id=LOC_A, router_id=ROUTER_A, organization_id=ORG_A, min_devices=5
    )

    def test_every_statement_is_bound_to_the_venue_router_and_organisation(
        self,
    ) -> None:
        for name, sql in _all_statements(self.SCOPE).items():
            assert ".location_id =" in sql, name
            assert ".router_id =" in sql, name
            assert ".organization_id =" in sql, name
            if name != "bounds":
                assert "window_start >=" in sql and "window_start <" in sql, name

    def test_the_search_filters_sorts_and_caps_in_the_database(self) -> None:
        sql = _all_statements(self.SCOPE)["page"]
        table = "traffic_flow_dest_buckets"
        assert f"{table}.remote_address <<= CAST(" in sql and "AS CIDR)" in sql
        assert f"{table}.protocol =" in sql and f"{table}.remote_port =" in sql
        assert f"{table}.remote_port !=" in sql  # "other" rows are not records
        assert "GROUP BY" in sql and f"HAVING sum({table}.bytes_up) >" in sql
        assert "ORDER BY" in sql and "ASC" in sql and "LIMIT" in sql
        down = _sql(
            dest.search_page_statement(
                self.SCOPE,
                parse_filters(direction="down"),
                since=HOUR_AGO,
                until=NOW,
                sort="time",
                order="desc",
                limit=5,
            )
        )
        assert f"HAVING sum({table}.bytes_down) >" in down
        assert "<<=" not in down
        assert "HAVING" not in _sql(
            dest.search_page_statement(
                self.SCOPE,
                DestinationFilters(),
                since=HOUR_AGO,
                until=NOW,
                sort="time",
                order="desc",
                limit=5,
            )
        )

    def test_the_total_counts_the_same_records_the_page_shows(self) -> None:
        statements = _all_statements(self.SCOPE)
        assert "count(*)" in statements["totals"]
        assert "LIMIT" not in statements["totals"]
        for fragment in ("<<= CAST(", "HAVING", "GROUP BY", "EXISTS (SELECT"):
            assert fragment in statements["totals"], fragment
            assert fragment in statements["page"], fragment

    def test_the_small_venue_rule_is_in_every_bucket_read(self) -> None:
        statements = _all_statements(self.SCOPE)
        for name in ("page", "totals", "unlisted", "service", "addresses"):
            assert "traffic_flow_windows.talker_count >=" in statements[name], name
        assert (
            "FILTER (WHERE traffic_flow_windows.talker_count <"
            in (statements["windows"])
        )

    def test_the_service_total_reads_the_service_buckets(self) -> None:
        sql = _all_statements(self.SCOPE)["service"]
        assert "traffic_flow_service_buckets" in sql and "bool_or" in sql
        assert "traffic_flow_dest_buckets" not in sql


# ---------------------------------------------------------------------------
# privacy: no device anywhere
# ---------------------------------------------------------------------------

#: A field or column whose name has one of these words identifies, or would
#: invite identifying, who was behind the traffic.
FORBIDDEN = {
    "client",
    "clients",
    "mac",
    "device",
    "devices",
    "guest",
    "guests",
    "session",
    "sessions",
    "talker",
    "talkers",
    "user",
    "src",
    "local",
    "host",
    "hostname",
    "nat",
}
#: The one name that has such a word and is allowed: the small-venue
#: threshold (the number 5), named as in the customer summary. A count
#: threshold, not an identifier.
ALLOWED = {"min_devices"}


def _offending(name: str) -> bool:
    return name not in ALLOWED and bool(
        set(re.split(r"[^a-z0-9]+", name.lower())) & FORBIDDEN
    )


def _keys_of(value: Any) -> set[str]:
    if isinstance(value, dict):
        out = set(value)
        for item in value.values():
            out |= _keys_of(item)
        return out
    if isinstance(value, list):
        out = set()
        for item in value:
            out |= _keys_of(item)
        return out
    return set()


class TestNoDeviceAnywhere:
    def test_the_check_itself_catches_what_it_should(self) -> None:
        for name in (
            "client_ip",
            "src_addr",
            "mac_address",
            "device_id",
            "guest_session_id",
            "top_talkers",
            "user_id",
            "nat_src",
        ):
            assert _offending(name), name
        for name in ("remote_address", "min_devices", "windows_withheld", "source"):
            assert not _offending(name), name

    def test_the_table_has_no_such_column(self) -> None:
        columns = [c.name for c in TrafficFlowDestinationBucket.__table__.columns]
        assert columns == [
            "id",
            "router_id",
            "organization_id",
            "location_id",
            "source",
            "window_start",
            "window_seconds",
            "remote_address",
            "protocol",
            "remote_port",
            "bytes_up",
            "bytes_down",
            "flows",
        ]
        assert [name for name in columns if _offending(name)] == []
        # ...and no foreign key to anything that has one.
        targets = {
            fk.column.table.name
            for fk in TrafficFlowDestinationBucket.__table__.foreign_keys
        }
        assert targets == {"routers", "organizations", "locations"}

    def test_the_migration_creates_no_such_column(self) -> None:
        ddl = "\n".join(_statements(MIGRATION)).lower()
        for word in ("client", "mac", "device", "guest", "session", "talker"):
            assert word not in ddl, word

    def test_no_response_model_has_such_a_field(self) -> None:
        seen: set[str] = set()
        for model in RESPONSE_MODELS:
            assert model.model_config.get("extra") == "forbid", model
            seen |= set(model.model_fields)
        assert {"address", "window_start", "min_devices", "rows", "items"} <= seen
        assert sorted(name for name in seen if _offending(name)) == []
        assert [name for name in CSV_COLUMNS if _offending(name)] == []

    def test_every_model_a_route_can_return_is_in_that_list(self) -> None:
        """A model added later is covered without anyone remembering to."""
        from pydantic import BaseModel

        declared = {
            value
            for value in vars(dest).values()
            if isinstance(value, type)
            and issubclass(value, BaseModel)
            and value.__module__ == dest.__name__
            and not value.__name__.startswith("_")
        }
        assert declared == set(RESPONSE_MODELS)

    def test_no_statement_reads_a_device_column(self) -> None:
        scope = DestinationScope(
            location_id=LOC_A, router_id=ROUTER_A, organization_id=ORG_A, min_devices=5
        )
        for name, sql in _all_statements(scope).items():
            lowered = sql.lower()
            for word in (
                "top_talkers",
                "top_destinations",
                "guest",
                "session",
                "mac",
                "ip_address",
                "exporter_address",
            ):
                assert word not in lowered, (name, word)
            # The only thing read about devices is how many there were.
            assert lowered.count("talker") == lowered.count("talker_count"), name

    async def test_no_real_response_carries_a_device(self, backend) -> None:
        await seed(backend)
        audit = Audit()
        service = _service(backend, audit)
        search = await service.search(location_id=LOC_A, actor_user_id=USER)
        customer = await service.search(
            location_id=LOC_A, actor_user_id=USER, organization_id=ORG_A, min_devices=5
        )
        drill = await service.service_destinations(
            location_id=LOC_A, actor_user_id=USER, protocol=6, port=443
        )
        export = await service.export_csv(location_id=LOC_A, actor_user_id=USER)
        dumped = [search.model_dump(), customer.model_dump(), drill.model_dump()]
        for payload in dumped:
            assert sorted(k for k in _keys_of(payload) if _offending(k)) == []
        everything = repr(dumped) + export.text + repr(audit.entries)
        for device in DEVICES:
            assert device not in everything, device
        assert EXPORTER not in everything


# ---------------------------------------------------------------------------
# migration (static: no database server)
# ---------------------------------------------------------------------------


class TestMigration:
    def test_revision_id_fits_and_has_one_parent(self) -> None:
        module = _migration(MIGRATION)
        assert len(module.revision) <= 32
        assert isinstance(module.down_revision, str)
        assert module.down_revision.startswith("015")

    def test_every_statement_is_a_no_op_when_already_applied(self) -> None:
        statements = _statements(MIGRATION)
        assert statements
        for statement in statements:
            assert "IF NOT EXISTS" in statement, statement
        for statement in _statements(MIGRATION, "downgrade"):
            assert "IF EXISTS" in statement, statement

    def test_it_creates_exactly_what_the_model_declares(self) -> None:
        table = TrafficFlowDestinationBucket.__table__
        ddl = "\n".join(_statements(MIGRATION))
        start = ddl.index(f"CREATE TABLE IF NOT EXISTS {table.name} ")
        body = ddl[start : ddl.index("CREATE INDEX", start)]
        columns = re.findall(
            r"(?:\( |, )([a-z_]+) "
            r"(?:BIGINT|UUID|VARCHAR|TIMESTAMPTZ|INTEGER|INET|SMALLINT)",
            body,
        )
        assert columns == [c.name for c in table.columns]
        assert (
            "uq_traffic_flow_dest_buckets_key UNIQUE (router_id, source, "
            "window_start, remote_address, protocol, remote_port)" in body
        )
        assert "remote_address INET NOT NULL" in body
        for index in table.indexes:
            assert f"CREATE INDEX IF NOT EXISTS {index.name} " in ddl, index.name
        # Postgres truncates identifiers at 63 bytes; a truncated name is a
        # different name on the next run.
        for name in re.findall(r"\b(?:pk|fk|uq|ix)_[a-z_]+", ddl):
            assert len(name) <= 63, name
