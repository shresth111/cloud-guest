"""Traffic flow: per-flow records for the Master flow table.

This is the one table of the domain where a device sits beside the address
it reached, so most of what is pinned here is a safeguard:

* nothing is written unless the record switch AND the router's export
  switch are on;
* the daily cap is never silent: storage stops, the moment is recorded, and
  every reader says "records incomplete since ...";
* a field the collector did not send is ``None`` / "not recorded", never a
  zero address, a guessed time or a derived NAT;
* the only routes are Master, GLOBAL-pinned, and every call is audited;
* retention is one setting, enforced by the sweep and by the search range.

The service and the writer run against small in-memory stand-ins. The real
statements are compiled always, and executed against a real PostgreSQL built
from the real migrations when ``TRAFFIC_FLOW_TEST_DSN`` is set (CI has no
database server, so ``TestOnPostgres`` is skipped there).
"""

from __future__ import annotations

import csv
import importlib.util
import io
import os
import pathlib
import re
import uuid
from datetime import UTC, date, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.dialects import postgresql

from app.domains.rbac.enums import ScopeType
from app.domains.traffic_flow import flow_records as fr
from app.domains.traffic_flow.flow_records import (
    CSV_COLUMNS,
    RESPONSE_MODELS,
    CappedDay,
    CapState,
    FlowRecordFilters,
    FlowRecordRepository,
    FlowRecordScope,
    FlowRecordService,
    FlowRecordWriter,
    RecordScopeTarget,
    RecordTotals,
    TrafficFlowRecord,
    TrafficFlowRecordCap,
    application_label,
    flow_record_rows,
    parse_flow_filters,
    resolve_record_range,
)
from app.domains.traffic_flow.service import TrafficFlowError, TrafficFlowIngestService
from app.domains.traffic_flow.tasks import pull_once
from tests.unit.test_traffic_flow import FakeRepo

NOW = datetime(2026, 10, 13, 9, 40, tzinfo=UTC)
W1 = NOW - timedelta(minutes=15)
W2 = NOW - timedelta(minutes=10)
HOUR_AGO = NOW - timedelta(hours=1)
ORG = uuid.UUID("aaaaaaaa-0000-4000-8000-00000000000a")
LOC = uuid.UUID("aaaaaaaa-0000-4000-8000-0000000000a1")
ROUTER = uuid.UUID("8a199617-0000-4000-8000-000000000031")
OTHER_ROUTER = uuid.UUID("aaaaaaaa-0000-4000-8000-0000000000a3")
USER = uuid.UUID("cccccccc-0000-4000-8000-00000000000c")
EXPORTER = "10.20.0.31"
VERSIONS = pathlib.Path("alembic/versions")
MIGRATION = "0162_traffic_flow_records.py"

DEVICE = "192.168.88.24"
REMOTE = "142.250.193.14"
WAN = "203.0.114.9"


@pytest.fixture(autouse=True)
def _info_logging(caplog: pytest.LogCaptureFixture) -> None:
    """INFO on, as in CI: a logger ``extra`` key that collides with a
    LogRecord attribute only raises when the record is actually built."""
    caplog.set_level("INFO", logger="app.domains.traffic_flow")


def _settings(**over: Any) -> Any:
    base = {
        "traffic_flow_enabled": True,
        "traffic_flow_records_enabled": True,
        "traffic_flow_record_retention_days": 7,
        "traffic_flow_record_daily_cap": 100_000,
        "traffic_flow_agent_url": "http://hub.invalid:9094",
        "traffic_flow_agent_secret": "s3cret",
    }
    return SimpleNamespace(**{**base, **over})


def rollup_row(src: str, dst: str, nbytes: int, **over: Any) -> dict[str, Any]:
    """A row as the collector sends it today: no times, no translation."""
    return {
        "peer_ip_src": EXPORTER,
        "ip_src": src,
        "ip_dst": dst,
        "ip_proto": "tcp",
        "port_src": 51544,
        "port_dst": 443,
        "bytes": nbytes,
        "packets": 7,
        **over,
    }


def flow_row(src: str, dst: str, nbytes: int, **over: Any) -> dict[str, Any]:
    """A row from a per-flow print plugin (COLLECTOR-FLOW-FIELDS.md)."""
    return {
        **rollup_row(src, dst, nbytes),
        "post_nat_ip_src": WAN,
        "post_nat_port_src": 40001,
        "post_nat_ip_dst": dst,
        "post_nat_port_dst": 443,
        "timestamp_start": "2026-10-13 09:25:45.000000",
        "timestamp_end": "2026-10-13 09:26:10.000000",
        "timestamp_arrival": "2026-10-13 09:26:11.000000",
        "flows": 1,
        **over,
    }


IDENTITY = {
    "router_id": ROUTER,
    "organization_id": ORG,
    "location_id": LOC,
    "source": "mikrotik_ipfix",
    "window_start": W1,
    "window_seconds": 300,
}


# ---------------------------------------------------------------------------
# reduction: nothing invented
# ---------------------------------------------------------------------------


class TestReduction:
    def test_a_per_flow_row_keeps_every_column_of_the_table(self) -> None:
        (record,) = flow_record_rows([flow_row(DEVICE, REMOTE, 33440)], EXPORTER)
        assert record == {
            "flow_start": datetime(2026, 10, 13, 9, 25, 45, tzinfo=UTC),
            "flow_end": datetime(2026, 10, 13, 9, 26, 10, tzinfo=UTC),
            "arrived_at": datetime(2026, 10, 13, 9, 26, 11, tzinfo=UTC),
            "src_address": DEVICE,
            "src_port": 51544,
            "dst_address": REMOTE,
            "dst_port": 443,
            "protocol": 6,
            "nat_src_address": WAN,
            "nat_src_port": 40001,
            "nat_dst_address": REMOTE,
            "nat_dst_port": 443,
            "bytes": 33440,
            "packets": 7,
            "flows": 1,
            "direction": "upload",
            "exporter_address": EXPORTER,
            "exporter_port": None,
        }

    def test_todays_collector_rows_leave_times_and_nat_not_recorded(self) -> None:
        (record,) = flow_record_rows([rollup_row(DEVICE, REMOTE, 10)], EXPORTER)
        for name in (
            "flow_start",
            "flow_end",
            "arrived_at",
            "nat_src_address",
            "nat_src_port",
            "nat_dst_address",
            "nat_dst_port",
            "flows",
            "exporter_port",
        ):
            assert record[name] is None, name
        assert (record["src_address"], record["dst_address"]) == (DEVICE, REMOTE)
        assert (record["bytes"], record["packets"]) == (10, 7)

    @pytest.mark.parametrize("zero", ["0.0.0.0", "::", "", "0"])  # noqa: S104
    def test_pmaccts_zero_nat_address_is_not_recorded_not_an_address(
        self, zero: str
    ) -> None:
        """pmacct prints a NAT field the router did not send as a zero
        address and a zero port, with no error."""
        (record,) = flow_record_rows(
            [
                flow_row(
                    DEVICE,
                    REMOTE,
                    1,
                    post_nat_ip_src=zero,
                    post_nat_port_src=0,
                    post_nat_ip_dst=zero,
                    post_nat_port_dst=0,
                )
            ],
            EXPORTER,
        )
        assert record["nat_src_address"] is None and record["nat_src_port"] is None
        assert record["nat_dst_address"] is None and record["nat_dst_port"] is None

    @pytest.mark.parametrize(
        "value", [0, "0", "", None, "0000-00-00 00:00:00", "1970-01-01 00:00:00", "x"]
    )
    def test_a_missing_or_zero_timestamp_is_not_recorded(self, value: Any) -> None:
        (record,) = flow_record_rows(
            [flow_row(DEVICE, REMOTE, 1, timestamp_start=value, timestamp_end=value)],
            EXPORTER,
        )
        assert record["flow_start"] is None and record["flow_end"] is None

    @pytest.mark.parametrize(
        "value",
        [1791883545, "1791883545", "1791883545.25", "2026-10-13T09:25:45+00:00"],
    )
    def test_epoch_and_iso_timestamps_are_read(self, value: Any) -> None:
        (record,) = flow_record_rows(
            [flow_row(DEVICE, REMOTE, 1, timestamp_start=value)], EXPORTER
        )
        assert record["flow_start"] is not None
        assert record["flow_start"].tzinfo is not None

    def test_the_start_is_never_taken_from_the_window(self) -> None:
        (record,) = flow_record_rows([rollup_row(DEVICE, REMOTE, 1)], EXPORTER)
        assert record["flow_start"] is None
        assert "window_start" not in record

    def test_an_absent_protocol_or_port_is_not_recorded(self) -> None:
        row = {
            "peer_ip_src": EXPORTER,
            "ip_src": DEVICE,
            "ip_dst": REMOTE,
            "bytes": 5,
        }
        (record,) = flow_record_rows([row], EXPORTER)
        assert record["protocol"] is None
        assert record["src_port"] is None and record["dst_port"] is None
        assert record["packets"] is None

    @pytest.mark.parametrize(
        ("src", "dst", "direction"),
        [
            (DEVICE, REMOTE, "upload"),
            (REMOTE, DEVICE, "download"),
            (DEVICE, "192.168.88.1", "internal"),
            (REMOTE, "8.8.8.8", "unclassified"),
        ],
    )
    def test_direction_is_which_side_is_private(self, src, dst, direction) -> None:
        (record,) = flow_record_rows([rollup_row(src, dst, 1)], EXPORTER)
        assert record["direction"] == direction

    def test_only_this_exporters_rows_and_only_real_addresses(self) -> None:
        rows = [
            rollup_row(DEVICE, REMOTE, 1),
            rollup_row(DEVICE, REMOTE, 2, peer_ip_src="10.20.0.99"),
            rollup_row("not-an-address", REMOTE, 3),
        ]
        assert [r["bytes"] for r in flow_record_rows(rows, EXPORTER)] == [1]

    def test_largest_first_so_a_cut_window_keeps_its_bulk(self) -> None:
        rows = [rollup_row(DEVICE, REMOTE, n) for n in (5, 900, 40)]
        assert [r["bytes"] for r in flow_record_rows(rows, EXPORTER)] == [900, 40, 5]

    @pytest.mark.parametrize(
        ("args", "label"),
        [
            ((6, 51544, 443, "upload"), "https (TCP/443)"),
            ((6, 443, 51544, "download"), "https (TCP/443)"),
            ((17, 40000, 19305, "upload"), "UDP/19305"),
            ((1, 0, 0, "upload"), "ICMP"),
            ((47, None, None, "upload"), "Protocol 47"),
            ((None, 1, 443, "upload"), None),
        ],
    )
    def test_application_is_a_port_label_from_the_outside_end(
        self, args, label
    ) -> None:
        assert application_label(*args) == label


# ---------------------------------------------------------------------------
# writer: the two switches and the cap
# ---------------------------------------------------------------------------


class Store:
    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []
        self.caps: dict[tuple[uuid.UUID, date], dict[str, Any]] = {}
        self.pruned: list[tuple[datetime, int]] = []

    async def cap_state(self, router_id: uuid.UUID, day: date) -> CapState:
        cap = self.caps.get((router_id, day))
        return CapState(cap["stored"], cap["capped_at"]) if cap else CapState()

    async def record_cap(
        self, *, router_id, location_id, day, stored, not_stored, capped_at
    ) -> None:  # noqa: ANN001
        cap = self.caps.setdefault(
            (router_id, day), {"stored": 0, "not_stored": 0, "capped_at": None}
        )
        cap["stored"] += stored
        cap["not_stored"] += not_stored
        cap["capped_at"] = cap["capped_at"] or capped_at

    async def insert_records(self, rows: list[dict[str, Any]]) -> None:
        self.records.extend(rows)

    async def delete_records_before(self, cutoff: datetime, *, limit: int) -> int:
        self.pruned.append((cutoff, limit))
        return 0


def _writer(store: Store, *, export_on: bool = True, **settings: Any) -> Any:
    async def enabled() -> set[uuid.UUID]:
        return {ROUTER} if export_on else set()

    return FlowRecordWriter(store, _settings(**settings), enabled_router_ids=enabled)


def _rows(n: int) -> list[dict[str, Any]]:
    return [rollup_row(DEVICE, f"142.250.1.{i + 1}", 1000 - i) for i in range(n)]


class TestWriter:
    async def test_writes_records_with_the_scoping_columns(self) -> None:
        store = Store()
        assert await _writer(store).write_window(IDENTITY, EXPORTER, _rows(3)) == 3
        assert len(store.records) == 3
        columns = {c.name for c in TrafficFlowRecord.__table__.columns} - {"id"}
        assert set(store.records[0]) == columns
        assert store.caps[(ROUTER, W1.date())] == {
            "stored": 3,
            "not_stored": 0,
            "capped_at": None,
        }

    async def test_nothing_is_written_while_the_record_switch_is_off(self) -> None:
        store = Store()
        writer = _writer(store, traffic_flow_records_enabled=False)
        assert await writer.write_window(IDENTITY, EXPORTER, _rows(3)) == 0
        assert store.records == [] and store.caps == {}

    async def test_nothing_is_written_for_a_router_whose_export_is_off(self) -> None:
        store = Store()
        writer = _writer(store, export_on=False)
        assert await writer.write_window(IDENTITY, EXPORTER, _rows(3)) == 0
        assert store.records == [] and store.caps == {}

    def test_the_record_switch_is_off_by_default(self) -> None:
        from app.core.config import Settings

        fields = Settings.model_fields
        assert fields["traffic_flow_records_enabled"].default is False
        assert fields["traffic_flow_record_retention_days"].default == 7
        assert fields["traffic_flow_record_daily_cap"].default == 100_000

    async def test_the_cap_cuts_the_window_and_records_since_when(self) -> None:
        store = Store()
        writer = _writer(store, traffic_flow_record_daily_cap=5)
        assert await writer.write_window(IDENTITY, EXPORTER, _rows(3)) == 3
        second = {**IDENTITY, "window_start": W2}
        assert await writer.write_window(second, EXPORTER, _rows(4)) == 2
        assert len(store.records) == 5
        # The two kept from the cut window are its largest.
        assert [r["bytes"] for r in store.records[3:]] == [1000, 999]
        assert store.caps[(ROUTER, W1.date())] == {
            "stored": 5,
            "not_stored": 2,
            "capped_at": W2,
        }

    async def test_after_the_cap_nothing_more_is_stored_that_day_and_it_is_counted(
        self,
    ) -> None:
        store = Store()
        writer = _writer(store, traffic_flow_record_daily_cap=2)
        await writer.write_window(IDENTITY, EXPORTER, _rows(3))
        later = {**IDENTITY, "window_start": NOW - timedelta(minutes=5)}
        assert await writer.write_window(later, EXPORTER, _rows(4)) == 0
        cap = store.caps[(ROUTER, W1.date())]
        assert len(store.records) == 2
        # "Since" stays the first moment storage stopped.
        assert (cap["stored"], cap["not_stored"], cap["capped_at"]) == (2, 5, W1)

    async def test_the_cap_is_per_utc_day(self) -> None:
        store = Store()
        writer = _writer(store, traffic_flow_record_daily_cap=2)
        await writer.write_window(IDENTITY, EXPORTER, _rows(3))
        tomorrow = {**IDENTITY, "window_start": W1 + timedelta(days=1)}
        assert await writer.write_window(tomorrow, EXPORTER, _rows(2)) == 2
        assert (
            store.caps[(ROUTER, (W1 + timedelta(days=1)).date())]["capped_at"] is None
        )

    async def test_a_cap_of_zero_stores_nothing_and_says_so(self) -> None:
        store = Store()
        writer = _writer(store, traffic_flow_record_daily_cap=0)
        assert await writer.write_window(IDENTITY, EXPORTER, _rows(2)) == 0
        assert store.caps[(ROUTER, W1.date())]["capped_at"] == W1

    async def test_retention_is_the_one_setting(self) -> None:
        store = Store()
        await _writer(store, traffic_flow_record_retention_days=3).prune(NOW)
        ((cutoff, limit),) = store.pruned
        assert cutoff == NOW - timedelta(days=3) and limit > 0


class TestIngestHook:
    async def test_written_once_with_the_window_and_rollups_do_not_depend_on_it(
        self,
    ) -> None:
        repo, store = FakeRepo(), Store()
        writer = _writer(store, traffic_flow_record_daily_cap=1)
        service = TrafficFlowIngestService(repo, flow_records=writer)  # type: ignore[arg-type]
        rows = [rollup_row(DEVICE, REMOTE, 100), rollup_row(DEVICE, "1.1.1.1", 50)]
        for _ in range(2):
            await service.ingest_window(window_start=W1, window_seconds=300, rows=rows)
        # One record (the cap), written once although the window came twice.
        assert [r["bytes"] for r in store.records] == [100]
        assert store.caps[(ROUTER, W1.date())]["not_stored"] == 1
        # The rollup has the whole window regardless of the cap.
        assert len(repo.inserted) == 1 and repo.inserted[0]["bytes_up"] == 150

    async def test_per_flow_rows_from_the_agent_are_preferred_for_records_only(
        self,
    ) -> None:
        repo, store = FakeRepo(), Store()
        service = TrafficFlowIngestService(repo, flow_records=_writer(store))  # type: ignore[arg-type]
        await service.ingest_window(
            window_start=W1,
            window_seconds=300,
            rows=[rollup_row(DEVICE, REMOTE, 100)],
            flow_rows=[flow_row(DEVICE, REMOTE, 60), flow_row(DEVICE, REMOTE, 40)],
        )
        assert [r["bytes"] for r in store.records] == [60, 40]
        assert all(r["nat_src_address"] == WAN for r in store.records)
        assert repo.inserted[0]["bytes_up"] == 100

    async def test_without_a_writer_ingest_is_what_it_was(self) -> None:
        repo = FakeRepo()
        await TrafficFlowIngestService(repo).ingest_window(  # type: ignore[arg-type]
            window_start=W1, window_seconds=300, rows=[rollup_row(DEVICE, REMOTE, 1)]
        )
        assert len(repo.inserted) == 1

    async def test_the_sweep_passes_flow_rows_and_prunes(self) -> None:
        repo, store = FakeRepo(), Store()

        async def fetch(after: int) -> dict[str, Any]:
            return {
                "windows": [
                    {
                        "window_start": int(W1.timestamp()),
                        "window_seconds": 300,
                        "rows": [rollup_row(DEVICE, REMOTE, 100)],
                        "flow_rows": [flow_row(DEVICE, REMOTE, 100)],
                    }
                ]
            }

        async def commit() -> None:
            return None

        result = await pull_once(
            repository=repo,  # type: ignore[arg-type]
            settings=_settings(),
            fetch_windows=fetch,
            commit=commit,
            now=lambda: NOW,
            flow_records=_writer(store),
        )
        assert result["written"] == 1 and result["pruned_flow_records"] == 0
        assert store.records[0]["flow_start"] is not None
        assert store.pruned[0][0] == NOW - timedelta(days=7)


# ---------------------------------------------------------------------------
# service
# ---------------------------------------------------------------------------


def _stored(**over: Any) -> Any:
    base = {
        **IDENTITY,
        **flow_record_rows([flow_row(DEVICE, REMOTE, 33440)], EXPORTER)[0],
        "id": 1,
    }
    return SimpleNamespace(**{**base, **over})


class Repo:
    def __init__(self, rows: list[Any] | None = None, *, total: int | None = None):
        self.rows = rows if rows is not None else [_stored()]
        self.total = len(self.rows) if total is None else total
        self.capped: list[CappedDay] = []
        self.exists = True
        self.calls: list[tuple[str, Any]] = []

    async def target(self, scope: FlowRecordScope) -> RecordScopeTarget | None:
        if not self.exists:
            return None
        return RecordScopeTarget(scope.location_id or LOC, scope.router_id, ORG)

    async def totals(self, scope, filters, *, since, until) -> RecordTotals:  # noqa: ANN001
        self.calls.append(("totals", filters))
        return RecordTotals(self.total, 33440 * self.total, 7 * self.total)

    async def page(self, scope, filters, *, since, until, sort, order, limit):  # noqa: ANN001
        self.calls.append(("page", (sort, order, limit, since, until)))
        return self.rows[:limit]

    async def capped_days(self, scope, *, since, until):  # noqa: ANN001
        return self.capped

    async def bounds(self, scope):  # noqa: ANN001
        return W1, W2


class Audit:
    def __init__(self, *, fail: bool = False) -> None:
        self.entries: list[dict[str, Any]] = []
        self.fail = fail

    async def create_audit_log_entry(self, **fields: Any) -> None:
        if self.fail:
            raise RuntimeError("audit store down")
        self.entries.append(fields)


def _service(repo: Any = None, audit: Audit | None = None, **settings: Any) -> Any:
    return FlowRecordService(
        repo or Repo(),
        _settings(**settings),
        audit_writer=audit or Audit(),
        now=lambda: NOW,
    )


class TestSearch:
    async def test_a_row_has_the_reference_tables_columns(self) -> None:
        out = await _service().search(actor_user_id=USER, location_id=LOC)
        assert out.rows[0].model_dump() == {
            "start": "2026-10-13T09:25:45+00:00",
            "end": "2026-10-13T09:26:10+00:00",
            "arrived_at": "2026-10-13T09:26:11+00:00",
            "window_start": W1.isoformat(),
            "window_end": (W1 + timedelta(minutes=5)).isoformat(),
            "src_address": DEVICE,
            "src_port": 51544,
            "dst_address": REMOTE,
            "dst_port": 443,
            "protocol": 6,
            "protocol_name": "tcp",
            "nat_src_address": WAN,
            "nat_src_port": 40001,
            "nat_dst_address": REMOTE,
            "nat_dst_port": 443,
            "bytes": 33440,
            "packets": 7,
            "application": "https (TCP/443)",
            "direction": "upload",
            "exporter": EXPORTER,
            "router_id": str(ROUTER),
        }
        assert out.totals.bytes == 33440 and out.totals.packets == 7
        assert (out.since, out.until) == (HOUR_AGO.isoformat(), NOW.isoformat())
        assert (out.data_oldest, out.data_newest) == (W1.isoformat(), W2.isoformat())
        assert out.retention_days == 7 and out.daily_cap == 100_000
        assert "one direction" in out.row_meaning and "not paired" in out.row_meaning

    async def test_an_exporter_port_is_shown_only_when_recorded(self) -> None:
        out = await _service(Repo([_stored(exporter_port=2060)])).search(
            actor_user_id=USER, location_id=LOC
        )
        assert out.rows[0].exporter == f"{EXPORTER}:2060"

    async def test_fields_the_collector_does_not_supply_are_named(self) -> None:
        stored = SimpleNamespace(
            **IDENTITY,
            **flow_record_rows([rollup_row(DEVICE, REMOTE, 10)], EXPORTER)[0],
            id=1,
        )
        out = await _service(Repo([stored])).search(actor_user_id=USER, location_id=LOC)
        assert out.fields_not_recorded == [
            "start",
            "end",
            "nat_src_address",
            "nat_dst_address",
            "exporter_port",
        ]
        row = out.rows[0]
        # null, never an empty string, a zero address or the window's time.
        assert (row.start, row.end, row.nat_src_address) == (None, None, None)
        assert row.window_start == W1.isoformat()
        full = await _service().search(actor_user_id=USER, location_id=LOC)
        assert full.fields_not_recorded == ["exporter_port"]

    async def test_one_capped_page_with_the_real_total(self) -> None:
        repo = Repo([_stored(id=n) for n in range(1200)], total=1834)
        out = await _service(repo).search(actor_user_id=USER, router_id=ROUTER)
        assert (out.limit, out.returned, out.total, out.truncated) == (
            1000,
            1000,
            1834,
            True,
        )
        assert out.query_ms >= 0
        assert repo.calls[1][1][2] == 1000
        assert out.totals.bytes == 33440 * 1834

    async def test_every_reader_says_records_incomplete_since(self) -> None:
        repo = Repo()
        repo.capped = [CappedDay(ROUTER, W1.date(), W2, 4200)]
        service = _service(repo)
        out = await service.search(actor_user_id=USER, location_id=LOC)
        assert out.incomplete is True
        assert out.incomplete_message is not None
        assert out.incomplete_message.startswith(
            "Records incomplete since 2026-10-13T09:30+00:00"
        )
        assert "4200 record(s)" in out.incomplete_message
        (stretch,) = out.incomplete_stretches
        assert stretch.model_dump() == {
            "router_id": str(ROUTER),
            "since": W2.isoformat(),
            "until": "2026-10-14T00:00:00+00:00",
            "records_not_stored": 4200,
        }
        export = await service.export_csv(actor_user_id=USER, location_id=LOC)
        assert export.incomplete_since == W2.isoformat()

    async def test_a_complete_range_says_nothing_about_a_cap(self) -> None:
        out = await _service().search(actor_user_id=USER, location_id=LOC)
        assert (out.incomplete, out.incomplete_message) == (False, None)
        assert out.incomplete_stretches == []

    async def test_filters_are_parsed_echoed_and_handed_to_the_statement(self) -> None:
        repo = Repo()
        out = await _service(repo).search(
            actor_user_id=USER,
            location_id=LOC,
            address="142.250.193.14/16",
            src_address=DEVICE,
            port=443,
            dst_port=443,
            protocol=6,
            sort="bytes",
            order="asc",
        )
        assert out.filters.model_dump() == {
            "address": "142.250.0.0/16",
            "src_address": DEVICE,
            "dst_address": None,
            "port": 443,
            "src_port": None,
            "dst_port": 443,
            "protocol": 6,
        }
        assert (out.sort, out.order) == ("bytes", "asc")
        assert repo.calls[0][1] == parse_flow_filters(
            address="142.250.0.0/16",
            src_address=DEVICE,
            port=443,
            dst_port=443,
            protocol=6,
        )

    @pytest.mark.parametrize(
        ("field", "kwargs"),
        [
            ("address", {"address": "nonsense"}),
            ("src_address", {"src_address": "1.2.3.4/40"}),
            ("dst_address", {"dst_address": "example.com"}),
            ("port", {"port": 70000}),
            ("protocol", {"protocol": 256}),
            ("sort", {"sort": "guest"}),
            ("order", {"order": "sideways"}),
        ],
    )
    async def test_a_bad_filter_is_refused_named_and_unaudited(
        self, field, kwargs
    ) -> None:
        audit = Audit()
        with pytest.raises(TrafficFlowError) as caught:
            await _service(audit=audit).search(
                actor_user_id=USER, location_id=LOC, **kwargs
            )
        assert caught.value.code == "TRAFFIC_FLOW_BAD_FILTER"
        assert caught.value.data["field"] == field and audit.entries == []

    async def test_a_venue_or_a_router_is_required_and_must_exist(self) -> None:
        with pytest.raises(TrafficFlowError) as none:
            await _service().search(actor_user_id=USER)
        assert none.value.code == "TRAFFIC_FLOW_SCOPE_REQUIRED"
        repo = Repo()
        repo.exists = False
        with pytest.raises(TrafficFlowError) as missing:
            await _service(repo).search(actor_user_id=USER, location_id=LOC)
        assert missing.value.status_code == 404

    async def test_nothing_is_read_while_the_feature_is_off(self) -> None:
        class OnlyTarget(Repo):
            async def totals(self, *a: Any, **k: Any) -> Any:
                raise AssertionError("read while off")

            page = capped_days = bounds = totals  # type: ignore[assignment]

        audit = Audit()
        out = await _service(OnlyTarget(), audit, traffic_flow_enabled=False).search(
            actor_user_id=USER, location_id=LOC
        )
        assert (out.feature_enabled, out.total, out.rows) == (False, 0, [])
        assert len(audit.entries) == 1

    async def test_held_records_stay_searchable_after_the_record_switch_goes_off(
        self,
    ) -> None:
        out = await _service(traffic_flow_records_enabled=False).search(
            actor_user_id=USER, location_id=LOC
        )
        assert (out.records_enabled, out.total) == (False, 1)


class TestRange:
    def _range(self, since: Any, until: Any, days: int = 7) -> Any:
        return resolve_record_range(since, until, now=NOW, retention_days=days)

    def test_default_is_the_last_hour_and_a_minute_range_is_used_as_given(self) -> None:
        assert self._range(None, None) == (HOUR_AGO, NOW)
        since = datetime(2026, 10, 12, 18, 7, tzinfo=UTC)
        until = datetime(2026, 10, 12, 18, 52, tzinfo=UTC)
        assert self._range(since, until) == (since, until)

    @pytest.mark.parametrize(
        ("since", "until", "code"),
        [
            (NOW, NOW, "TRAFFIC_FLOW_BAD_RANGE"),
            (
                NOW - timedelta(days=7, minutes=1),
                NOW + timedelta(minutes=1),
                "TRAFFIC_FLOW_WINDOW_TOO_LARGE",
            ),
            (
                NOW - timedelta(days=9),
                NOW - timedelta(days=8),
                "TRAFFIC_FLOW_RANGE_OUTSIDE_RETENTION",
            ),
        ],
    )
    def test_refused_never_shortened(self, since, until, code) -> None:
        with pytest.raises(TrafficFlowError) as caught:
            self._range(since, until)
        assert caught.value.code == code and caught.value.status_code == 422

    def test_the_bounds_follow_the_retention_setting(self) -> None:
        with pytest.raises(TrafficFlowError) as caught:
            self._range(NOW - timedelta(days=4), NOW - timedelta(days=3, hours=20), 3)
        assert caught.value.code == "TRAFFIC_FLOW_RANGE_OUTSIDE_RETENTION"
        assert caught.value.data["earliest"] == (NOW - timedelta(days=3)).isoformat()
        assert "kept for 3 days" in caught.value.message
        with pytest.raises(TrafficFlowError) as long:
            self._range(NOW - timedelta(days=3, minutes=5), NOW + timedelta(hours=1), 3)
        assert long.value.code == "TRAFFIC_FLOW_WINDOW_TOO_LARGE"


class TestCsv:
    async def test_shape_and_not_recorded_is_an_empty_cell(self) -> None:
        bare = SimpleNamespace(
            **IDENTITY,
            **flow_record_rows([rollup_row(REMOTE, DEVICE, 10)], EXPORTER)[0],
            id=2,
        )
        export = await _service(Repo([_stored(), bare])).export_csv(
            actor_user_id=USER, location_id=LOC
        )
        lines = list(csv.reader(io.StringIO(export.text)))
        assert tuple(lines[0]) == CSV_COLUMNS
        assert len(lines) == 3 and all(len(line) == len(CSV_COLUMNS) for line in lines)
        first = dict(zip(CSV_COLUMNS, lines[1], strict=True))
        assert first["start"] == "2026-10-13T09:25:45+00:00"
        assert (first["src_address"], first["src_port"]) == (DEVICE, "51544")
        assert (first["nat_src_address"], first["nat_src_port"]) == (WAN, "40001")
        assert (first["application"], first["exporter"]) == (
            "https (TCP/443)",
            EXPORTER,
        )
        second = dict(zip(CSV_COLUMNS, lines[2], strict=True))
        assert (second["start"], second["nat_src_address"]) == ("", "")
        assert second["direction"] == "download"
        assert "None" not in export.text
        assert export.filename == "traffic-lens-flows-20261013T0840Z-20261013T0940Z.csv"
        assert (export.total, export.rows, export.truncated) == (2, 2, False)

    async def test_a_cut_download_says_so(self, monkeypatch) -> None:
        monkeypatch.setattr(fr, "FLOW_RECORD_CSV_MAX_ROWS", 2)
        repo = Repo([_stored(id=n) for n in range(5)])
        export = await _service(repo).export_csv(actor_user_id=USER, location_id=LOC)
        assert (export.total, export.rows, export.truncated) == (5, 2, True)
        assert fr.FLOW_RECORD_SEARCH_LIMIT == 1000


class TestAudit:
    async def test_a_search_writes_who_what_filters_and_count(self) -> None:
        audit = Audit()
        await _service(audit=audit).search(
            actor_user_id=USER, location_id=LOC, address=DEVICE, port=443
        )
        (entry,) = audit.entries
        assert entry["action"] == "traffic_flow_records_searched"
        assert entry["actor_user_id"] == USER
        assert (entry["entity_type"], entry["entity_id"]) == ("location", LOC)
        assert (entry["location_id"], entry["organization_id"]) == (LOC, ORG)
        meta = entry["event_metadata"]
        assert meta["filters"]["address"] == DEVICE and meta["filters"]["port"] == 443
        assert (meta["row_count"], meta["returned"], meta["console"]) == (
            1,
            1,
            "master",
        )
        assert meta["since"] == HOUR_AGO.isoformat()
        assert len(entry["action"]) <= 50

    async def test_a_download_writes_its_own_row(self, monkeypatch) -> None:
        monkeypatch.setattr(fr, "FLOW_RECORD_CSV_MAX_ROWS", 2)
        audit = Audit()
        repo = Repo([_stored(id=n) for n in range(5)])
        await _service(repo, audit).export_csv(actor_user_id=USER, router_id=ROUTER)
        (entry,) = audit.entries
        assert entry["action"] == "traffic_flow_records_exported"
        meta = entry["event_metadata"]
        assert (meta["row_count"], meta["total"], meta["truncated"]) == (2, 5, True)
        assert meta["router_id"] == str(ROUTER)

    async def test_no_record_is_returned_if_the_audit_row_cannot_be_written(
        self,
    ) -> None:
        service = _service(audit=Audit(fail=True))
        with pytest.raises(RuntimeError, match="audit store down"):
            await service.search(actor_user_id=USER, location_id=LOC)
        with pytest.raises(RuntimeError, match="audit store down"):
            await service.export_csv(actor_user_id=USER, location_id=LOC)

    def test_the_audit_writer_is_not_optional(self) -> None:
        with pytest.raises(TypeError):
            FlowRecordService(Repo(), _settings())  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# routes: Master only
# ---------------------------------------------------------------------------


class TestRoutes:
    def _router(self) -> Any:
        from app.domains.traffic_flow.flow_records_router import (
            traffic_flow_records_platform_router,
        )

        return traffic_flow_records_platform_router

    def test_two_get_routes_pinned_global_on_traffic_flows_read(self) -> None:
        router = self._router()
        assert sorted((sorted(r.methods), r.path) for r in router.routes) == [
            (["GET"], "/platform/traffic-flow/flows"),
            (["GET"], "/platform/traffic-flow/flows/export"),
        ]
        for route in router.routes:
            closures = [
                {
                    type(cell.cell_contents): cell.cell_contents
                    for cell in (getattr(d.dependency, "__closure__", None) or ())
                }
                for d in route.dependencies
            ]
            (pin,) = [c for c in closures if ScopeType in c]
            assert pin[ScopeType] == ScopeType.GLOBAL
            assert pin[str] == "traffic_flows.read"

    def test_only_the_two_routers_and_the_sweep_touch_flow_records(self) -> None:
        """Nothing else in the domain imports the table or its services."""
        from app.api.v1.router import api_v1_router

        paths = {r.path for r in api_v1_router.routes}
        assert {
            p for p in paths if p.rstrip("/").endswith(("/flows", "/flows/export"))
        } == {
            "/platform/traffic-flow/flows",
            "/platform/traffic-flow/flows/export",
            "/traffic-flow/locations/{location_id}/flows",
            "/traffic-flow/locations/{location_id}/flows/export",
        }
        domain = pathlib.Path("app/domains/traffic_flow")
        own = {"flow_records.py", "flow_record_models.py"}
        importers = sorted(
            f.name
            for f in domain.glob("*.py")
            if f.name not in own
            and re.search(r"from \.flow_record(s|_models)\b", f.read_text())
        )
        assert importers == [
            "flow_records_customer_router.py",
            "flow_records_router.py",
            "models.py",
            "tasks.py",
        ]

    def test_over_http(self) -> None:
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from app.common.exceptions import register_exception_handlers
        from app.domains.rbac.dependencies import CurrentUser
        from app.domains.traffic_flow import flow_records_router as module

        repo, audit = Repo(), Audit()
        repo.capped = [CappedDay(ROUTER, W1.date(), W2, 9)]
        app = FastAPI()
        register_exception_handlers(app)
        app.include_router(module.traffic_flow_records_platform_router)
        user = SimpleNamespace(id=str(USER))
        app.dependency_overrides[module._READ] = lambda: user
        app.dependency_overrides[CurrentUser] = lambda: user
        app.dependency_overrides[module.get_flow_record_service] = lambda: (
            _service(repo, audit)
        )
        client = TestClient(app)
        base = "/platform/traffic-flow/flows"

        assert client.get(base).status_code == 422  # neither venue nor router
        found = client.get(
            base,
            params={
                "location_id": str(LOC),
                "since": "2026-10-13T09:07:00Z",
                "until": "2026-10-13T09:38:00Z",
                "address": "192.168.88.0/24",
                "protocol": 6,
            },
        )
        assert found.status_code == 200, found.text
        data = found.json()["data"]
        assert data["since"] == "2026-10-13T09:07:00+00:00"
        assert data["incomplete"] is True and data["rows"][0]["src_address"] == DEVICE
        export = client.get(f"{base}/export", params={"router_id": str(ROUTER)})
        assert export.status_code == 200
        assert export.headers["content-type"].startswith("text/csv")
        assert export.headers["x-total-rows"] == "1"
        assert export.headers["x-records-incomplete-since"] == W2.isoformat()
        assert export.text.splitlines()[0] == ",".join(CSV_COLUMNS)
        old = client.get(
            base, params={"location_id": str(LOC), "since": "2026-09-01T00:00:00Z"}
        )
        assert old.status_code == 422
        assert [e["action"] for e in audit.entries] == [
            "traffic_flow_records_searched",
            "traffic_flow_records_exported",
        ]


# ---------------------------------------------------------------------------
# customer route: own venue only, behind the second add-on
# ---------------------------------------------------------------------------

ORG_B = uuid.UUID("bbbbbbbb-0000-4000-8000-00000000000b")
LOC_A2 = uuid.UUID("aaaaaaaa-0000-4000-8000-0000000000a9")
LOC_B = uuid.UUID("bbbbbbbb-0000-4000-8000-0000000000b1")
ROUTER_B = uuid.UUID("bbbbbbbb-0000-4000-8000-0000000000b2")
OWNER = {LOC: ORG, LOC_A2: ORG, LOC_B: ORG_B}


class Lookup:
    """Stands in for ``LocationService.get_location``."""

    async def get_location(self, location_id, *, requesting_organization_id=None):  # noqa: ANN001
        from app.domains.location.exceptions import (
            CrossOrganizationLocationAccessError,
            LocationNotFoundError,
        )

        if location_id not in OWNER:
            raise LocationNotFoundError(location_id)
        if OWNER[location_id] != requesting_organization_id:
            raise CrossOrganizationLocationAccessError()
        return SimpleNamespace(id=location_id, organization_id=OWNER[location_id])


class TenantRepo(Repo):
    """Records every scope it is asked with, and knows whose venue is whose."""

    def __init__(self) -> None:
        super().__init__()
        self.scopes: list[FlowRecordScope] = []

    async def target(self, scope: FlowRecordScope) -> RecordScopeTarget | None:
        self.scopes.append(scope)
        if scope.router_id is not None:
            raise AssertionError("a customer read must never look a router up")
        if scope.location_id not in OWNER:
            return None
        return RecordScopeTarget(scope.location_id, None, OWNER[scope.location_id])

    async def totals(self, scope, filters, *, since, until):  # noqa: ANN001
        self.scopes.append(scope)
        return await super().totals(scope, filters, since=since, until=until)

    async def page(self, scope, filters, **kw):  # noqa: ANN001
        self.scopes.append(scope)
        return await super().page(scope, filters, **kw)

    async def capped_days(self, scope, *, since, until):  # noqa: ANN001
        self.scopes.append(scope)
        return self.capped

    async def bounds(self, scope):  # noqa: ANN001
        self.scopes.append(scope)
        return W1, W2


def _customer(
    repo: Any = None,
    audit: Audit | None = None,
    *,
    confined_to: frozenset[uuid.UUID] | None = None,
) -> Any:
    """As the route builds it: the REAL venue check of the customer venue
    routes in front of the record reads."""
    from app.domains.traffic_flow.flow_records import CustomerFlowRecordService
    from app.domains.traffic_flow.service import TrafficFlowCustomerService

    venues = TrafficFlowCustomerService(
        object(),  # type: ignore[arg-type]
        Lookup(),
        _settings(),
        caller_location_scope=confined_to,
        now=lambda: NOW,
    )
    return CustomerFlowRecordService(
        _service(repo if repo is not None else TenantRepo(), audit), venues
    )


def _dependency_calls(dependant: Any) -> set[Any]:
    calls = {d.call for d in dependant.dependencies}
    for d in dependant.dependencies:
        calls |= _dependency_calls(d)
    return calls


def _closure(call: Any) -> list[Any]:
    return [c.cell_contents for c in (getattr(call, "__closure__", None) or ())]


class TestCustomer:
    def _routes(self) -> list[Any]:
        from app.domains.traffic_flow.flow_records_customer_router import (
            traffic_flow_records_customer_router,
        )

        return list(traffic_flow_records_customer_router.routes)

    def test_read_only_and_only_these_two(self) -> None:
        assert sorted((sorted(r.methods), r.path) for r in self._routes()) == [
            (["GET"], "/traffic-flow/locations/{location_id}/flows"),
            (["GET"], "/traffic-flow/locations/{location_id}/flows/export"),
        ]

    def test_guards_organisation_the_second_add_on_and_the_venue_permission(
        self,
    ) -> None:
        from app.domains.billing.constants import PlanFeatureKey
        from app.domains.rbac.dependencies import (
            CurrentLocation,
            CurrentOrganization,
            RequireOrganization,
        )
        from app.domains.rbac.location_scope import CallerLocationScope

        for route in self._routes():
            guards = [d.dependency for d in route.dependencies]
            assert len(guards) == 3 and guards[0] is RequireOrganization, route.path
            feature = _closure(guards[1])
            assert PlanFeatureKey.TRAFFIC_FLOW_RECORDS in feature, route.path
            # Not the first add-on: Traffic Lens alone does not open this.
            assert PlanFeatureKey.TRAFFIC_FLOW not in feature, route.path
            permission = _closure(guards[2])
            assert "venue_traffic.read" in permission, route.path
            assert ScopeType.LOCATION in permission, route.path
            calls = _dependency_calls(route.dependant)
            for needed in (
                RequireOrganization,
                CurrentOrganization,
                CurrentLocation,
                CallerLocationScope,
            ):
                assert needed in calls, (route.path, needed)

    def test_no_route_takes_a_venue_or_an_organisation_from_the_query(self) -> None:
        for route in self._routes():
            assert {p.name for p in route.dependant.path_params} == {"location_id"}
            names = {p.name for p in _all_query_params(route.dependant)}
            assert "organization_id" not in names and "location_id" not in names
            assert names == {
                "router_id",
                "since",
                "until",
                "address",
                "src_address",
                "dst_address",
                "port",
                "src_port",
                "dst_port",
                "protocol",
                "sort",
                "order",
            }
            assert route.dependant.body_params == []

    def test_the_add_on_is_separate_off_by_default_and_master_switchable(self) -> None:
        from app.domains.billing.constants import (
            ADDON_FEATURE_KEYS,
            BOOLEAN_FEATURE_KEYS,
            FEATURE_REQUIRES,
            PlanFeatureKey,
        )

        key = PlanFeatureKey.TRAFFIC_FLOW_RECORDS
        assert key.value == "traffic_flow_records" != PlanFeatureKey.TRAFFIC_FLOW.value
        assert key in ADDON_FEATURE_KEYS and key in BOOLEAN_FEATURE_KEYS
        # It needs Traffic Lens, and Traffic Lens does not imply it.
        assert FEATURE_REQUIRES[key] is PlanFeatureKey.TRAFFIC_FLOW
        assert PlanFeatureKey.TRAFFIC_FLOW not in FEATURE_REQUIRES

    async def test_it_is_listed_for_the_master_panel_as_off(self) -> None:
        from app.domains.feature_entitlement.service import FeatureEntitlementService

        listing = await FeatureEntitlementService(None, None).list_features()  # type: ignore[arg-type]
        (feature,) = [f for f in listing.features if f.key == "traffic_flow_records"]
        assert feature.default_enabled is False and feature.type == "boolean"
        (base,) = [f for f in listing.features if f.key == "traffic_flow"]
        assert base.default_enabled is False

    async def test_the_add_on_off_is_a_402_even_with_traffic_lens_on(self) -> None:
        from app.domains.billing.exceptions import FeatureNotEntitledError

        guard = self._routes()[0].dependencies[1].dependency

        class Checker:
            def __init__(self, *features: str) -> None:
                self.features = features

            async def get_snapshot(self, organization_id: uuid.UUID) -> Any:
                return SimpleNamespace(
                    enabled_features=frozenset(self.features),
                    limits={},
                    has_feature=lambda key: key.value in self.features,
                )

        with pytest.raises(FeatureNotEntitledError) as caught:
            await guard(organization_id=ORG, checker=Checker("traffic_flow"))
        assert caught.value.status_code == 402
        assert caught.value.data["feature_key"] == "traffic_flow_records"
        assert (
            await guard(
                organization_id=ORG,
                checker=Checker("traffic_flow", "traffic_flow_records"),
            )
            == ORG
        )

    async def test_own_venue_every_statement_carries_venue_and_organisation(
        self,
    ) -> None:
        repo, audit = TenantRepo(), Audit()
        data = await _customer(repo, audit).search(
            LOC, organization_id=ORG, actor_user_id=USER, address=DEVICE
        )
        assert data["total"] == 1 and data["rows"][0]["src_address"] == DEVICE
        reads = repo.scopes[1:]
        assert len(reads) == 4
        for scope in reads:
            assert (scope.location_id, scope.organization_id) == (LOC, ORG)
        (entry,) = audit.entries
        assert entry["action"] == "traffic_flow_records_searched"
        assert entry["actor_user_id"] == USER
        assert (entry["entity_type"], entry["entity_id"]) == ("location", LOC)
        assert (entry["location_id"], entry["organization_id"]) == (LOC, ORG)
        assert entry["event_metadata"]["console"] == "customer"
        assert entry["event_metadata"]["filters"]["address"] == DEVICE

    async def test_another_organisations_venue_is_404_nothing_read_nothing_audited(
        self,
    ) -> None:
        from app.domains.traffic_flow.service import TrafficFlowLocationNotFoundError

        repo, audit = TenantRepo(), Audit()
        service = _customer(repo, audit)
        for call in (
            service.search(LOC_B, organization_id=ORG, actor_user_id=USER),
            service.export_csv(LOC_B, organization_id=ORG, actor_user_id=USER),
            service.search(uuid.uuid4(), organization_id=ORG, actor_user_id=USER),
        ):
            with pytest.raises(TrafficFlowLocationNotFoundError) as caught:
                await call
            assert caught.value.status_code == 404
        assert repo.scopes == [] and repo.calls == [] and audit.entries == []

    async def test_a_caller_confined_to_one_venue_cannot_read_a_sibling(self) -> None:
        from app.domains.traffic_flow.service import TrafficFlowCrossLocationError

        repo, audit = TenantRepo(), Audit()
        service = _customer(repo, audit, confined_to=frozenset({LOC}))
        assert (await service.search(LOC, organization_id=ORG, actor_user_id=USER))[
            "total"
        ] == 1
        with pytest.raises(TrafficFlowCrossLocationError) as caught:
            await service.search(LOC_A2, organization_id=ORG, actor_user_id=USER)
        assert caught.value.status_code == 403
        with pytest.raises(TrafficFlowCrossLocationError):
            await service.export_csv(LOC_A2, organization_id=ORG, actor_user_id=USER)
        assert len(audit.entries) == 1

    async def test_a_route_cannot_name_another_venue_or_organisation(self) -> None:
        service = _customer()
        with pytest.raises(TypeError):
            await service.search(
                LOC, organization_id=ORG, actor_user_id=USER, location_id=LOC_B
            )
        repo = TenantRepo()
        await _customer(repo).search(
            LOC, organization_id=ORG, actor_user_id=USER, **{"router_id": ROUTER_B}
        )
        # A foreign router id is never looked up (TenantRepo.target raises
        # if it is); it only narrows inside the caller's own venue.
        for scope in repo.scopes[1:]:
            assert (scope.location_id, scope.organization_id, scope.router_id) == (
                LOC,
                ORG,
                ROUTER_B,
            )

    async def test_the_boundary_does_not_rest_on_the_venue_check_alone(self) -> None:
        """Defence in depth, the cross-tenant defect class: even if the
        venue check passed a foreign venue through, the service compares the
        loaded venue's organisation itself, and the statements filter on the
        organisation column."""

        class Trusting:
            async def own_location(self, location_id, organization_id):  # noqa: ANN001
                return location_id

        from app.domains.traffic_flow.flow_records import CustomerFlowRecordService

        repo, audit = TenantRepo(), Audit()
        service = CustomerFlowRecordService(_service(repo, audit), Trusting())
        with pytest.raises(TrafficFlowError) as caught:
            await service.search(LOC_B, organization_id=ORG, actor_user_id=USER)
        assert caught.value.status_code == 404
        assert repo.calls == [] and audit.entries == []
        scope = FlowRecordScope(location_id=LOC_B, organization_id=ORG)
        for statement in (
            fr.record_page_statement(
                scope,
                FlowRecordFilters(),
                since=HOUR_AGO,
                until=NOW,
                sort="start",
                order="desc",
                limit=5,
            ),
            fr.record_totals_statement(
                scope, FlowRecordFilters(), since=HOUR_AGO, until=NOW
            ),
            fr.record_bounds_statement(scope),
        ):
            sql = _sql(statement)
            assert "traffic_flow_records.organization_id =" in sql
            assert "traffic_flow_records.location_id =" in sql
        # The cap table has no organisation column; it is bound to the venue.
        capped = _sql(fr.capped_days_statement(scope, since=HOUR_AGO, until=NOW))
        assert "traffic_flow_record_caps.location_id =" in capped

    async def test_a_customer_read_without_a_venue_fails_closed(self) -> None:
        with pytest.raises(TrafficFlowError) as caught:
            await _service().search(
                actor_user_id=USER, organization_id=ORG, router_id=ROUTER
            )
        assert caught.value.status_code == 404

    async def test_nothing_about_the_platforms_equipment_is_returned(self) -> None:
        import json

        repo = TenantRepo()
        repo.capped = [CappedDay(ROUTER, W1.date(), W2, 12)]
        service = _customer(repo)
        data = await service.search(LOC, organization_id=ORG, actor_user_id=USER)
        assert "feature_enabled" not in data and "records_enabled" not in data
        assert "exporter" not in data["rows"][0]
        assert "exporter_port" not in data["fields_not_recorded"]
        # The same notices as the Master table.
        assert data["incomplete"] is True
        assert data["incomplete_message"].startswith("Records incomplete since")
        assert (data["retention_days"], data["limit"]) == (7, 1000)
        assert data["query_ms"] >= 0
        export = await service.export_csv(LOC, organization_id=ORG, actor_user_id=USER)
        header = export.text.splitlines()[0].split(",")
        assert "exporter" not in header and header[:2] == ["start", "end"]
        assert export.incomplete_since == W2.isoformat()
        said = (json.dumps(data) + export.text).lower()
        assert EXPORTER not in said
        for word in (
            "tunnel",
            "wireguard",
            "exporter",
            "collector",
            "netflow",
            "ipfix",
        ):
            assert word not in said, word

    def test_over_http(self) -> None:
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from app.common.exceptions import register_exception_handlers
        from app.domains.rbac.dependencies import (
            CurrentLocation,
            CurrentUser,
            RequireOrganization,
        )
        from app.domains.traffic_flow import flow_records_customer_router as module

        audit = Audit()
        header: dict[str, uuid.UUID | None] = {"location": None}
        app = FastAPI()
        register_exception_handlers(app)
        app.include_router(module.traffic_flow_records_customer_router)
        user = SimpleNamespace(id=str(USER))
        for guard in module._GUARDS:
            app.dependency_overrides[guard.dependency] = lambda: user
        app.dependency_overrides[RequireOrganization] = lambda: ORG
        app.dependency_overrides[CurrentLocation] = lambda: header["location"]
        app.dependency_overrides[CurrentUser] = lambda: user
        app.dependency_overrides[module.get_customer_flow_record_service] = lambda: (
            _customer(TenantRepo(), audit)
        )
        client = TestClient(app)
        base = f"/traffic-flow/locations/{LOC}/flows"

        found = client.get(base, params={"port": 443, "since": "2026-10-13T09:07:00Z"})
        assert found.status_code == 200, found.text
        data = found.json()["data"]
        assert data["filters"]["port"] == 443 and "exporter" not in data["rows"][0]
        export = client.get(f"{base}/export")
        assert export.status_code == 200
        assert export.headers["content-type"].startswith("text/csv")
        assert export.headers["x-total-rows"] == "1"
        assert client.get(f"/traffic-flow/locations/{LOC_B}/flows").status_code == 404
        # A venue named in the query cannot replace the one in the path.
        ignored = client.get(base, params={"location_id": str(LOC_B)})
        assert ignored.status_code == 200
        assert ignored.json()["data"]["location_id"] == str(LOC)
        header["location"] = LOC_A2
        assert client.get(base).status_code == 403
        header["location"] = None
        assert [e["action"] for e in audit.entries] == [
            "traffic_flow_records_searched",
            "traffic_flow_records_exported",
            "traffic_flow_records_searched",
        ]
        assert {e["actor_user_id"] for e in audit.entries} == {USER}
        assert {e["location_id"] for e in audit.entries} == {LOC}


def _all_query_params(dependant: Any) -> list[Any]:
    out = list(dependant.query_params)
    for child in dependant.dependencies:
        out.extend(_all_query_params(child))
    return out


# ---------------------------------------------------------------------------
# statements (compiled) and the migration (static)
# ---------------------------------------------------------------------------


def _sql(statement: Any) -> str:
    return str(statement.compile(dialect=postgresql.dialect()))


def _statements(filename: str, fn: str = "upgrade") -> list[str]:
    out: list[str] = []

    class _Op:
        def execute(self, sql: Any) -> None:
            out.append(" ".join(str(sql).split()))

        def __getattr__(self, name: str) -> Any:
            raise AssertionError(f"op.{name} is not guarded; use op.execute")

    spec = importlib.util.spec_from_file_location(
        filename.removesuffix(".py"), VERSIONS / filename
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.op = _Op()
    getattr(module, fn)()
    return out


class TestStatements:
    SCOPE = FlowRecordScope(location_id=LOC, router_id=ROUTER)

    def test_the_search_filters_sorts_and_caps_in_the_database(self) -> None:
        filters = parse_flow_filters(
            address="142.250.0.0/16", src_address=DEVICE, port=443, protocol=6
        )
        sql = _sql(
            fr.record_page_statement(
                self.SCOPE,
                filters,
                since=HOUR_AGO,
                until=NOW,
                sort="start",
                order="desc",
                limit=1000,
            )
        )
        table = "traffic_flow_records"
        assert f"{table}.location_id =" in sql and f"{table}.router_id =" in sql
        assert "window_start >=" in sql and "window_start <" in sql
        # "address" is either end, before or after translation.
        for column in (
            "src_address",
            "dst_address",
            "nat_src_address",
            "nat_dst_address",
        ):
            assert f"{table}.{column} <<= CAST(" in sql, column
        assert f"{table}.src_port =" in sql and f"{table}.dst_port =" in sql
        assert f"{table}.protocol =" in sql
        assert "coalesce(traffic_flow_records.flow_start" in sql
        assert "NULLS LAST" in sql and "LIMIT" in sql
        totals = _sql(
            fr.record_totals_statement(self.SCOPE, filters, since=HOUR_AGO, until=NOW)
        )
        assert "count(*)" in totals and "LIMIT" not in totals and "<<= CAST(" in totals

    def test_the_cap_upsert_adds_and_keeps_the_first_capped_at(self) -> None:
        sql = " ".join(
            _statements(MIGRATION)
        )  # the unique key the upsert relies on exists
        assert "uq_traffic_flow_record_caps_key UNIQUE (router_id, day)" in sql
        unique = {
            tuple(c.name for c in constraint.columns)
            for constraint in TrafficFlowRecordCap.__table__.constraints
            if constraint.__class__.__name__ == "UniqueConstraint"
        }
        assert unique == {("router_id", "day")}

    def test_capped_days_and_retention_statements(self) -> None:
        capped = _sql(fr.capped_days_statement(self.SCOPE, since=HOUR_AGO, until=NOW))
        assert "capped_at IS NOT NULL" in capped and "capped_at <" in capped
        assert "traffic_flow_record_caps.day >=" in capped
        assert "traffic_flow_record_caps.router_id =" in capped
        prune = _sql(fr.record_delete_statement(NOW, limit=10))
        assert "window_start <" in prune and "LIMIT" in prune
        assert "traffic_flow_record_caps.day <" in _sql(fr.cap_delete_statement(NOW))


class TestMigration:
    def test_idempotent_and_matches_the_models(self) -> None:
        statements = _statements(MIGRATION)
        for statement in statements:
            assert "IF NOT EXISTS" in statement, statement
        for statement in _statements(MIGRATION, "downgrade"):
            assert "IF EXISTS" in statement, statement
        ddl = "\n".join(statements)
        for model in (TrafficFlowRecord, TrafficFlowRecordCap):
            table = model.__table__
            start = ddl.index(f"CREATE TABLE IF NOT EXISTS {table.name} ")
            body = ddl[start : ddl.index("CREATE INDEX", start)]
            columns = re.findall(
                r"(?:\( |, )([a-z_]+) "
                r"(?:BIGINT|UUID|VARCHAR|TIMESTAMPTZ|INTEGER|INET|SMALLINT|DATE)",
                body,
            )
            assert columns == [c.name for c in table.columns], table.name
            for index in table.indexes:
                assert f"CREATE INDEX IF NOT EXISTS {index.name} " in ddl, index.name
        for name in re.findall(r"\b(?:pk|fk|uq|ix)_[a-z_]+", ddl):
            assert len(name) <= 63, name

    def test_optional_fields_are_nullable_and_have_no_default(self) -> None:
        """NULL is "not recorded". A default of 0 would turn an unrecorded
        NAT port or packet count into a recorded zero."""
        columns = TrafficFlowRecord.__table__.columns
        for name in (
            "flow_start",
            "flow_end",
            "arrived_at",
            "src_port",
            "dst_port",
            "protocol",
            "nat_src_address",
            "nat_src_port",
            "nat_dst_address",
            "nat_dst_port",
            "packets",
            "flows",
            "exporter_port",
        ):
            assert columns[name].nullable, name
            assert columns[name].default is None, name
        ddl = " ".join(_statements(MIGRATION))
        assert "nat_src_address INET NULL" in ddl and "packets BIGINT NULL" in ddl

    def test_revision(self) -> None:
        spec = importlib.util.spec_from_file_location("m", VERSIONS / MIGRATION)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        assert len(module.revision) <= 32 and isinstance(module.down_revision, str)

    def test_every_response_model_forbids_extras(self) -> None:
        from pydantic import BaseModel

        declared = {
            value
            for value in vars(fr).values()
            if isinstance(value, type)
            and issubclass(value, BaseModel)
            and value.__module__ == fr.__name__
            and not value.__name__.startswith("_")
        }
        assert declared == set(RESPONSE_MODELS)
        for model in RESPONSE_MODELS:
            assert model.model_config.get("extra") == "forbid"
        # No name, phone, MAC or guest reference rides along with a flow.
        fields = set().union(*(set(m.model_fields) for m in RESPONSE_MODELS))
        assert not {
            f for f in fields if re.search(r"guest|session|mac|phone|name$", f)
        } - {"protocol_name"}


# ---------------------------------------------------------------------------
# the real statements on a real PostgreSQL (opt-in)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not os.environ.get("TRAFFIC_FLOW_TEST_DSN"),
    reason="TRAFFIC_FLOW_TEST_DSN is not set (no database server in CI)",
)
class TestOnPostgres:
    async def test_write_cap_search_and_prune(self) -> None:
        from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
        from sqlalchemy.pool import NullPool

        engine = create_async_engine(
            os.environ["TRAFFIC_FLOW_TEST_DSN"], poolclass=NullPool
        )
        async with engine.begin() as connection:
            for table in (
                "traffic_flow_record_caps",
                "traffic_flow_records",
                "routers",
                "locations",
                "organizations",
            ):
                await connection.execute(text(f"DROP TABLE IF EXISTS {table} CASCADE"))
            await connection.execute(
                text("CREATE TABLE organizations (id UUID PRIMARY KEY)")
            )
            await connection.execute(
                text(
                    "CREATE TABLE locations (id UUID PRIMARY KEY, organization_id "
                    "UUID, is_deleted BOOLEAN NOT NULL DEFAULT false)"
                )
            )
            await connection.execute(
                text(
                    "CREATE TABLE routers (id UUID PRIMARY KEY, location_id UUID, "
                    "organization_id UUID, is_deleted BOOLEAN NOT NULL DEFAULT false)"
                )
            )
            for _ in range(2):  # the second run must be a no-op
                for statement in _statements(MIGRATION):
                    await connection.execute(text(statement))
            await connection.execute(
                text("INSERT INTO organizations VALUES (:o)"), {"o": ORG}
            )
            await connection.execute(
                text("INSERT INTO locations VALUES (:l, :o)"), {"l": LOC, "o": ORG}
            )
            for router in (ROUTER, OTHER_ROUTER):
                await connection.execute(
                    text("INSERT INTO routers VALUES (:r, :l, :o)"),
                    {"r": router, "l": LOC, "o": ORG},
                )
        async with AsyncSession(engine, expire_on_commit=False) as session:
            repository = FlowRecordRepository(session)

            async def enabled() -> set[uuid.UUID]:
                return {ROUTER}

            writer = FlowRecordWriter(
                repository,
                _settings(traffic_flow_record_daily_cap=4),
                enabled_router_ids=enabled,
            )
            first = [
                flow_row(DEVICE, REMOTE, 900),
                flow_row(REMOTE, DEVICE, 5000, port_src=443, port_dst=51544),
                rollup_row(DEVICE, "8.8.8.8", 40, ip_proto="udp", port_dst=53),
            ]
            assert await writer.write_window(IDENTITY, EXPORTER, first) == 3
            second = [
                flow_row("fd00::16", "2404:6800:4003::200e", 700),
                flow_row(DEVICE, "1.1.1.1", 600),
                flow_row(DEVICE, "9.9.9.9", 500),
            ]
            later = {**IDENTITY, "window_start": W2}
            assert await writer.write_window(later, EXPORTER, second) == 1
            # A router whose export is off writes nothing.
            other = {**IDENTITY, "router_id": OTHER_ROUTER}
            assert await writer.write_window(other, EXPORTER, first) == 0
            await session.flush()

            assert await repository.cap_state(ROUTER, W1.date()) == CapState(4, W2)
            service = FlowRecordService(
                repository, _settings(), audit_writer=Audit(), now=lambda: NOW
            )
            out = await service.search(actor_user_id=USER, location_id=LOC)
            assert (out.total, out.returned) == (4, 4)
            assert (
                out.incomplete and out.incomplete_stretches[0].records_not_stored == 2
            )
            assert out.incomplete_stretches[0].since == W2.isoformat()
            assert out.totals.bytes == 900 + 5000 + 40 + 700
            # Newest first. The three timed records share a start, so the
            # later window leads and the rest keep insertion order (largest
            # first); the record without a start sorts by its window, last.
            assert [r.bytes for r in out.rows] == [700, 5000, 900, 40]
            assert out.rows[3].start is None and out.rows[3].nat_src_address is None
            assert out.rows[0].src_address == "fd00::16"
            assert out.rows[1].nat_src_address == WAN

            async def count(**filters: Any) -> int:
                return (
                    await service.search(actor_user_id=USER, location_id=LOC, **filters)
                ).total

            assert await count(address=DEVICE) == 3
            assert await count(address="192.168.88.0/24") == 3
            assert await count(address=WAN) == 3  # matched on the translation only
            assert await count(src_address=DEVICE) == 2
            assert await count(dst_address=DEVICE) == 1
            assert await count(address="2404:6800::/32") == 1
            assert await count(port=443) == 3
            assert await count(src_port=443) == 1
            assert await count(dst_port=53) == 1
            assert await count(protocol=17) == 1
            assert await count(protocol=6, port=443, address=REMOTE) == 2
            assert await count(router_id=OTHER_ROUTER) == 0
            assert await count(since=W2, until=NOW) == 1

            by_bytes = await service.search(
                actor_user_id=USER, location_id=LOC, sort="bytes", order="asc"
            )
            assert [r.bytes for r in by_bytes.rows] == [40, 700, 900, 5000]
            export = await service.export_csv(actor_user_id=USER, router_id=ROUTER)
            assert (export.total, export.rows) == (4, 4)
            assert export.incomplete_since == W2.isoformat()

            assert await repository.target(FlowRecordScope(router_id=ROUTER)) == (
                RecordScopeTarget(LOC, ROUTER, ORG)
            )
            assert (
                await repository.target(FlowRecordScope(location_id=uuid.uuid4()))
                is None
            )

            assert await repository.delete_records_before(W2, limit=100) == 3
            assert await count() == 1
            await repository.delete_records_before(NOW + timedelta(days=2), limit=100)
            assert await repository.cap_state(ROUTER, W1.date()) == CapState()
            assert (
                await repository.capped_days(
                    FlowRecordScope(location_id=LOC), since=HOUR_AGO, until=NOW
                )
                == []
            )
            await session.rollback()
        await engine.dispose()


def test_filters_dataclass_default_is_no_filter() -> None:
    assert parse_flow_filters() == FlowRecordFilters()
