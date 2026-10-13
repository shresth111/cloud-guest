"""Traffic flow: platform overhead.

A managed router keeps a tunnel to the platform's hub; its own traffic to the
platform is not the venue's. Seen on a live venue: "UDP/51820 was 66% of your
traffic in the last hour", which was the router's management tunnel.

* **Classification** -- both directions, inside the tunnel and the tunnel
  itself, and what must NOT match: a venue's own WireGuard to anywhere else.
* **Totals add up** -- overhead is counted, once, and in nothing else.
* **Each view** -- window totals, service and destination buckets, the
  country writer's input, top devices and destinations, flow records, the
  summary, the Destinations statements and the findings.
* **History** -- windows stored before the change are corrected on read from
  their destination buckets.

Addresses: outside ends, the stand-in hub included, are well-known public
resolvers, because the reducer treats the documentation ranges as private.
No address here is the platform's.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy.dialects import postgresql

from app.core.config import Settings
from app.domains.traffic_flow import destinations as dest
from app.domains.traffic_flow.destination_buckets import (
    TrafficFlowDestinationBucket,
    destination_rows,
)
from app.domains.traffic_flow.destinations import DestinationScope, ServiceTotal
from app.domains.traffic_flow.findings import HourRow, unusual_service_candidates
from app.domains.traffic_flow.findings_service import (
    FindingsRepository,
    address_rows_statement,
    platform_overhead_statement,
)
from app.domains.traffic_flow.flow_record_models import TrafficFlowRecord
from app.domains.traffic_flow.flow_records import (
    DIRECTION_INTERNAL,
    DIRECTION_PLATFORM,
    DIRECTION_UP,
    FlowRecordScope,
    flow_record_rows,
    prepare_records,
)
from app.domains.traffic_flow.ingest import reduce_window, service_rows
from app.domains.traffic_flow.models import TrafficFlowWindow
from app.domains.traffic_flow.platform_overhead import (
    NO_PLATFORM_ENDPOINTS,
    PLATFORM_OVERHEAD_NOTE,
    PlatformEndpoints,
    platform_endpoints_from,
    platform_endpoints_of,
)
from app.domains.traffic_flow.service import (
    ExporterRouter,
    SummaryScope,
    TrafficFlowCustomerService,
    TrafficFlowIngestService,
    TrafficFlowSummaryService,
    history_overhead_statement,
)
from app.domains.traffic_flow.summary import (
    ServiceStepRow,
    build_summary,
    step_start_of,
)

NOW = datetime(2026, 10, 13, 9, 0, tzinfo=UTC)
ROUTER_ID = uuid.UUID("8a199617-0000-4000-8000-000000000031")
LOC = uuid.UUID("a1a1a1a1-0000-4000-8000-000000000001")
ORG = uuid.UUID("aaaaaaaa-0000-4000-8000-00000000000a")

EXPORTER = "10.20.0.31"  # the router's tunnel address
HUB_TUNNEL = "10.20.0.1"
# A stand-in for the hub's public endpoint. It has to be an address the
# reducer treats as public (documentation ranges count as private there), so
# a well-known public resolver's second address is borrowed.
HUB = "8.8.4.4"
HUB_PORT = 51820
HUB6 = "2001:db8:aa::10"
ROUTER_WAN = "100.64.7.20"  # the router's WAN side behind carrier NAT
GUEST = "192.168.88.24"
OTHER_VPN = "9.9.9.9"  # somebody's own WireGuard server, same port
NTP = "1.1.1.1"

PLATFORM = platform_endpoints_from([(HUB, HUB_PORT)])


@pytest.fixture(autouse=True)
def _info_logging(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level("INFO", logger="app.domains.traffic_flow")


def row(
    src: str,
    dst: str,
    nbytes: int,
    *,
    proto: Any = "udp",
    sport: int | None = 40000,
    dport: int | None = 443,
    packets: int = 1,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "peer_ip_src": EXPORTER,
        "ip_src": src,
        "ip_dst": dst,
        "bytes": nbytes,
        "packets": packets,
        "flows": 1,
    }
    if proto is not None:
        out["ip_proto"] = proto
    if sport is not None:
        out["port_src"] = sport
    if dport is not None:
        out["port_dst"] = dport
    return out


TUNNEL_UP = row(ROUTER_WAN, HUB, 6600, sport=13231, dport=HUB_PORT)
TUNNEL_DOWN = row(HUB, ROUTER_WAN, 3300, sport=HUB_PORT, dport=13231)
IN_TUNNEL_UP = row(EXPORTER, HUB_TUNNEL, 900, proto="tcp", sport=50123, dport=8728)
IN_TUNNEL_DOWN = row(HUB_TUNNEL, EXPORTER, 400, proto="tcp", sport=8728, dport=50123)
ROUTER_NTP = row(ROUTER_WAN, NTP, 3000, sport=123, dport=123)
GUEST_WEB_UP = row(GUEST, "8.8.8.8", 100, proto="tcp", dport=443)
GUEST_WEB_DOWN = row("8.8.8.8", GUEST, 900, proto="tcp", sport=443, dport=51000)
GUEST_OWN_VPN_UP = row(GUEST, OTHER_VPN, 700, sport=51111, dport=HUB_PORT)
GUEST_OWN_VPN_DOWN = row(OTHER_VPN, GUEST, 7000, sport=HUB_PORT, dport=51111)


# ---------------------------------------------------------------------------
# classification
# ---------------------------------------------------------------------------


class TestClassification:
    @pytest.mark.parametrize(
        ("collector_row", "want"),
        [
            (TUNNEL_UP, "up"),
            (TUNNEL_DOWN, "down"),
            (IN_TUNNEL_UP, "up"),
            (IN_TUNNEL_DOWN, "down"),
        ],
    )
    def test_the_routers_traffic_to_the_platform_in_both_directions(
        self, collector_row: dict[str, Any], want: str
    ) -> None:
        assert PLATFORM.row_direction(collector_row) == want

    @pytest.mark.parametrize(
        "collector_row",
        [
            GUEST_OWN_VPN_UP,  # same protocol, same port, another address
            GUEST_OWN_VPN_DOWN,
            ROUTER_NTP,  # the router's own traffic, but not to the platform
            GUEST_WEB_UP,
            GUEST_WEB_DOWN,
            # The hub's address on another port, or over TCP, is not the tunnel.
            row(ROUTER_WAN, HUB, 10, dport=443),
            row(ROUTER_WAN, HUB, 10, proto="tcp", dport=HUB_PORT),
            # The hub's port as the LOCAL port of a row to somewhere else.
            row(GUEST, "8.8.8.8", 10, sport=HUB_PORT, dport=53),
        ],
    )
    def test_everything_else_is_left_alone(self, collector_row: dict[str, Any]) -> None:
        assert PLATFORM.row_direction(collector_row) is None

    def test_a_venues_own_wireguard_is_not_hidden_even_on_the_same_port(
        self,
    ) -> None:
        """The reason the port alone is never enough: 51820 is every
        WireGuard server's default."""
        reduced = reduce_window([GUEST_OWN_VPN_UP, GUEST_OWN_VPN_DOWN], PLATFORM)[
            EXPORTER
        ]
        assert reduced.overhead_rows == 0
        assert reduced.services == {(17, HUB_PORT): [700, 7000, 2]}
        assert list(reduced.destinations) == [OTHER_VPN]
        assert (reduced.bytes_up, reduced.bytes_down) == (700, 7000)

    def test_in_tunnel_traffic_needs_no_configuration(self) -> None:
        """An end that is the exporter itself. Known from the row alone."""
        assert NO_PLATFORM_ENDPOINTS.row_direction(IN_TUNNEL_UP) == "up"
        assert NO_PLATFORM_ENDPOINTS.row_direction(IN_TUNNEL_DOWN) == "down"
        # ...but the tunnel's outer packets cannot be told without the hub.
        assert NO_PLATFORM_ENDPOINTS.row_direction(TUNNEL_UP) is None

    def test_protocol_by_number_or_name_and_ports_as_text(self) -> None:
        for proto in (17, "17", "udp", "UDP"):
            assert PLATFORM.row_direction({**TUNNEL_UP, "ip_proto": proto}) == "up"
        assert PLATFORM.row_direction({**TUNNEL_UP, "port_dst": str(HUB_PORT)}) == "up"

    def test_rows_without_protocol_and_ports_cannot_match_the_tunnel(self) -> None:
        bare = row(ROUTER_WAN, HUB, 10, proto=None, sport=None, dport=None)
        assert PLATFORM.row_direction(bare) is None

    def test_ipv6_hub_and_one_spelling_per_address(self) -> None:
        platform = platform_endpoints_from([("2001:DB8:AA:0::10", HUB_PORT)])
        assert platform.endpoints == frozenset({(HUB6, HUB_PORT)})
        assert (
            platform.row_direction(row("2001:db8:1::2", HUB6, 5, dport=HUB_PORT))
            == "up"
        )

    def test_a_hostname_endpoint_is_reported_not_guessed(self) -> None:
        platform = platform_endpoints_from([("hub.example.net", HUB_PORT)])
        assert not platform and platform.unresolved_hosts == ("hub.example.net",)
        assert platform.row_direction(TUNNEL_UP) is None
        # The setting supplies the addresses; the port comes from the table.
        platform = platform_endpoints_from(
            [("hub.example.net", HUB_PORT)], [HUB, "junk"]
        )
        assert platform.endpoints == frozenset({(HUB, HUB_PORT)})
        assert platform.row_direction(TUNNEL_UP) == "up"

    def test_two_hubs_and_no_hub(self) -> None:
        platform = platform_endpoints_from([(HUB, HUB_PORT), ("198.51.100.20", 13231)])
        assert platform.addresses == frozenset({HUB, "198.51.100.20"})
        assert platform.is_endpoint("198.51.100.20", 17, 13231)
        assert not platform.is_endpoint("198.51.100.20", 17, HUB_PORT)
        assert not platform_endpoints_from([])
        assert platform_endpoints_from([(HUB, None)]).endpoints == frozenset()

    def test_setting_defaults_to_empty_and_no_address_is_in_the_code(self) -> None:
        assert Settings().traffic_flow_platform_addresses == ""
        source = pathlib.Path(
            "app/domains/traffic_flow/platform_overhead.py"
        ).read_text()
        import re

        assert not re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", source)
        assert "51820" not in source

    async def test_endpoints_come_through_the_repository_or_not_at_all(self) -> None:
        class WithLoader:
            async def platform_endpoints(self, settings: Any) -> PlatformEndpoints:
                return PLATFORM

        assert await platform_endpoints_of(WithLoader(), None) is PLATFORM
        assert await platform_endpoints_of(object(), None) is NO_PLATFORM_ENDPOINTS


# ---------------------------------------------------------------------------
# the reducer: totals add up, and overhead is in nothing else
# ---------------------------------------------------------------------------

IDLE_VENUE = [TUNNEL_UP, TUNNEL_DOWN, IN_TUNNEL_UP, IN_TUNNEL_DOWN, ROUTER_NTP]
BUSY_VENUE = [*IDLE_VENUE, GUEST_WEB_UP, GUEST_WEB_DOWN, GUEST_OWN_VPN_UP]


class TestReducer:
    def test_totals_add_up_with_overhead_counted_once(self) -> None:
        w = reduce_window(BUSY_VENUE, PLATFORM)[EXPORTER]
        assert (w.overhead_bytes_up, w.overhead_bytes_down) == (7500, 3700)
        assert w.overhead_rows == 4
        assert (w.bytes_up, w.bytes_down) == (3000 + 100 + 700, 900)
        assert (w.bytes_internal, w.bytes_unclassified) == (0, 0)
        assert w.bytes_total == sum(r["bytes"] for r in BUSY_VENUE)
        assert w.bytes_total == (
            w.bytes_up
            + w.bytes_down
            + w.bytes_internal
            + w.bytes_unclassified
            + w.overhead_bytes_up
            + w.overhead_bytes_down
        )

    def test_overhead_is_in_no_list_and_no_bucket(self) -> None:
        w = reduce_window(BUSY_VENUE, PLATFORM)[EXPORTER]
        everything = json.dumps(
            [
                sorted(w.talkers),
                sorted(w.destinations),
                sorted(map(str, w.services)),
                sorted(map(str, w.destination_services)),
                service_rows(w),
                destination_rows(w),
            ]
        )
        assert HUB not in everything and HUB_TUNNEL not in everything
        assert EXPORTER not in everything
        # The guest's own VPN on the same port is still there, alone.
        assert w.services[(17, HUB_PORT)] == [700, 0, 1]
        assert not [r for r in destination_rows(w) if r["remote_address"] == HUB]
        # Buckets still add up to client traffic exactly.
        assert sum(r["bytes_up"] + r["bytes_down"] for r in service_rows(w)) == (
            w.bytes_up + w.bytes_down
        )

    def test_the_idle_venue_is_no_longer_mostly_its_own_tunnel(self) -> None:
        """The defect as reported: the tunnel 66%, NTP second."""
        before = reduce_window(IDLE_VENUE)[EXPORTER]
        top = max(before.services.items(), key=lambda kv: kv[1][0] + kv[1][1])
        assert top[0] == (17, HUB_PORT)  # what the customer was shown
        after = reduce_window(IDLE_VENUE, PLATFORM)[EXPORTER]
        assert list(after.services) == [(17, 123)]
        assert (17, HUB_PORT) not in after.services
        # The router's WAN address is a "device" only for its NTP now.
        assert after.talkers[ROUTER_WAN].bytes_up == 3000
        assert after.talkers[ROUTER_WAN].bytes_down == 0

    def test_in_tunnel_traffic_leaves_internal(self) -> None:
        """It used to be counted as venue-internal, a line customers see."""
        assert (
            reduce_window([IN_TUNNEL_UP, IN_TUNNEL_DOWN])[EXPORTER].bytes_internal == 0
        )
        lan = row(GUEST, "192.168.88.1", 50, dport=53)
        w = reduce_window([IN_TUNNEL_UP, lan], PLATFORM)[EXPORTER]
        assert w.bytes_internal == 50 and w.overhead_bytes_up == 900

    def test_a_router_with_a_public_wan_address_is_not_left_unclassified(
        self,
    ) -> None:
        public_wan = "9.9.9.10"
        rows = [
            row(public_wan, HUB, 500, sport=13231, dport=HUB_PORT),
            row(HUB, public_wan, 250, sport=HUB_PORT, dport=13231),
        ]
        assert reduce_window(rows)[EXPORTER].bytes_unclassified == 750
        w = reduce_window(rows, PLATFORM)[EXPORTER]
        assert w.bytes_unclassified == 0
        assert (w.overhead_bytes_up, w.overhead_bytes_down) == (500, 250)

    def test_overhead_rows_do_not_change_whether_services_were_measured(
        self,
    ) -> None:
        w = reduce_window(IDLE_VENUE, PLATFORM)[EXPORTER]
        assert w.services_measured is True and w.packets_measured is True


# ---------------------------------------------------------------------------
# ingest: what each table receives
# ---------------------------------------------------------------------------


class IngestRepo:
    def __init__(self) -> None:
        self.windows: list[dict[str, Any]] = []
        self.services: list[dict[str, Any]] = []
        self.destinations: list[dict[str, Any]] = []

    async def exporter_router_map(self):
        return {EXPORTER: ExporterRouter(ROUTER_ID, ORG, LOC)}

    async def sessions_by_ip(self, router_id, ips, *, start, end):  # noqa: ANN001
        return {}

    async def insert_window(self, values):  # noqa: ANN001
        self.windows.append(dict(values))
        return True

    async def insert_service_buckets(self, rows):  # noqa: ANN001
        self.services.extend(dict(r) for r in rows)

    async def insert_destination_buckets(self, rows):  # noqa: ANN001
        self.destinations.extend(dict(r) for r in rows)


class Capture:
    """Stands in for the geo writer and the flow-record writer."""

    def __init__(self) -> None:
        self.geo: list[Any] = []
        self.records: list[Any] = []

    async def write_window(self, identity, *args):  # noqa: ANN001, ANN002
        if len(args) == 1:
            self.geo.append(args[0])
        else:
            self.records.append(list(args[1]))
        return 0

    async def prune(self, now):  # noqa: ANN001
        return 0


class TestIngest:
    async def _ingest(self, rows: list[dict[str, Any]], platform: PlatformEndpoints):
        repo, capture = IngestRepo(), Capture()
        service = TrafficFlowIngestService(
            repo,  # type: ignore[arg-type]
            geo=capture,
            flow_records=capture,
            platform=platform,
        )
        await service.ingest_window(
            window_start=NOW - timedelta(minutes=5), window_seconds=300, rows=rows
        )
        return repo, capture

    async def test_window_row_holds_overhead_apart_from_client_traffic(self) -> None:
        repo, _ = await self._ingest(BUSY_VENUE, PLATFORM)
        (window,) = repo.windows
        assert (window["bytes_overhead_up"], window["bytes_overhead_down"]) == (
            7500,
            3700,
        )
        assert (window["bytes_up"], window["bytes_down"]) == (3800, 900)
        assert window["bytes_internal"] == 0
        assert window["bytes_total"] == sum(r["bytes"] for r in BUSY_VENUE)
        text = json.dumps(window["top_talkers"]) + json.dumps(
            window["top_destinations"]
        )
        assert HUB not in text and EXPORTER not in text and HUB_TUNNEL not in text

    async def test_a_classified_window_with_no_overhead_is_zero_not_null(self) -> None:
        repo, _ = await self._ingest([GUEST_WEB_UP], PLATFORM)
        assert repo.windows[0]["bytes_overhead_up"] == 0
        assert repo.windows[0]["bytes_overhead_down"] == 0

    async def test_no_bucket_and_no_country_input_carries_the_hub(self) -> None:
        repo, capture = await self._ingest(BUSY_VENUE, PLATFORM)
        assert HUB not in {r["remote_address"] for r in repo.destinations}
        assert {(r["protocol"], r["remote_port"]) for r in repo.services} == {
            (17, 123),
            (6, 443),
            (17, HUB_PORT),  # the guest's own VPN
        }
        vpn = next(r for r in repo.services if r["remote_port"] == HUB_PORT)
        assert (vpn["bytes_up"], vpn["bytes_down"]) == (700, 0)
        # The country writer is handed the reducer's remote addresses.
        (remote_addresses,) = capture.geo
        assert HUB not in remote_addresses and OTHER_VPN in remote_addresses

    async def test_without_a_known_hub_only_the_in_tunnel_part_is_set_aside(
        self,
    ) -> None:
        repo, _ = await self._ingest(IDLE_VENUE, NO_PLATFORM_ENDPOINTS)
        (window,) = repo.windows
        assert (window["bytes_overhead_up"], window["bytes_overhead_down"]) == (
            900,
            400,
        )
        assert HUB in {r["remote_address"] for r in repo.destinations}


# ---------------------------------------------------------------------------
# flow records
# ---------------------------------------------------------------------------


def _sql(statement: Any) -> str:
    return str(
        statement.compile(
            dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}
        )
    )


class TestFlowRecords:
    def test_tunnel_records_are_marked_and_in_tunnel_ones_stay_internal(self) -> None:
        records = flow_record_rows(BUSY_VENUE, EXPORTER, PLATFORM)
        by_ends = {
            (r["src_address"], r["dst_address"]): r["direction"] for r in records
        }
        assert by_ends[(ROUTER_WAN, HUB)] == DIRECTION_PLATFORM
        assert by_ends[(HUB, ROUTER_WAN)] == DIRECTION_PLATFORM
        assert by_ends[(EXPORTER, HUB_TUNNEL)] == DIRECTION_INTERNAL
        assert by_ends[(GUEST, OTHER_VPN)] == DIRECTION_UP
        assert by_ends[(ROUTER_WAN, NTP)] == DIRECTION_UP
        assert len(DIRECTION_PLATFORM) <= 16  # the column's width

    def test_marked_records_are_stored_for_master_and_survive_merging(self) -> None:
        records = flow_record_rows(BUSY_VENUE, EXPORTER, PLATFORM)
        stored, counts = prepare_records(
            records, store_internal=False, merge_ports=True
        )
        marked = [r for r in stored if r["direction"] == DIRECTION_PLATFORM]
        assert {(r["src_address"], r["dst_address"]) for r in marked} == {
            (ROUTER_WAN, HUB),
            (HUB, ROUTER_WAN),
        }
        assert counts.internal == 2  # the in-tunnel pair, left out as before

    def test_without_endpoints_nothing_is_marked(self) -> None:
        records = flow_record_rows(BUSY_VENUE, EXPORTER)
        assert DIRECTION_PLATFORM not in {r["direction"] for r in records}

    def test_a_customer_scope_never_returns_them(self) -> None:
        customer = FlowRecordScope(
            location_id=LOC, organization_id=ORG, platform=PLATFORM
        )
        sql = " AND ".join(
            _sql(condition) for condition in customer.conditions(TrafficFlowRecord)
        )
        assert "traffic_flow_records.direction != 'platform'" in sql
        # ...and rows stored before they were marked, by the hub's endpoint.
        assert f"dst_address = CAST('{HUB}' AS INET)" in sql
        assert f"src_port = {HUB_PORT}" in sql and "protocol = 17" in sql
        assert "NOT (" in sql

    def test_a_customer_scope_hides_marked_rows_even_with_no_known_hub(self) -> None:
        customer = FlowRecordScope(location_id=LOC, organization_id=ORG)
        sql = " AND ".join(
            _sql(condition) for condition in customer.conditions(TrafficFlowRecord)
        )
        assert "direction != 'platform'" in sql

    def test_master_keeps_them_with_the_marker(self) -> None:
        master = FlowRecordScope(location_id=LOC, platform=PLATFORM)
        sql = " AND ".join(
            _sql(condition) for condition in master.conditions(TrafficFlowRecord)
        )
        assert "platform" not in sql and "INET" not in sql


# ---------------------------------------------------------------------------
# summary
# ---------------------------------------------------------------------------


def _window(
    minutes_ago: int,
    *,
    up: int,
    down: int,
    overhead: tuple[int, int] | None,
    destinations: list[dict[str, Any]] | None = None,
) -> Any:
    return SimpleNamespace(
        router_id=ROUTER_ID,
        location_id=LOC,
        window_start=NOW - timedelta(minutes=minutes_ago),
        window_seconds=300,
        bytes_up=up,
        bytes_down=down,
        bytes_overhead_up=None if overhead is None else overhead[0],
        bytes_overhead_down=None if overhead is None else overhead[1],
        bytes_internal=0,
        bytes_unclassified=0,
        flows_total=4,
        services_measured=True,
        talker_count=6,
        destination_count=2,
        top_talkers=[],
        top_destinations=destinations or [],
    )


def _step(
    minutes_ago: int, protocol: int, port: int, up: int, down: int
) -> ServiceStepRow:
    return ServiceStepRow(
        step_start_of(NOW - timedelta(minutes=minutes_ago), 300),
        protocol,
        port,
        up,
        down,
        2,
    )


def _summary(
    windows: list[Any], rows: list[ServiceStepRow], **kw: Any
) -> dict[str, Any]:
    args: dict[str, Any] = {
        "windows": windows,
        "service_rows": rows,
        "since": NOW - timedelta(hours=1),
        "until": NOW,
        "window_seconds": 300,
        "step_seconds": 300,
        "limit": 10,
        "series": 8,
        "data_oldest": None,
        "data_newest": None,
    }
    args.update(kw)
    return build_summary(**args)


#: A window stored BEFORE the change: the tunnel (6600 up, 3300 down) is
#: still inside its client totals, its 17/51820 service and its destinations.
OLD_WINDOW = _window(
    10,
    up=6600 + 3000,
    down=3300,
    overhead=None,
    destinations=[
        {"ip": HUB, "bytes": 9900, "bytes_up": 6600, "bytes_down": 3300, "flows": 2},
        {"ip": NTP, "bytes": 3000, "bytes_up": 3000, "bytes_down": 0, "flows": 1},
    ],
)
OLD_SERVICES = [_step(10, 17, HUB_PORT, 6600, 3300), _step(10, 17, 123, 3000, 0)]
OLD_OVERHEAD = [_step(10, 17, HUB_PORT, 6600, 3300)]


class TestSummary:
    def test_classified_windows_report_overhead_on_its_own_line(self) -> None:
        data = _summary(
            [_window(10, up=3000, down=0, overhead=(7500, 3700))],
            [_step(10, 17, 123, 3000, 0)],
        )
        assert data["platform_overhead"] == {
            "bytes_up": 7500,
            "bytes_down": 3700,
            "bytes": 11200,
            "windows_classified": 1,
            "note": PLATFORM_OVERHEAD_NOTE,
        }
        # ...and it is in no total, share or list.
        assert (data["totals"]["bytes_up"], data["totals"]["bytes_down"]) == (3000, 0)
        assert [i["port"] for i in data["services"]["items"]] == [123]
        assert data["services"]["items"][0]["share"] == 1.0

    def test_the_reported_defect_uncorrected_is_what_the_customer_saw(self) -> None:
        data = _summary([OLD_WINDOW], OLD_SERVICES)
        top = data["services"]["items"][0]
        assert (top["port"], top["share"]) == (HUB_PORT, round(9900 / 12900, 4))

    def test_an_old_window_is_corrected_on_read(self) -> None:
        data = _summary(
            [OLD_WINDOW],
            OLD_SERVICES,
            history_overhead=OLD_OVERHEAD,
            hidden_addresses=PLATFORM.addresses,
        )
        assert (data["totals"]["bytes_up"], data["totals"]["bytes_down"]) == (3000, 0)
        # The tunnel's service is gone, not listed with zeros.
        assert [
            (i["port"], i["bytes"], i["share"]) for i in data["services"]["items"]
        ] == [(123, 3000, 1.0)]
        (step,) = data["timeline"]["steps"]
        assert (step["bytes_up"], step["bytes_down"]) == (3000, 0)
        assert step["services"] == {"17/123": 3000} and step["other_bytes"] == 0
        assert step["protocols"]["udp"] == 3000
        assert [p["bytes"] for p in data["protocols"]] == [0, 3000, 0, 0]
        assert [d["ip"] for d in data["destinations"]["items"]] == [NTP]
        assert data["platform_overhead"]["bytes"] == 9900
        assert data["platform_overhead"]["windows_classified"] == 0
        # Still adds up: what was taken out is what is reported.
        assert data["totals"]["bytes_up"] + data["totals"]["bytes_down"] + 9900 == 12900

    def test_a_venues_own_vpn_on_the_same_port_keeps_its_share(self) -> None:
        """Old window with BOTH the tunnel and a guest's VPN on 51820: only
        the hub's part comes off the service."""
        window = _window(10, up=6600 + 700, down=3300 + 7000, overhead=None)
        data = _summary(
            [window],
            [_step(10, 17, HUB_PORT, 7300, 10300)],
            history_overhead=OLD_OVERHEAD,
        )
        (service,) = data["services"]["items"]
        assert (service["port"], service["bytes_up"], service["bytes_down"]) == (
            HUB_PORT,
            700,
            7000,
        )
        assert data["totals"]["bytes_down"] == 7000

    def test_old_windows_do_not_feed_the_device_list(self) -> None:
        """An old window lists the router itself as a "device" carrying the
        tunnel, and nothing stored says which entry it is. Its devices are
        left out rather than shown with shares over 100%."""

        def talker(ip: str, up: int, down: int) -> dict[str, Any]:
            return {
                "ip": ip,
                "bytes_up": up,
                "bytes_down": down,
                "flows": 1,
                "match": "none",
                "guest_session_id": None,
            }

        old = _window(10, up=9600, down=3300, overhead=None)
        old.top_talkers = [talker(ROUTER_WAN, 9600, 3300)]
        new = _window(5, up=100, down=900, overhead=(7500, 3700))
        new.top_talkers = [talker(GUEST, 100, 900)]
        data = _summary(
            [old, new],
            [*OLD_SERVICES, _step(5, 6, 443, 100, 900)],
            history_overhead=OLD_OVERHEAD,
        )
        assert [d["ip"] for d in data["devices"]["items"]] == [GUEST]
        assert data["devices"]["windows_not_listed"] == 1
        assert all(d["share_at_least"] <= 1 for d in data["devices"]["items"])
        # With nothing to correct, every window feeds the list as before.
        plain = _summary([old, new], [_step(5, 6, 443, 100, 900)])
        assert {d["ip"] for d in plain["devices"]["items"]} == {ROUTER_WAN, GUEST}
        assert "windows_not_listed" not in plain["devices"]

    def test_the_correction_never_goes_below_zero(self) -> None:
        window = _window(10, up=100, down=0, overhead=None)
        data = _summary(
            [window],
            [_step(10, 17, HUB_PORT, 100, 0)],
            history_overhead=[_step(10, 17, HUB_PORT, 5000, 5000)],
        )
        assert data["totals"]["bytes_up"] == 0 and data["totals"]["bytes_down"] == 0
        assert data["platform_overhead"]["bytes"] == 100  # only what was there

    def test_new_and_old_windows_together(self) -> None:
        new = _window(5, up=3000, down=0, overhead=(7500, 3700))
        data = _summary(
            [OLD_WINDOW, new],
            [*OLD_SERVICES, _step(5, 17, 123, 3000, 0)],
            history_overhead=OLD_OVERHEAD,
            hidden_addresses=PLATFORM.addresses,
        )
        assert data["platform_overhead"]["bytes"] == 9900 + 11200
        assert data["platform_overhead"]["windows_classified"] == 1
        assert data["totals"]["bytes_up"] == 6000
        assert [i["port"] for i in data["services"]["items"]] == [123]

    def test_not_measured_has_no_overhead_figure(self) -> None:
        assert _summary([], [])["platform_overhead"] is None


class SummaryRepo:
    def __init__(self, platform: PlatformEndpoints | None) -> None:
        self.platform = platform
        self.overhead_asked = 0
        if platform is None:
            # A repository that cannot say: the service must cope.
            self.platform_endpoints = None  # type: ignore[assignment]

    async def platform_endpoints(self, settings: Any) -> PlatformEndpoints:  # type: ignore[no-redef]
        return self.platform  # type: ignore[return-value]

    async def data_bounds(self, scope):  # noqa: ANN001
        return OLD_WINDOW.window_start, OLD_WINDOW.window_start

    async def windows_in_range(self, scope, *, since, until):  # noqa: ANN001
        return [OLD_WINDOW]

    async def service_steps(self, scope, *, since, until, step_seconds):  # noqa: ANN001
        return list(OLD_SERVICES)

    async def history_overhead_steps(
        self, scope, platform, *, since, until, step_seconds
    ):  # noqa: ANN001
        self.overhead_asked += 1
        assert platform is self.platform and scope == SummaryScope(location_id=LOC)
        return list(OLD_OVERHEAD)

    async def fleet_routers(self, router_id=None, *, location_id=None):  # noqa: ANN001
        return []

    async def router_activity(self, recent_since):  # noqa: ANN001
        return {}


_SETTINGS = SimpleNamespace(
    traffic_flow_enabled=True, traffic_flow_agent_url="", traffic_flow_agent_secret=""
)


class TestSummaryService:
    async def test_master_summary_is_corrected_and_shows_the_line(self) -> None:
        repo = SummaryRepo(PLATFORM)
        data = await TrafficFlowSummaryService(
            repo, _SETTINGS, now=lambda: NOW
        ).summary(  # type: ignore[arg-type]
            router_id=None, location_id=LOC, since=None, until=None
        )
        assert repo.overhead_asked == 1
        assert [i["port"] for i in data["services"]["items"]] == [123]
        assert data["platform_overhead"]["bytes"] == 9900

    async def test_with_no_known_hub_nothing_is_subtracted_or_asked(self) -> None:
        for repo in (SummaryRepo(NO_PLATFORM_ENDPOINTS), SummaryRepo(None)):
            data = await TrafficFlowSummaryService(
                repo, _SETTINGS, now=lambda: NOW
            ).summary(  # type: ignore[arg-type]
                router_id=None, location_id=LOC, since=None, until=None
            )
            assert repo.overhead_asked == 0
            assert data["services"]["items"][0]["port"] == HUB_PORT

    async def test_customer_summary_has_the_sentence_and_no_tunnel(self) -> None:
        class Locations:
            async def get_location(
                self, location_id, *, requesting_organization_id=None
            ):  # noqa: ANN001
                return SimpleNamespace(id=location_id, organization_id=ORG)

        service = TrafficFlowCustomerService(
            SummaryRepo(PLATFORM),  # type: ignore[arg-type]
            Locations(),
            _SETTINGS,  # type: ignore[arg-type]
            now=lambda: NOW,
        )
        data = await service.summary(LOC, organization_id=ORG, since=None, until=None)
        assert data["platform_overhead"] == {
            "excluded": True,
            "note": (
                "Traffic the router exchanges with Wyfy to be managed is not counted."
            ),
        }
        text = json.dumps(data).lower()
        assert str(HUB_PORT) not in text and HUB not in text
        for word in ("tunnel", "wireguard", "exporter", "9900"):
            assert word not in text, word
        assert [i["port"] for i in data["services"]["items"]] == [123]
        assert data["totals"]["bytes_up"] == 3000


# ---------------------------------------------------------------------------
# destinations and findings: statements and corrections
# ---------------------------------------------------------------------------

_WHERE = {"since": NOW - timedelta(hours=1), "until": NOW}
_HIDDEN = (
    f"NOT (traffic_flow_dest_buckets.protocol = 17 AND "
    f"traffic_flow_dest_buckets.remote_address = CAST('{HUB}' AS INET) AND "
    f"traffic_flow_dest_buckets.remote_port = {HUB_PORT})"
)


def _scope(platform: PlatformEndpoints = PLATFORM, **kw: Any) -> DestinationScope:
    return DestinationScope(location_id=LOC, platform=platform, **kw)


def _destination_statements(scope: DestinationScope) -> dict[str, Any]:
    filters = dest.parse_filters(address=None, protocol=None, port=None, direction=None)
    return {
        "page": dest.search_page_statement(
            scope, filters, **_WHERE, sort="bytes", order="desc", limit=10
        ),
        "totals": dest.search_totals_statement(scope, filters, **_WHERE),
        "drill": dest.service_destinations_statement(
            scope, **_WHERE, protocol=17, port=HUB_PORT, limit=10
        ),
        "drill_totals": dest.service_destination_totals_statement(
            scope, **_WHERE, protocol=17, port=HUB_PORT
        ),
        "findings_addresses": address_rows_statement(scope, **_WHERE),
    }


class TestDestinationsAndFindings:
    def test_every_destination_read_leaves_the_hub_out(self) -> None:
        for name, statement in _destination_statements(_scope()).items():
            assert _HIDDEN in " ".join(_sql(statement).split()), name
        # Master and customer alike: the hub is nobody's destination.
        customer = _scope(organization_id=ORG, min_devices=5)
        for name, statement in _destination_statements(customer).items():
            assert _HIDDEN in " ".join(_sql(statement).split()), name

    def test_with_no_known_hub_no_row_is_hidden(self) -> None:
        for name, statement in _destination_statements(
            _scope(NO_PLATFORM_ENDPOINTS)
        ).items():
            assert "NOT (" not in _sql(statement), name

    def test_only_address_and_port_together_hide_a_row(self) -> None:
        """A venue's own WireGuard: same protocol and port, another address.
        The condition is a conjunction, so it is kept."""
        condition = " ".join(
            _sql(PLATFORM.bucket_condition(TrafficFlowDestinationBucket)).split()
        )
        assert condition == _HIDDEN.removeprefix("NOT (").removesuffix(")")
        assert " OR " not in condition

    def test_history_statements_sum_the_hub_rows_inside_the_scope(self) -> None:
        for statement in (
            history_overhead_statement(
                SummaryScope(location_id=LOC), PLATFORM, **_WHERE, step_seconds=300
            ),
            platform_overhead_statement(_scope(), **_WHERE, seconds=3600),
            dest.platform_overhead_total_statement(
                _scope(), **_WHERE, protocol=17, port=HUB_PORT
            ),
        ):
            sql = " ".join(_sql(statement).split())
            assert f"remote_address = CAST('{HUB}' AS INET)" in sql
            assert f"traffic_flow_dest_buckets.location_id = '{LOC}'" in sql
            assert "NOT (" not in sql
        assert (
            history_overhead_statement(
                SummaryScope(location_id=LOC),
                NO_PLATFORM_ENDPOINTS,
                **_WHERE,
                step_seconds=300,
            )
            is None
        )
        assert (
            platform_overhead_statement(
                _scope(NO_PLATFORM_ENDPOINTS), **_WHERE, seconds=3600
            )
            is None
        )

    async def test_drill_down_takes_the_tunnel_off_the_services_total(self) -> None:
        class Repo:
            def __init__(self) -> None:
                self.asked: list[str] = []

            async def platform_endpoints(self, settings: Any) -> PlatformEndpoints:
                return PLATFORM

            async def venue(self, location_id: uuid.UUID) -> Any:
                return dest.Venue(location_id=location_id, organization_id=ORG)

            async def window_stats(self, scope, *, since, until):  # noqa: ANN001
                return dest.WindowStats(windows=1, measured=1, withheld=0)

            async def data_bounds(self, scope):  # noqa: ANN001
                return (NOW, NOW)

            async def service_total(self, scope, **where):  # noqa: ANN001, ANN003
                return ServiceTotal(7300, 10300, 4, 0, 40, 60)

            async def platform_overhead_total(self, scope, **where):  # noqa: ANN001, ANN003
                self.asked.append("overhead")
                assert scope.platform is PLATFORM
                return (6600, 3300, 2)

            async def service_destination_totals(self, scope, **where):  # noqa: ANN001, ANN003
                return dest.Totals(1, 700, 7000, 2, 5, 9)

            async def service_destinations(self, scope, **where):  # noqa: ANN001, ANN003
                return [dest.AddressRow(OTHER_VPN, 700, 7000, 2, 5, 9)]

        class Audit:
            async def create_audit_log_entry(self, **fields: Any) -> None:
                return None

        repo = Repo()
        service = dest.DestinationService(
            repo,  # type: ignore[arg-type]
            SimpleNamespace(traffic_flow_enabled=True),  # type: ignore[arg-type]
            audit_writer=Audit(),
            now=lambda: NOW,
        )
        out = await service.service_destinations(
            location_id=LOC, actor_user_id=uuid.uuid4(), protocol=17, port=HUB_PORT
        )
        assert repo.asked == ["overhead"]
        assert out.service is not None
        assert (out.service.bytes_up, out.service.bytes_down) == (700, 7000)
        assert [i.address for i in out.items] == [OTHER_VPN]
        assert out.unlisted_bytes == 0

    async def test_findings_inputs_are_the_venues_not_the_tunnels(self) -> None:
        """The upload-heavy rule reads bytes per hour, the unusual-service
        rule a service's bytes per day. Both come off the stored figures
        before any rule sees them."""
        hour = datetime(2026, 10, 13, 8, 0, tzinfo=UTC)
        day = datetime(2026, 10, 13, 0, 0, tzinfo=UTC)

        class Result:
            def __init__(self, rows: list[tuple[Any, ...]]) -> None:
                self._rows = rows

            def all(self) -> list[tuple[Any, ...]]:
                return self._rows

        class Session:
            def __init__(self, results: list[list[tuple[Any, ...]]]) -> None:
                self.results = results
                self.statements: list[str] = []

            async def execute(self, statement: Any) -> Result:
                self.statements.append(" ".join(_sql(statement).split()))
                return Result(self.results.pop(0))

        session = Session(
            [
                [(hour, 9600, 3300, 12, 12)],  # windows: client bytes of the hour
                [(hour, 17, HUB_PORT, 6600, 3300)],  # the tunnel in that hour
            ]
        )
        hours = await FindingsRepository(session).hour_rows(_scope(), **_WHERE)  # type: ignore[arg-type]
        assert hours == [HourRow(hour, 3000, 0, 12, 12)]
        assert "traffic_flow_windows" in session.statements[0]
        assert f"CAST('{HUB}' AS INET)" in session.statements[1]

        session = Session(
            [
                [(day, 17, HUB_PORT, 17600)],  # service bucket: tunnel + a VPN
                [(day, 17, HUB_PORT, 6600, 3300)],
            ]
        )
        history = await FindingsRepository(session).service_history(  # type: ignore[arg-type]
            _scope(), [(17, HUB_PORT)], **_WHERE
        )
        assert [(h.protocol, h.port, h.bytes) for h in history] == [
            (17, HUB_PORT, 7700)
        ]

    async def test_findings_without_a_known_hub_read_nothing_extra(self) -> None:
        class Session:
            def __init__(self) -> None:
                self.count = 0

            async def execute(self, statement: Any) -> Any:
                self.count += 1
                return SimpleNamespace(all=lambda: [])

        session = Session()
        await FindingsRepository(session).hour_rows(  # type: ignore[arg-type]
            _scope(NO_PLATFORM_ENDPOINTS), **_WHERE
        )
        assert session.count == 1

    def test_the_tunnel_is_never_an_unusual_service_candidate(self) -> None:
        from app.domains.traffic_flow.findings import is_ordinary_service

        # WireGuard's default port is "ordinary" to the rule anyway...
        assert is_ordinary_service(17, HUB_PORT)
        # ...so the case that matters is a hub on some other port.
        port = 13231
        assert not is_ordinary_service(17, port)
        mib = 1024 * 1024
        window = _window(10, up=660 * mib + 300 * mib, down=330 * mib, overhead=None)
        rows = [
            _step(10, 17, port, 660 * mib, 330 * mib),
            _step(10, 17, 123, 300 * mib, 0),
        ]
        uncorrected = _summary([window], rows)
        assert (17, port) in {
            (c["protocol"], c["port"]) for c in unusual_service_candidates(uncorrected)
        }
        corrected = _summary(
            [window], rows, history_overhead=[_step(10, 17, port, 660 * mib, 330 * mib)]
        )
        assert (17, port) not in {
            (c["protocol"], c["port"]) for c in unusual_service_candidates(corrected)
        }
        # Classified at ingest, the tunnel never reaches a service bucket at
        # all, so there is nothing for either rule to fire on.
        fresh = reduce_window(IDLE_VENUE, PLATFORM)[EXPORTER]
        assert (17, HUB_PORT) not in fresh.services
        assert fresh.bytes_up == 3000  # the hour's upload is the venue's


# ---------------------------------------------------------------------------
# migration 0164 (static)
# ---------------------------------------------------------------------------


class TestMigration:
    FILE = pathlib.Path("alembic/versions/0164_traffic_flow_window_overhead.py")

    def _module(self) -> Any:
        spec = importlib.util.spec_from_file_location("m0164", self.FILE)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def _statements(self, fn: str) -> list[str]:
        statements: list[str] = []

        class _Op:
            def execute(self, sql: Any) -> None:
                statements.append(" ".join(str(sql).split()))

            def __getattr__(self, name: str) -> Any:
                raise AssertionError(f"op.{name} is not guarded; use op.execute")

        module = self._module()
        module.op = _Op()
        getattr(module, fn)()
        return statements

    def test_it_has_one_parent_and_one_child(self) -> None:
        module = self._module()
        assert module.down_revision == "0163_traffic_flow_record_merge"
        versions = list(pathlib.Path("alembic/versions").glob("*.py"))
        assert [
            p.name
            for p in versions
            if f'down_revision = "{module.down_revision}"' in p.read_text()
        ] == [self.FILE.name]
        # The resolved-hostnames revision follows; a second child would be
        # a second head.
        assert [
            p.name
            for p in versions
            if f'down_revision = "{module.revision}"' in p.read_text()
        ] == ["0165_traffic_flow_platform_hosts.py"]

    def test_columns_are_nullable_with_no_default_and_no_backfill(self) -> None:
        up = self._statements("upgrade")
        assert up == [
            "ALTER TABLE traffic_flow_windows ADD COLUMN IF NOT EXISTS "
            f"{column} BIGINT NULL"
            for column in ("bytes_overhead_up", "bytes_overhead_down")
        ]
        text = " ".join(up).upper()
        # NULL must keep meaning "stored before overhead was classified".
        assert "DEFAULT" not in text and "NOT NULL" not in text and "UPDATE" not in text
        down = self._statements("downgrade")
        assert len(down) == 2 and all("DROP COLUMN IF EXISTS" in s for s in down)

    def test_the_model_declares_them_nullable(self) -> None:
        for name in ("bytes_overhead_up", "bytes_overhead_down"):
            column = TrafficFlowWindow.__table__.columns[name]
            assert column.nullable is True and column.default is None
