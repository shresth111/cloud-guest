"""Traffic Lens Geo Location: lookup, country buckets, the by-country
summary, scoping and authorization. No database server and no network.

The MaxMind DB files used here are built in memory by ``_build_mmdb`` from a
handful of documentation-style prefixes -- no excerpt of the real DB-IP data
is in the repository.

What is pinned:

* **Lookup** -- public IPv4 and IPv6 resolve; private, CGNAT, link-local,
  loopback, multicast, reserved and garbage addresses are refused *before*
  either file is touched; a missing or corrupt file makes geo unavailable
  instead of raising.
* **Buckets** -- one window's rows sum exactly to its client traffic, with
  explicit "other" and "unknown" rows; the unknown row is always written, so
  "looked up, nothing there" differs from "not looked up".
* **Idempotency** -- a re-pulled window adds no country rows.
* **Three empties** -- not measured, measured but not looked up (geo
  unavailable), and measured zero are three different answers.
* **Scoping** -- every read statement carries the venue/router condition.
* **Authorization** -- the route is pinned GLOBAL on ``traffic_flows.read``.
"""

from __future__ import annotations

import importlib.util
import ipaddress
import pathlib
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy.dialects import postgresql

from app.domains.rbac.enums import ScopeType
from app.domains.traffic_flow import geo as geo_module
from app.domains.traffic_flow.geo import (
    ATTRIBUTION,
    OTHER_COUNTRY,
    OTHER_NETWORK_ASN,
    UNKNOWN_COUNTRY,
    UNKNOWN_NETWORK_ASN,
    GeoAnswer,
    GeoCountryRow,
    GeoLookup,
    build_geo_summary,
    geo_rows,
    get_geo_lookup,
    is_public_address,
)
from app.domains.traffic_flow.geo_service import (
    CustomerGeoService,
    GeoScope,
    GeoWindowWriter,
    TrafficFlowGeoService,
    country_bucket_insert_statement,
    country_rows_statement,
    windows_looked_up_statement,
)
from app.domains.traffic_flow.ingest import reduce_window
from app.domains.traffic_flow.mmdb import MMDBError, MMDBReader
from app.domains.traffic_flow.models import TrafficFlowCountryBucket
from app.domains.traffic_flow.service import (
    ExporterRouter,
    SummaryScope,
    TrafficFlowError,
    TrafficFlowIngestService,
)
from app.domains.traffic_flow.tasks import pull_once

NOW = datetime(2026, 10, 12, 14, 10, tzinfo=UTC)
ROUTER_ID = uuid.UUID("11111111-0000-4000-8000-000000000001")
ORG_ID = uuid.UUID("22222222-0000-4000-8000-000000000002")
LOCATION_ID = uuid.UUID("33333333-0000-4000-8000-000000000003")
VERSIONS = pathlib.Path("alembic/versions")


@pytest.fixture(autouse=True)
def _info_logging(caplog: pytest.LogCaptureFixture) -> None:
    # A logger ``extra`` key that shadows a LogRecord attribute only raises
    # when INFO is actually emitted.
    caplog.set_level("INFO", logger="app.domains.traffic_flow")


# ---------------------------------------------------------------------------
# a tiny MaxMind DB writer (test-only)
# ---------------------------------------------------------------------------


def _encode(value: Any) -> bytes:
    def head(kind: int, size: int) -> bytes:
        assert size < 285
        # Sizes from 29 take the marker 29 and one more byte.
        marker, extra = (size, b"") if size < 29 else (29, bytes([size - 29]))
        if kind <= 7:
            return bytes([(kind << 5) | marker]) + extra
        return bytes([marker, kind - 7]) + extra

    if isinstance(value, bool):
        return head(14, int(value))
    if isinstance(value, str):
        raw = value.encode()
        return head(2, len(raw)) + raw
    if isinstance(value, int):
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        kind = 6 if len(raw) <= 4 else 9
        return head(kind, len(raw)) + raw
    if isinstance(value, dict):
        return head(7, len(value)) + b"".join(
            _encode(k) + _encode(v) for k, v in value.items()
        )
    if isinstance(value, list):
        return head(11, len(value)) + b"".join(_encode(v) for v in value)
    raise TypeError(type(value))


def _build_mmdb(
    entries: dict[str, dict[str, Any]], *, record_size: int = 24, ip_version: int = 6
) -> bytes:
    data = b""
    offsets: list[int] = []
    for record in entries.values():
        offsets.append(len(data))
        data += _encode(record)
    nodes: list[list[Any]] = [[None, None]]
    for index, prefix in enumerate(entries):
        network = ipaddress.ip_network(prefix)
        bits = int(network.network_address)
        length = network.prefixlen
        width = network.max_prefixlen
        if ip_version == 6 and network.version == 4:
            length, width = length + 96, 128
        node = 0
        for position in range(length):
            bit = (bits >> (width - 1 - position)) & 1
            if position == length - 1:
                nodes[node][bit] = ("data", offsets[index])
                break
            if not isinstance(nodes[node][bit], int):
                nodes.append([None, None])
                nodes[node][bit] = len(nodes) - 1
            node = nodes[node][bit]
    count = len(nodes)

    def record(value: Any) -> int:
        if value is None:
            return count
        if isinstance(value, int):
            return value
        return count + 16 + value[1]

    tree = b""
    for left, right in nodes:
        lo, hi = record(left), record(right)
        if record_size == 24:
            tree += lo.to_bytes(3, "big") + hi.to_bytes(3, "big")
        elif record_size == 28:
            tree += (
                (lo & 0xFFFFFF).to_bytes(3, "big")
                + bytes([((lo >> 24) << 4) | (hi >> 24)])
                + (hi & 0xFFFFFF).to_bytes(3, "big")
            )
        else:
            tree += lo.to_bytes(4, "big") + hi.to_bytes(4, "big")
    metadata = _encode(
        {
            "binary_format_major_version": 2,
            "binary_format_minor_version": 0,
            "build_epoch": 1790818572,  # 2026-10-01
            "database_type": "Test",
            "description": {"en": "test"},
            "ip_version": ip_version,
            "languages": ["en"],
            "node_count": count,
            "record_size": record_size,
        }
    )
    return tree + b"\x00" * 16 + data + b"\xab\xcd\xefMaxMind.com" + metadata


def _country(code: str) -> dict[str, Any]:
    return {
        "continent": {"code": "XX"},
        "country": {"iso_code": code, "is_in_european_union": False},
    }


def _network(asn: int, name: str) -> dict[str, Any]:
    return {"autonomous_system_number": asn, "autonomous_system_organization": name}


#: Country and network for the addresses the tests use.
COUNTRIES = {
    "8.8.8.0/24": _country("US"),
    "49.36.0.0/14": _country("IN"),
    "1.1.1.0/24": _country("AU"),
    "5.5.0.0/16": _country("DE"),
    "9.9.9.0/24": _country("CH"),
    "2001:4860::/32": _country("US"),
    "100.64.0.0/10": _country("ZZ"),  # CGNAT: present so a lookup WOULD answer
    "192.168.0.0/16": _country("ZZ"),
}
NETWORKS = {
    "8.8.8.0/24": _network(15169, "Example Search LLC"),
    "49.36.0.0/15": _network(55836, "Example Mobile Ltd"),
    "49.38.0.0/15": _network(45609, "Example Broadband Ltd"),
    "1.1.1.0/24": _network(13335, "Example CDN Inc"),
    "2001:4860::/32": _network(15169, "Example Search LLC"),
    "7.7.7.0/24": _network(64500, "Network Without Country"),
}


def _write_files(
    directory: pathlib.Path, *, country: bool = True, asn: bool = True
) -> pathlib.Path:
    directory.mkdir(parents=True, exist_ok=True)
    if country:
        (directory / geo_module.COUNTRY_FILENAME).write_bytes(_build_mmdb(COUNTRIES))
    if asn:
        (directory / geo_module.ASN_FILENAME).write_bytes(_build_mmdb(NETWORKS))
    return directory


@pytest.fixture
def lookup(tmp_path: pathlib.Path) -> Any:
    found = GeoLookup(_write_files(tmp_path / "geo"))
    assert found.available, found.unavailable_reason
    yield found
    found.close()


@pytest.fixture
def no_lookup(tmp_path: pathlib.Path) -> GeoLookup:
    return GeoLookup(tmp_path / "nothing-here")


# ---------------------------------------------------------------------------
# the file reader
# ---------------------------------------------------------------------------


class TestReader:
    @pytest.mark.parametrize("record_size", [24, 28, 32])
    def test_reads_ipv4_and_ipv6_from_an_ipv6_tree(
        self, tmp_path: pathlib.Path, record_size: int
    ) -> None:
        path = tmp_path / "t.mmdb"
        path.write_bytes(_build_mmdb(COUNTRIES, record_size=record_size))
        reader = MMDBReader(path)
        try:
            assert reader.record_size == record_size and reader.ip_version == 6
            got = reader.get(ipaddress.ip_address("8.8.8.8"))
            assert got["country"]["iso_code"] == "US"
            assert got["country"]["is_in_european_union"] is False
            got = reader.get(ipaddress.ip_address("2001:4860:4860::8888"))
            assert got["country"]["iso_code"] == "US"
            assert reader.get(ipaddress.ip_address("8.8.9.1")) is None
            assert reader.get(ipaddress.ip_address("2a00::1")) is None
            assert reader.build_epoch == 1790818572
        finally:
            reader.close()

    def test_ipv4_only_tree(self, tmp_path: pathlib.Path) -> None:
        path = tmp_path / "t.mmdb"
        path.write_bytes(_build_mmdb({"8.8.8.0/24": _country("US")}, ip_version=4))
        reader = MMDBReader(path)
        try:
            assert reader.get(ipaddress.ip_address("8.8.8.8"))["country"] == {
                "iso_code": "US",
                "is_in_european_union": False,
            }
            assert reader.get(ipaddress.ip_address("2001:4860::1")) is None
        finally:
            reader.close()

    @pytest.mark.parametrize(
        "content",
        [b"", b"not a database at all", b"\xab\xcd\xefMaxMind.com\xff\xff"],
        ids=["empty", "garbage", "marker-then-garbage"],
    )
    def test_a_bad_file_is_refused_at_open(
        self, tmp_path: pathlib.Path, content: bytes
    ) -> None:
        path = tmp_path / "bad.mmdb"
        path.write_bytes(content)
        with pytest.raises(MMDBError):
            MMDBReader(path)

    def test_a_tree_larger_than_the_file_is_refused(
        self, tmp_path: pathlib.Path
    ) -> None:
        good = _build_mmdb(COUNTRIES)
        marker = good.rfind(b"\xab\xcd\xefMaxMind.com")
        path = tmp_path / "cut.mmdb"
        path.write_bytes(good[:20] + good[marker:])
        with pytest.raises(MMDBError):
            MMDBReader(path)

    def test_a_record_pointing_outside_the_file_is_no_answer_not_a_crash(
        self, tmp_path: pathlib.Path
    ) -> None:
        good = bytearray(_build_mmdb({"0.0.0.0/1": _country("US")}, ip_version=4))
        # The root's left record is the data pointer: point it far away.
        good[0:3] = (0xFFFFFF).to_bytes(3, "big")
        path = tmp_path / "wild.mmdb"
        path.write_bytes(bytes(good))
        reader = MMDBReader(path)
        try:
            assert reader.get(ipaddress.ip_address("8.8.8.8")) is None
        finally:
            reader.close()


# ---------------------------------------------------------------------------
# lookup
# ---------------------------------------------------------------------------


class _Tripwire:
    """Stands in for a data file: any read is a test failure."""

    build_epoch = None

    def get(self, address: Any) -> Any:
        raise AssertionError(f"{address} must not be looked up")

    def close(self) -> None:
        pass


class TestLookup:
    def test_public_ipv4(self, lookup: GeoLookup) -> None:
        assert lookup.lookup("8.8.8.8") == GeoAnswer("US", 15169, "Example Search LLC")
        assert lookup.lookup("49.37.1.1") == GeoAnswer(
            "IN", 55836, "Example Mobile Ltd"
        )

    def test_public_ipv6_and_ipv4_mapped(self, lookup: GeoLookup) -> None:
        assert lookup.lookup("2001:4860:4860::8888") == GeoAnswer(
            "US", 15169, "Example Search LLC"
        )
        assert lookup.lookup("::ffff:8.8.8.8") == GeoAnswer(
            "US", 15169, "Example Search LLC"
        )

    def test_country_without_network_and_network_without_country(
        self, lookup: GeoLookup
    ) -> None:
        assert lookup.lookup("5.5.5.5") == GeoAnswer("DE", None, None)
        assert lookup.lookup("7.7.7.7") == GeoAnswer(
            None, 64500, "Network Without Country"
        )

    def test_public_address_in_neither_file_is_an_empty_answer(
        self, lookup: GeoLookup
    ) -> None:
        # An answer ("we looked, nothing"), not None ("we did not look").
        assert lookup.lookup("23.1.2.3") == GeoAnswer(None, None, None)

    @pytest.mark.parametrize(
        "address",
        [
            "192.168.88.24",  # private
            "10.20.0.31",
            "172.16.5.5",
            "100.64.1.1",  # CGNAT
            "100.127.255.254",
            "169.254.10.10",  # link-local
            "127.0.0.1",  # loopback
            "224.0.0.251",  # multicast
            "239.255.255.250",
            "240.0.0.1",  # reserved
            "255.255.255.255",
            "0.0.0.0",  # noqa: S104 -- unspecified, as data
            "fe80::1",  # IPv6 link-local
            "fd00::1",  # IPv6 unique local
            "::1",
            "ff02::fb",
            "::ffff:192.168.1.1",  # private, IPv4-mapped
            "not-an-address",
            "",
        ],
    )
    def test_non_public_addresses_are_never_looked_up(
        self, lookup: GeoLookup, address: str
    ) -> None:
        assert is_public_address(address) is None
        lookup._country = lookup._asn = _Tripwire()  # type: ignore[assignment]
        assert lookup.lookup(address) is None

    def test_the_files_would_have_answered_for_cgnat_and_private(
        self, tmp_path: pathlib.Path
    ) -> None:
        """The refusal is the lookup's, not an accident of the test data."""
        reader = MMDBReader(_write_files(tmp_path) / geo_module.COUNTRY_FILENAME)
        try:
            assert reader.get(ipaddress.ip_address("100.64.1.1")) is not None
            assert reader.get(ipaddress.ip_address("192.168.88.24")) is not None
        finally:
            reader.close()

    def test_missing_directory_is_unavailable_not_an_error(
        self, no_lookup: GeoLookup
    ) -> None:
        assert no_lookup.available is False
        assert no_lookup.unavailable_reason
        assert no_lookup.lookup("8.8.8.8") is None
        assert no_lookup.describe() is None

    @pytest.mark.parametrize(("country", "asn"), [(True, False), (False, True)])
    def test_either_file_missing_is_unavailable(
        self, tmp_path: pathlib.Path, country: bool, asn: bool
    ) -> None:
        found = GeoLookup(_write_files(tmp_path, country=country, asn=asn))
        assert found.available is False and found.lookup("8.8.8.8") is None

    def test_corrupt_file_is_unavailable_not_an_error(
        self, tmp_path: pathlib.Path
    ) -> None:
        directory = _write_files(tmp_path)
        (directory / geo_module.ASN_FILENAME).write_bytes(b"\x00" * 64)
        found = GeoLookup(directory)
        assert found.available is False
        assert "MMDBError" in (found.unavailable_reason or "")

    def test_describe_names_the_source_and_its_build_dates(
        self, lookup: GeoLookup
    ) -> None:
        assert lookup.describe() == {
            "name": "DB-IP Lite",
            "country_data_built": "2026-10-01",
            "network_data_built": "2026-10-01",
        }

    def test_one_lookup_per_directory_per_process(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(geo_module, "_LOOKUPS", {})
        directory = _write_files(tmp_path)
        first = get_geo_lookup(str(directory))
        assert get_geo_lookup(directory) is first and first.available
        assert get_geo_lookup(tmp_path / "other") is not first
        first.close()

    def test_default_directory_is_backend_data_geo(self) -> None:
        path = geo_module.default_geo_data_dir()
        assert path.parts[-2:] == ("data", "geo")
        assert (path.parent.parent / "app" / "domains" / "traffic_flow").is_dir()


# ---------------------------------------------------------------------------
# one window -> country buckets
# ---------------------------------------------------------------------------


def _dest(up: int, down: int, flows: int = 1) -> list[int]:
    """``ExporterWindow.destinations`` value: [bytes, flows, up, down]."""
    return [up + down, flows, up, down]


def _total(rows: list[dict[str, Any]]) -> tuple[int, int, int]:
    return (
        sum(r["bytes_up"] for r in rows),
        sum(r["bytes_down"] for r in rows),
        sum(r["flows"] for r in rows),
    )


def _find(rows: list[dict[str, Any]], country: str, asn: int) -> dict[str, Any]:
    (row,) = [r for r in rows if r["country_code"] == country and r["asn"] == asn]
    return row


class TestGeoRows:
    def test_rows_sum_exactly_including_unknown(self, lookup: GeoLookup) -> None:
        destinations = {
            "8.8.8.8": _dest(10, 100, 2),
            "8.8.8.9": _dest(1, 5),
            "49.36.0.1": _dest(20, 200),
            "49.38.0.1": _dest(3, 30),
            "5.5.5.5": _dest(4, 40),  # country, no network
            "7.7.7.7": _dest(5, 50),  # network, no country -> unknown
            "23.1.2.3": _dest(6, 60),  # in neither file -> unknown
            "224.0.0.251": _dest(7, 0),  # never looked up -> unknown
        }
        rows = geo_rows(destinations, lookup)
        assert _total(rows) == (56, 485, 9)
        assert _find(rows, "US", 15169) == {
            "country_code": "US",
            "asn": 15169,
            "network_name": "Example Search LLC",
            "bytes_up": 11,
            "bytes_down": 105,
            "flows": 3,
        }
        assert _find(rows, "IN", 55836)["bytes_down"] == 200
        assert _find(rows, "IN", 45609)["network_name"] == "Example Broadband Ltd"
        germany = _find(rows, "DE", UNKNOWN_NETWORK_ASN)
        assert germany["network_name"] is None and germany["bytes_down"] == 40
        unknown = _find(rows, UNKNOWN_COUNTRY, UNKNOWN_NETWORK_ASN)
        assert (unknown["bytes_up"], unknown["bytes_down"], unknown["flows"]) == (
            18,
            110,
            3,
        )

    def test_unknown_row_is_written_even_when_empty(self, lookup: GeoLookup) -> None:
        """It is the "this window was looked up" marker."""
        assert geo_rows({}, lookup) == [
            {
                "country_code": UNKNOWN_COUNTRY,
                "asn": UNKNOWN_NETWORK_ASN,
                "network_name": None,
                "bytes_up": 0,
                "bytes_down": 0,
                "flows": 0,
            }
        ]
        rows = geo_rows({"8.8.8.8": _dest(1, 2)}, lookup)
        assert _find(rows, UNKNOWN_COUNTRY, UNKNOWN_NETWORK_ASN)["bytes_down"] == 0

    def test_geo_unavailable_writes_nothing_at_all(self, no_lookup: GeoLookup) -> None:
        # Not even the unknown row: this window was NOT looked up.
        assert geo_rows({"8.8.8.8": _dest(1, 2)}, no_lookup) == []

    def test_countries_beyond_the_cap_fold_into_other(self, lookup: GeoLookup) -> None:
        destinations = {
            "49.36.0.1": _dest(0, 500),
            "8.8.8.8": _dest(0, 300),
            "1.1.1.1": _dest(0, 20),
            "5.5.5.5": _dest(0, 10),
        }
        rows = geo_rows(destinations, lookup, countries=2)
        assert {r["country_code"] for r in rows} == {
            "IN",
            "US",
            OTHER_COUNTRY,
            UNKNOWN_COUNTRY,
        }
        other = _find(rows, OTHER_COUNTRY, OTHER_NETWORK_ASN)
        assert other["bytes_down"] == 30 and other["flows"] == 2
        assert other["network_name"] is None
        assert _total(rows) == (0, 830, 4)

    def test_networks_beyond_the_cap_fold_into_their_country(
        self, lookup: GeoLookup
    ) -> None:
        destinations = {
            "49.36.0.1": _dest(0, 500),
            "49.38.0.1": _dest(0, 50),
            "8.8.8.8": _dest(0, 300),
            "1.1.1.1": _dest(0, 20),
        }
        rows = geo_rows(destinations, lookup, networks=2)
        assert _find(rows, "IN", 55836)["bytes_down"] == 500
        assert _find(rows, "US", 15169)["bytes_down"] == 300
        # The country keeps its total: the cut network moved to its "other".
        assert _find(rows, "IN", OTHER_NETWORK_ASN)["bytes_down"] == 50
        assert _find(rows, "AU", OTHER_NETWORK_ASN)["bytes_down"] == 20
        assert not [r for r in rows if r["asn"] == 13335]
        assert _total(rows) == (0, 870, 4)

    def test_no_row_carries_an_address(self, lookup: GeoLookup) -> None:
        rows = geo_rows({"8.8.8.8": _dest(1, 2), "23.1.2.3": _dest(3, 4)}, lookup)
        for row in rows:
            assert set(row) == {
                "country_code",
                "asn",
                "network_name",
                "bytes_up",
                "bytes_down",
                "flows",
            }
            assert "8.8.8.8" not in repr(row) and "23.1.2.3" not in repr(row)

    def test_rows_of_a_reduced_window_sum_to_its_client_traffic(
        self, lookup: GeoLookup
    ) -> None:
        def flow(src: str, dst: str, nbytes: int) -> dict[str, Any]:
            return {
                "peer_ip_src": "10.20.0.31",
                "ip_src": src,
                "ip_dst": dst,
                "bytes": nbytes,
                "packets": 1,
                "flows": 1,
            }

        window = reduce_window(
            [
                flow("192.168.88.10", "8.8.8.8", 100),
                flow("8.8.8.8", "192.168.88.10", 900),
                flow("192.168.88.11", "49.36.0.1", 50),
                flow("2001:4860:4860::8888", "fd00::10", 70),
                flow("192.168.88.10", "192.168.88.1", 5000),  # internal
                flow("8.8.8.8", "1.1.1.1", 7000),  # unclassified
                flow("192.168.88.12", "224.0.0.251", 30),
            ]
        )["10.20.0.31"]
        rows = geo_rows(window.destinations, lookup)
        up, down, _flows = _total(rows)
        assert (up, down) == (window.bytes_up, window.bytes_down) == (180, 970)
        # Internal and unclassified traffic is in no country, not even unknown.
        assert _find(rows, UNKNOWN_COUNTRY, UNKNOWN_NETWORK_ASN)["bytes_up"] == 30
        assert _find(rows, "US", 15169)["bytes_down"] == 970


# ---------------------------------------------------------------------------
# ingest: written once, with the window
# ---------------------------------------------------------------------------


class IngestRepo:
    """The slice of ``TrafficFlowRepository`` ingest and the pull use."""

    def __init__(self) -> None:
        self.keys: set[tuple[Any, ...]] = set()
        self.windows: list[dict[str, Any]] = []
        self.service_rows: list[dict[str, Any]] = []
        self.state = SimpleNamespace(
            last_window_start=None,
            last_pull_at=None,
            last_pull_ok=None,
            last_error=None,
            unknown_exporters=[],
        )

    async def exporter_router_map(self) -> dict[str, ExporterRouter]:
        return {
            "10.20.0.31": ExporterRouter(
                router_id=ROUTER_ID, organization_id=ORG_ID, location_id=LOCATION_ID
            )
        }

    async def sessions_by_ip(self, router_id, ips, *, start, end):  # noqa: ANN001
        return {}

    async def insert_window(self, values):  # noqa: ANN001
        key = (values["router_id"], values["source"], values["window_start"])
        if key in self.keys:
            return False
        self.keys.add(key)
        self.windows.append(dict(values))
        return True

    async def insert_service_buckets(self, rows):  # noqa: ANN001
        self.service_rows.extend(rows)

    async def insert_destination_buckets(self, rows):  # noqa: ANN001
        return None

    async def delete_destination_buckets_before(self, cutoff, *, limit):  # noqa: ANN001
        return 0

    async def get_state(self) -> Any:
        return self.state

    async def delete_windows_before(self, cutoff, *, limit):  # noqa: ANN001
        return 0

    async def delete_service_buckets_before(self, cutoff, *, limit):  # noqa: ANN001
        return 0


class GeoRepo:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []
        self.inserts = 0
        self.pruned: list[tuple[datetime, int]] = []

    async def insert_country_buckets(self, rows):  # noqa: ANN001
        self.inserts += 1
        self.rows.extend(rows)

    async def delete_country_buckets_before(self, cutoff, *, limit):  # noqa: ANN001
        self.pruned.append((cutoff, limit))
        return 3


FLOWS = [
    {
        "peer_ip_src": "10.20.0.31",
        "ip_src": "192.168.88.10",
        "ip_dst": "8.8.8.8",
        "bytes": 100,
        "packets": 1,
        "flows": 1,
    },
    {
        "peer_ip_src": "10.20.0.31",
        "ip_src": "49.36.0.1",
        "ip_dst": "192.168.88.10",
        "bytes": 900,
        "packets": 1,
        "flows": 1,
    },
]


class TestIngest:
    async def _ingest(self, repo: IngestRepo, geo: Any, start: datetime) -> Any:
        return await TrafficFlowIngestService(repo, geo=geo).ingest_window(  # type: ignore[arg-type]
            window_start=start, window_seconds=300, rows=FLOWS
        )

    async def test_country_rows_carry_the_window_identity(
        self, lookup: GeoLookup
    ) -> None:
        repo, geo_repo = IngestRepo(), GeoRepo()
        start = NOW - timedelta(minutes=10)
        await self._ingest(repo, GeoWindowWriter(geo_repo, lookup), start)  # type: ignore[arg-type]
        assert {r["country_code"] for r in geo_repo.rows} == {
            "US",
            "IN",
            UNKNOWN_COUNTRY,
        }
        for row in geo_repo.rows:
            assert row["router_id"] == ROUTER_ID
            assert row["organization_id"] == ORG_ID
            assert row["location_id"] == LOCATION_ID
            assert row["source"] == "mikrotik_ipfix"
            assert row["window_start"] == start and row["window_seconds"] == 300
            assert set(row) == {
                c.name for c in TrafficFlowCountryBucket.__table__.columns
            } - {"id"}
        window = repo.windows[0]
        assert _total(geo_repo.rows)[:2] == (window["bytes_up"], window["bytes_down"])

    async def test_a_re_pulled_window_adds_no_country_rows(
        self, lookup: GeoLookup
    ) -> None:
        repo, geo_repo = IngestRepo(), GeoRepo()
        writer = GeoWindowWriter(geo_repo, lookup)  # type: ignore[arg-type]
        start = NOW - timedelta(minutes=10)
        first = await self._ingest(repo, writer, start)
        before = list(geo_repo.rows)
        again = await self._ingest(repo, writer, start)
        assert (first.written, again.written, again.duplicates) == (1, 0, 1)
        assert geo_repo.rows == before and geo_repo.inserts == 1

    async def test_without_geo_data_ingest_still_works_and_writes_no_country_row(
        self, no_lookup: GeoLookup
    ) -> None:
        repo, geo_repo = IngestRepo(), GeoRepo()
        result = await self._ingest(
            repo,
            GeoWindowWriter(geo_repo, no_lookup),  # type: ignore[arg-type]
            NOW - timedelta(minutes=10),
        )
        assert result.written == 1 and geo_repo.rows == []

    async def test_ingest_without_a_geo_writer_is_unchanged(self) -> None:
        repo = IngestRepo()
        result = await self._ingest(repo, None, NOW - timedelta(minutes=10))
        assert result.written == 1 and len(repo.windows) == 1

    async def test_pull_ingests_and_prunes_country_buckets_at_retention(
        self, lookup: GeoLookup
    ) -> None:
        repo, geo_repo = IngestRepo(), GeoRepo()
        start = int((NOW - timedelta(minutes=10)).timestamp())

        async def fetch(after: int) -> dict[str, Any]:
            return {
                "windows": [
                    {"window_start": start, "window_seconds": 300, "rows": FLOWS}
                ]
            }

        async def commit() -> None:
            return None

        result = await pull_once(
            repository=repo,  # type: ignore[arg-type]
            settings=SimpleNamespace(
                traffic_flow_enabled=True,
                traffic_flow_agent_url="http://hub.invalid:9094",
                traffic_flow_agent_secret="s3cret",  # noqa: S106
            ),
            fetch_windows=fetch,
            commit=commit,
            now=lambda: NOW,
            geo=GeoWindowWriter(geo_repo, lookup),  # type: ignore[arg-type]
        )
        assert result["written"] == 1 and result["pruned_country_buckets"] == 3
        assert geo_repo.rows
        ((cutoff, limit),) = geo_repo.pruned
        assert cutoff == NOW - timedelta(days=7) and limit > 0


def _sql(statement: Any) -> str:
    return str(statement.compile(dialect=postgresql.dialect()))


class TestStorage:
    def test_insert_is_idempotent_on_the_unique_key(self) -> None:
        row = {
            "router_id": ROUTER_ID,
            "organization_id": None,
            "location_id": None,
            "source": "mikrotik_ipfix",
            "window_start": NOW,
            "window_seconds": 300,
            "country_code": "IN",
            "asn": 55836,
            "network_name": "Example Mobile Ltd",
            "bytes_up": 1,
            "bytes_down": 2,
            "flows": 1,
        }
        sql = _sql(country_bucket_insert_statement([row, {**row, "asn": 0}]))
        assert "ON CONFLICT ON CONSTRAINT uq_traffic_flow_country_buckets_key" in sql
        assert "DO NOTHING" in sql

    def test_unique_key_and_scoping_columns_match_the_service_buckets(self) -> None:
        table = TrafficFlowCountryBucket.__table__
        unique = {
            tuple(c.name for c in constraint.columns)
            for constraint in table.constraints
            if constraint.__class__.__name__ == "UniqueConstraint"
        }
        assert unique == {
            ("router_id", "source", "window_start", "country_code", "asn")
        }
        for column in ("router_id", "organization_id", "location_id"):
            assert column in table.columns
        assert {tuple(c.name for c in index.columns) for index in table.indexes} == {
            ("window_start",),
            ("location_id", "window_start"),
        }
        # No address column of any kind.
        assert not [c.name for c in table.columns if "ip" in c.name.split("_")]
        assert not [c.name for c in table.columns if "address" in c.name]

    @pytest.mark.parametrize(
        "statement", [country_rows_statement, windows_looked_up_statement]
    )
    def test_every_read_is_scoped_to_the_venue_and_router(self, statement: Any) -> None:
        both = _sql(
            statement(
                SummaryScope(router_id=ROUTER_ID, location_id=LOCATION_ID),
                since=NOW - timedelta(hours=1),
                until=NOW,
            )
        )
        assert "traffic_flow_country_buckets.router_id =" in both
        assert "traffic_flow_country_buckets.location_id =" in both
        assert "window_start >=" in both and "window_start <" in both
        venue_only = _sql(
            statement(
                SummaryScope(location_id=LOCATION_ID),
                since=NOW - timedelta(hours=1),
                until=NOW,
            )
        )
        assert "traffic_flow_country_buckets.location_id =" in venue_only
        assert "router_id =" not in venue_only

    def test_country_rows_are_summed_per_country_and_network(self) -> None:
        sql = _sql(
            country_rows_statement(
                SummaryScope(location_id=LOCATION_ID),
                since=NOW - timedelta(hours=1),
                until=NOW,
            )
        )
        assert (
            "GROUP BY traffic_flow_country_buckets.country_code, "
            "traffic_flow_country_buckets.asn" in sql
        )

    def test_looked_up_windows_are_counted_by_their_unknown_row(self) -> None:
        sql = _sql(
            windows_looked_up_statement(
                SummaryScope(location_id=LOCATION_ID),
                since=NOW - timedelta(hours=1),
                until=NOW,
            )
        )
        assert "country_code =" in sql and "asn =" in sql and "count(" in sql


# ---------------------------------------------------------------------------
# the by-country summary (pure)
# ---------------------------------------------------------------------------

SOURCE = {
    "name": "DB-IP Lite",
    "country_data_built": "2026-10-01",
    "network_data_built": "2026-10-01",
}


def _row(
    country: str, asn: int, up: int, down: int, name: str | None = None
) -> GeoCountryRow:
    return GeoCountryRow(country, asn, name, up, down, 1)


def _summary(rows: list[GeoCountryRow], **over: Any) -> dict[str, Any]:
    args: dict[str, Any] = {
        "feature_enabled": True,
        "geo_available": True,
        "source": SOURCE,
        "windows": 12,
        "windows_measured": 12,
        "rows": rows,
        "since": NOW - timedelta(hours=1),
        "until": NOW,
        "window_seconds": 300,
        "limit": 10,
        "networks": 5,
        "data_oldest": NOW - timedelta(hours=5),
        "data_newest": NOW - timedelta(minutes=5),
    }
    args.update(over)
    return build_geo_summary(**args)


ROWS = [
    _row("IN", 55836, 100, 500, "Example Mobile Ltd"),
    _row("IN", 45609, 0, 100, "Example Broadband Ltd"),
    _row("IN", OTHER_NETWORK_ASN, 0, 50),
    _row("IN", UNKNOWN_NETWORK_ASN, 0, 50),
    _row("US", 15169, 20, 80, "Example Search LLC"),
    _row("AU", 13335, 0, 40, "Example CDN Inc"),
    _row(OTHER_COUNTRY, OTHER_NETWORK_ASN, 0, 20),
    _row(UNKNOWN_COUNTRY, UNKNOWN_NETWORK_ASN, 10, 30),
]


class TestSummaryAssembly:
    def test_not_measured_has_no_totals_and_no_zeros(self) -> None:
        out = _summary([], windows=0, windows_measured=0)
        assert out["measured"] is False and out["geo_measured"] is False
        assert out["totals"] is None and out["unknown"] is None
        assert out["countries"]["items"] == [] and out["exact"] is False
        assert out["geo_available"] is True  # the server could look up; no data
        assert out["data_oldest"] == (NOW - timedelta(hours=5)).isoformat()

    def test_measured_but_geo_unavailable_is_its_own_answer(self) -> None:
        out = _summary([], windows_measured=0, geo_available=False, source=None)
        assert out["measured"] is True
        assert out["geo_available"] is False and out["geo_measured"] is False
        assert out["totals"] is None and out["countries"]["items"] == []
        assert out["source"] is None and out["windows"] == 12
        assert out["attribution"] == ATTRIBUTION

    def test_measured_but_not_looked_up_while_the_data_is_now_there(self) -> None:
        """Windows ingested before the data files were installed."""
        out = _summary([], windows_measured=0)
        assert out["geo_available"] is True and out["geo_measured"] is False
        assert out["totals"] is None

    def test_measured_zero_is_distinct_from_not_measured(self) -> None:
        out = _summary([_row(UNKNOWN_COUNTRY, UNKNOWN_NETWORK_ASN, 0, 0)])
        assert out["measured"] is True and out["geo_measured"] is True
        assert out["totals"] == {"bytes_up": 0, "bytes_down": 0, "bytes": 0, "flows": 1}
        assert out["unknown"]["bytes"] == 0 and out["unknown"]["share"] == 0.0
        assert out["countries"]["items"] == [] and out["exact"] is True

    def test_shares_add_up_with_other_and_unknown(self) -> None:
        out = _summary(ROWS)
        assert out["totals"] == {
            "bytes_up": 130,
            "bytes_down": 870,
            "bytes": 1000,
            "flows": 8,
        }
        items = out["countries"]["items"]
        assert [(i["country_code"], i["bytes"], i["share"]) for i in items] == [
            ("IN", 800, 0.8),
            ("US", 100, 0.1),
            ("AU", 40, 0.04),
        ]
        assert items[0]["bytes_up"] == 100 and items[0]["bytes_down"] == 700
        assert out["countries"]["other_bytes"] == 20
        assert out["countries"]["other_share"] == 0.02
        assert out["unknown"] == {
            "bytes_up": 10,
            "bytes_down": 30,
            "bytes": 40,
            "flows": 1,
            "share": 0.04,
        }
        listed = sum(i["bytes"] for i in items)
        assert (
            listed + out["countries"]["other_bytes"] + out["unknown"]["bytes"]
            == out["totals"]["bytes"]
        )

    def test_networks_inside_a_country(self) -> None:
        india = _summary(ROWS)["countries"]["items"][0]
        assert india["networks"] == {
            "items": [
                {
                    "asn": 55836,
                    "network_name": "Example Mobile Ltd",
                    "bytes_up": 100,
                    "bytes_down": 500,
                    "bytes": 600,
                    "flows": 1,
                    "share": 0.75,
                },
                {
                    "asn": 45609,
                    "network_name": "Example Broadband Ltd",
                    "bytes_up": 0,
                    "bytes_down": 100,
                    "bytes": 100,
                    "flows": 1,
                    "share": 0.125,
                },
            ],
            "other_bytes": 50,
            "unknown_bytes": 50,
        }

    def test_network_limit_moves_the_rest_to_other(self) -> None:
        india = _summary(ROWS, networks=1)["countries"]["items"][0]
        assert [n["asn"] for n in india["networks"]["items"]] == [55836]
        assert india["networks"]["other_bytes"] == 150
        assert india["networks"]["unknown_bytes"] == 50
        assert india["bytes"] == 800  # the country total does not move

    def test_country_limit_moves_the_rest_to_other(self) -> None:
        out = _summary(ROWS, limit=1)
        assert [i["country_code"] for i in out["countries"]["items"]] == ["IN"]
        assert out["countries"]["other_bytes"] == 20 + 100 + 40
        assert out["totals"]["bytes"] == 1000

    def test_partly_looked_up_range_is_not_exact_and_says_how_much(self) -> None:
        out = _summary(ROWS, windows_measured=7)
        assert out["geo_measured"] is True and out["exact"] is False
        assert (out["windows"], out["windows_measured"]) == (12, 7)

    def test_a_network_is_never_called_an_application(self) -> None:
        text = repr(_summary(ROWS)).lower()
        assert "network_name" in text
        for word in ("app", "application", "service_name", "site"):
            assert f"'{word}" not in text

    def test_no_address_in_the_response(self) -> None:
        out = _summary(ROWS)
        for item in out["countries"]["items"]:
            assert "ip" not in item
            for network in item["networks"]["items"]:
                assert set(network) == {
                    "asn",
                    "network_name",
                    "bytes_up",
                    "bytes_down",
                    "bytes",
                    "flows",
                    "share",
                }

    def test_attribution_is_always_present(self) -> None:
        for out in (
            _summary(ROWS),
            _summary([], windows=0, windows_measured=0),
            _summary([], windows_measured=0, geo_available=False, source=None),
        ):
            assert out["attribution"]["text"] == "IP Geolocation by DB-IP"
            assert out["attribution"]["url"] == "https://db-ip.com"
            assert out["attribution"]["license"] == "CC BY 4.0"


# ---------------------------------------------------------------------------
# the service
# ---------------------------------------------------------------------------


class ReadRepo:
    """Rows keyed by venue, so a scope mix-up shows up as wrong numbers."""

    def __init__(self) -> None:
        self.windows: dict[uuid.UUID, list[datetime]] = {}
        self.looked_up: dict[uuid.UUID, int] = {}
        self.withheld: dict[uuid.UUID, int] = {}
        self.rows: dict[uuid.UUID, list[GeoCountryRow]] = {}
        self.calls: list[tuple[str, Any]] = []

    async def data_bounds(self, scope):  # noqa: ANN001
        self.calls.append(("bounds", scope))
        starts = self.windows.get(scope.location_id, [])
        return (min(starts), max(starts)) if starts else (None, None)

    async def window_count(self, scope, *, since, until):  # noqa: ANN001
        self.calls.append(("windows", (scope, since, until)))
        return len(
            [s for s in self.windows.get(scope.location_id, []) if since <= s < until]
        )

    async def windows_looked_up(self, scope, *, since, until):  # noqa: ANN001
        self.calls.append(("looked_up", scope))
        return (
            self.looked_up.get(scope.location_id, 0),
            self.withheld.get(scope.location_id, 0) if scope.min_devices else 0,
        )

    async def country_rows(self, scope, *, since, until):  # noqa: ANN001
        self.calls.append(("rows", scope))
        return self.rows.get(scope.location_id, [])


OTHER_LOCATION = uuid.UUID("44444444-0000-4000-8000-000000000004")


def _service(
    repo: ReadRepo, lookup: GeoLookup, *, enabled: bool = True
) -> TrafficFlowGeoService:
    return TrafficFlowGeoService(
        repo,  # type: ignore[arg-type]
        SimpleNamespace(traffic_flow_enabled=enabled),  # type: ignore[arg-type]
        lookup,
        now=lambda: NOW,
    )


async def _ask(service: TrafficFlowGeoService, **kw: Any) -> dict[str, Any]:
    args: dict[str, Any] = {
        "router_id": None,
        "location_id": LOCATION_ID,
        "since": None,
        "until": None,
    }
    args.update(kw)
    return await service.by_country(**args)


def _populated() -> ReadRepo:
    repo = ReadRepo()
    repo.windows[LOCATION_ID] = [NOW - timedelta(minutes=m) for m in (10, 20, 30)]
    repo.looked_up[LOCATION_ID] = 3
    repo.rows[LOCATION_ID] = ROWS
    repo.windows[OTHER_LOCATION] = [NOW - timedelta(minutes=10)]
    repo.looked_up[OTHER_LOCATION] = 1
    repo.rows[OTHER_LOCATION] = [_row("JP", 2516, 5, 5, "Another Venue Network")]
    return repo


class TestService:
    async def test_default_range_is_the_last_hour(self, lookup: GeoLookup) -> None:
        out = await _ask(_service(_populated(), lookup))
        assert out["until"] == NOW.isoformat()
        assert out["since"] == (NOW - timedelta(hours=1)).isoformat()
        assert out["measured"] and out["geo_measured"] and out["exact"]
        assert (out["windows"], out["windows_measured"]) == (3, 3)
        assert out["source"]["name"] == "DB-IP Lite" and out["geo_available"] is True

    async def test_one_venue_never_sees_another_venues_rows(
        self, lookup: GeoLookup
    ) -> None:
        repo = _populated()
        mine = await _ask(_service(repo, lookup))
        theirs = await _ask(_service(repo, lookup), location_id=OTHER_LOCATION)
        assert "JP" not in repr(mine) and "Another Venue" not in repr(mine)
        assert [i["country_code"] for i in theirs["countries"]["items"]] == ["JP"]
        for name, scope in [c for c in repo.calls if c[0] in ("looked_up", "rows")]:
            assert scope.location_id in (LOCATION_ID, OTHER_LOCATION), name

    async def test_scope_reaches_every_repository_call(self, lookup: GeoLookup) -> None:
        repo = _populated()
        await _ask(_service(repo, lookup), router_id=ROUTER_ID)
        want = GeoScope(router_id=ROUTER_ID, location_id=LOCATION_ID)
        assert [c[0] for c in repo.calls] == ["bounds", "windows", "looked_up", "rows"]
        assert repo.calls[0][1] == want and repo.calls[1][1][0] == want
        assert repo.calls[2][1] == want and repo.calls[3][1] == want

    async def test_a_scope_is_required(self, lookup: GeoLookup) -> None:
        with pytest.raises(TrafficFlowError) as raised:
            await _ask(_service(ReadRepo(), lookup), location_id=None)
        assert raised.value.code == "TRAFFIC_FLOW_SCOPE_REQUIRED"

    async def test_inverted_range_is_refused(self, lookup: GeoLookup) -> None:
        with pytest.raises(TrafficFlowError) as raised:
            await _ask(_service(ReadRepo(), lookup), since=NOW, until=NOW)
        assert raised.value.code == "TRAFFIC_FLOW_BAD_RANGE"

    async def test_seven_days_is_allowed_and_more_is_refused_not_clamped(
        self, lookup: GeoLookup
    ) -> None:
        service = _service(_populated(), lookup)
        out = await _ask(service, since=NOW - timedelta(days=7), until=NOW)
        assert out["since"] == (NOW - timedelta(days=7)).isoformat()
        with pytest.raises(TrafficFlowError) as raised:
            await _ask(service, since=NOW - timedelta(days=7, seconds=1), until=NOW)
        assert raised.value.code == "TRAFFIC_FLOW_WINDOW_TOO_LARGE"
        assert raised.value.status_code == 422

    async def test_naive_times_are_read_as_utc(self, lookup: GeoLookup) -> None:
        out = await _ask(
            _service(_populated(), lookup),
            since=datetime(2026, 10, 12, 13, 0),  # noqa: DTZ001
            until=datetime(2026, 10, 12, 14, 0),  # noqa: DTZ001
        )
        assert out["since"] == "2026-10-12T13:00:00+00:00"

    async def test_empty_range_is_not_measured_but_knows_where_data_starts(
        self, lookup: GeoLookup
    ) -> None:
        repo = _populated()
        out = await _ask(
            _service(repo, lookup),
            since=NOW - timedelta(days=2),
            until=NOW - timedelta(days=1),
        )
        assert out["measured"] is False and out["totals"] is None
        assert out["data_oldest"] == (NOW - timedelta(minutes=30)).isoformat()
        # Nothing measured: the country table is not even read.
        assert [c[0] for c in repo.calls] == ["bounds", "windows"]

    async def test_geo_unavailable_and_nothing_looked_up(
        self, no_lookup: GeoLookup
    ) -> None:
        repo = _populated()
        repo.looked_up[LOCATION_ID] = 0
        out = await _ask(_service(repo, no_lookup))
        assert out["measured"] is True
        assert out["geo_available"] is False and out["geo_measured"] is False
        assert out["totals"] is None and out["countries"]["items"] == []
        assert out["source"] is None and out["attribution"] == ATTRIBUTION
        assert "rows" not in [c[0] for c in repo.calls]

    async def test_rows_stored_earlier_are_still_shown_if_the_files_went_missing(
        self, no_lookup: GeoLookup
    ) -> None:
        """Stored rows were looked up when they were written; showing them is
        not a guess. ``geo_available`` still says new traffic is not."""
        out = await _ask(_service(_populated(), no_lookup))
        assert out["geo_available"] is False and out["geo_measured"] is True
        assert out["totals"]["bytes"] == 1000

    async def test_flag_off_says_so_and_reads_nothing(self, lookup: GeoLookup) -> None:
        repo = _populated()
        out = await _ask(_service(repo, lookup, enabled=False))
        assert out["feature_enabled"] is False and out["measured"] is False
        assert out["totals"] is None and repo.calls == []

    async def test_list_sizes_are_clamped(self, lookup: GeoLookup) -> None:
        out = await _ask(_service(_populated(), lookup), limit=1, networks=1)
        assert len(out["countries"]["items"]) == 1
        assert len(out["countries"]["items"][0]["networks"]["items"]) == 1


# ---------------------------------------------------------------------------
# authorization and mounting
# ---------------------------------------------------------------------------


def _pins(route: Any) -> dict[Any, Any]:
    closures = [
        {
            type(cell.cell_contents): cell.cell_contents
            for cell in (getattr(d.dependency, "__closure__", None) or ())
        }
        for d in route.dependencies
    ]
    pinned = [c for c in closures if ScopeType in c]
    assert pinned, closures
    return pinned[0]


class TestAuthorization:
    def test_geo_route_is_pinned_global_on_the_read_permission(self) -> None:
        from app.domains.traffic_flow.geo_router import (
            traffic_flow_geo_platform_router,
        )

        (route,) = traffic_flow_geo_platform_router.routes
        assert route.path == "/geo" and route.methods == {"GET"}
        pin = _pins(route)
        assert pin[ScopeType] == ScopeType.GLOBAL and pin[str] == "traffic_flows.read"

    def test_the_mounted_route_keeps_its_pin(self) -> None:
        from app.domains.traffic_flow.router import traffic_flow_platform_router

        (route,) = [
            r for r in traffic_flow_platform_router.routes if r.path.endswith("/geo")
        ]
        assert route.path == "/platform/traffic-flow/geo"
        assert _pins(route)[ScopeType] == ScopeType.GLOBAL

    def test_served_under_platform_only(self) -> None:
        from app.api.v1.router import api_v1_router

        paths = {r.path for r in api_v1_router.routes}
        assert "/platform/traffic-flow/geo" in paths
        # Exactly one other: the customer venue route (TestCustomerGeo).
        assert [
            p for p in paths if p.endswith("/geo") and not p.startswith("/platform/")
        ] == ["/traffic-flow/locations/{location_id}/geo"]

    def test_scope_and_range_are_query_parameters_not_a_body(self) -> None:
        from app.domains.traffic_flow.geo_router import (
            traffic_flow_geo_platform_router,
        )

        (route,) = traffic_flow_geo_platform_router.routes
        names = {p.name for p in route.dependant.query_params}
        assert names == {
            "router_id",
            "location_id",
            "since",
            "until",
            "limit",
            "networks",
        }
        assert route.dependant.body_params == []


# ---------------------------------------------------------------------------
# migration 0160 (static: no database server)
# ---------------------------------------------------------------------------


def _migration(filename: str) -> Any:
    spec = importlib.util.spec_from_file_location(
        filename.removesuffix(".py"), VERSIONS / filename
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(module: Any, monkeypatch: pytest.MonkeyPatch, fn: str) -> list[str]:
    statements: list[str] = []

    class _Op:
        def execute(self, sql: Any) -> None:
            statements.append(" ".join(str(sql).split()))

        def __getattr__(self, name: str) -> Any:
            raise AssertionError(f"op.{name} is not guarded; use op.execute")

    monkeypatch.setattr(module, "op", _Op())
    getattr(module, fn)()
    return statements


class TestMigration:
    FILE = "0160_traffic_flow_country_buckets.py"

    def test_chain(self) -> None:
        module = _migration(self.FILE)
        assert module.down_revision == "0159_traffic_flow_dest_buckets"
        assert len(module.revision) <= 40

    def test_no_other_revision_claims_the_same_parent(self) -> None:
        """Two heads would stop ``alembic upgrade head`` at deploy. Fails the
        day another migration lands on 0159 first: re-chain this one."""
        mine = _migration(self.FILE)
        children = [
            path.name
            for path in VERSIONS.glob("*.py")
            if f'down_revision = "{mine.down_revision}"' in path.read_text()
        ]
        assert children == [self.FILE]
        assert not [
            path.name
            for path in VERSIONS.glob("*.py")
            if f'down_revision = "{mine.revision}"' in path.read_text()
        ]

    def test_every_statement_is_a_no_op_when_already_applied(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        statements = _run(_migration(self.FILE), monkeypatch, "upgrade")
        assert len(statements) == 3
        for statement in statements:
            assert "IF NOT EXISTS" in statement, statement
        for statement in _run(_migration(self.FILE), monkeypatch, "downgrade"):
            assert "IF EXISTS" in statement, statement

    def test_table_matches_the_model(self, monkeypatch: pytest.MonkeyPatch) -> None:
        create, *indexes = _run(_migration(self.FILE), monkeypatch, "upgrade")
        table = TrafficFlowCountryBucket.__table__
        assert f"CREATE TABLE IF NOT EXISTS {table.name} " in create
        for column in table.columns:
            assert f" {column.name} " in create, column.name
        assert (
            "uq_traffic_flow_country_buckets_key UNIQUE "
            "(router_id, source, window_start, country_code, asn)" in create
        )
        assert "REFERENCES routers (id) ON DELETE CASCADE" in create
        for index in table.indexes:
            assert any(f" {index.name} " in statement for statement in indexes)


# ---------------------------------------------------------------------------
# how the data reaches an image
# ---------------------------------------------------------------------------


def _fetch_script() -> Any:
    spec = importlib.util.spec_from_file_location(
        "fetch_geo_data", pathlib.Path("scripts/fetch_geo_data.py")
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestDelivery:
    def test_the_data_files_are_not_in_the_repository(self) -> None:
        assert "data/geo/" in pathlib.Path(".gitignore").read_text().splitlines()
        assert not list(pathlib.Path("app").rglob("*.mmdb"))
        assert not list(pathlib.Path("tests").rglob("*.mmdb"))

    def test_image_build_fetches_but_does_not_depend_on_it(self) -> None:
        text = pathlib.Path("Dockerfile").read_text()
        assert "scripts/fetch_geo_data.py --dest /app/data/geo" in text
        step = text[text.index("ARG FETCH_GEO_DATA") :]
        assert "|| echo" in step  # a failed download must not fail the build
        assert text.index("COPY scripts") < text.index("fetch_geo_data.py")
        assert text.index("COPY app") < text.index("fetch_geo_data.py")

    def test_script_names_match_what_the_application_opens(self) -> None:
        script = _fetch_script()
        assert {filename for _edition, filename, _key in script.EDITIONS} == {
            geo_module.COUNTRY_FILENAME,
            geo_module.ASN_FILENAME,
        }
        assert script.BASE_URL.startswith("https://download.db-ip.com/")
        months = script.candidate_months(None)
        assert len(months) == 2 and months[0] > months[1]
        assert script.candidate_months("2026-09") == ["2026-09"]

    def test_a_failed_fetch_leaves_the_existing_files_alone(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        script = _fetch_script()
        directory = _write_files(tmp_path)
        before = {p.name: p.read_bytes() for p in directory.iterdir()}
        calls: list[str] = []

        def download(url: str, target: pathlib.Path) -> str:
            calls.append(url)
            if "asn" in url:
                raise RuntimeError("network down")
            # A valid file, but not the one already in place.
            target.write_bytes(
                _build_mmdb({"8.8.8.0/24": _country("CA")}, record_size=32)
            )
            return "0" * 64

        monkeypatch.setattr(script, "download", download)
        with pytest.raises(RuntimeError):
            script.fetch(directory, "2026-10")
        assert len(calls) == 2
        assert {p.name: p.read_bytes() for p in directory.iterdir()} == before

    def test_a_download_that_is_not_a_usable_database_is_refused(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        script = _fetch_script()

        def download(url: str, target: pathlib.Path) -> str:
            target.write_bytes(b"<html>rate limited</html>")
            return "0" * 64

        monkeypatch.setattr(script, "download", download)
        with pytest.raises(MMDBError):
            script.fetch(tmp_path / "fresh", "2026-10")
        assert not list((tmp_path / "fresh").glob("*.mmdb"))
        assert not list((tmp_path / "fresh").glob(".*.part"))

    def test_a_good_fetch_installs_both_files_and_a_manifest(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        script = _fetch_script()

        def download(url: str, target: pathlib.Path) -> str:
            target.write_bytes(_build_mmdb(NETWORKS if "asn" in url else COUNTRIES))
            return "0" * 64

        monkeypatch.setattr(script, "download", download)
        manifest = script.fetch(tmp_path / "fresh", "2026-10")
        assert manifest["release"] == "2026-10" and manifest["license"] == "CC BY 4.0"
        found = GeoLookup(tmp_path / "fresh")
        try:
            assert found.lookup("8.8.8.8") == GeoAnswer(
                "US", 15169, "Example Search LLC"
            )
        finally:
            found.close()


# ---------------------------------------------------------------------------
# customer venue route: scoping, add-on, and networks withheld at small venues
# ---------------------------------------------------------------------------

ORG_B = uuid.UUID("55555555-0000-4000-8000-000000000005")
SIBLING_LOCATION = uuid.UUID("66666666-0000-4000-8000-000000000006")


class Venues:
    """Stands in for ``LocationService.get_location``: the real one raises
    for a missing venue and for another organisation's."""

    owner = {LOCATION_ID: ORG_ID, SIBLING_LOCATION: ORG_ID, OTHER_LOCATION: ORG_B}

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
    repo: ReadRepo,
    lookup: GeoLookup,
    *,
    confined_to: frozenset[uuid.UUID] | None = None,
) -> CustomerGeoService:
    """The customer service as the route builds it: the REAL venue check of
    the customer venue routes in front of the geo read."""
    from app.domains.traffic_flow.service import TrafficFlowCustomerService

    venues = TrafficFlowCustomerService(
        object(),  # type: ignore[arg-type]
        Venues(),
        SimpleNamespace(  # type: ignore[arg-type]
            traffic_flow_enabled=True,
            traffic_flow_agent_url="",
            traffic_flow_agent_secret="",
        ),
        caller_location_scope=confined_to,
        now=lambda: NOW,
    )
    return CustomerGeoService(_service(repo, lookup), venues)


async def _venue(service: CustomerGeoService, venue: uuid.UUID, **kw: Any) -> Any:
    args: dict[str, Any] = {"organization_id": ORG_ID, "since": None, "until": None}
    args.update(kw)
    return await service.by_country(venue, **args)


def _shown(
    country: str, asn: int, down: int, shown_down: int, name: str | None = None
) -> GeoCountryRow:
    """A summed row where only ``shown_down`` of ``down`` came from windows
    with enough devices."""
    return GeoCountryRow(
        country, asn, name, 0, down, 1, 0, shown_down, 1 if shown_down else 0
    )


def _dependency_calls(dependant: Any) -> set[Any]:
    calls = {d.call for d in dependant.dependencies}
    for d in dependant.dependencies:
        calls |= _dependency_calls(d)
    return calls


class TestCustomerGeo:
    async def test_own_venue_gets_the_master_shape_without_the_platform_switch(
        self, lookup: GeoLookup
    ) -> None:
        repo = _populated()
        out = await _venue(_customer(repo, lookup), LOCATION_ID)
        assert out["location_id"] == str(LOCATION_ID)
        assert "feature_enabled" not in out
        assert out["measured"] and out["geo_measured"]
        assert out["attribution"] == ATTRIBUTION
        assert out["networks_min_devices"] == 5
        assert out["networks_withheld_windows"] == 0

    async def test_every_read_carries_the_venue_the_organisation_and_the_rule(
        self, lookup: GeoLookup
    ) -> None:
        repo = _populated()
        await _venue(_customer(repo, lookup), LOCATION_ID, router_id=ROUTER_ID)
        want = GeoScope(
            router_id=ROUTER_ID,
            location_id=LOCATION_ID,
            organization_id=ORG_ID,
            min_devices=5,
        )
        assert [c[0] for c in repo.calls] == ["bounds", "windows", "looked_up", "rows"]
        assert repo.calls[0][1] == want and repo.calls[1][1][0] == want
        assert repo.calls[2][1] == want and repo.calls[3][1] == want

    async def test_another_organisations_venue_is_a_404_and_nothing_is_read(
        self, lookup: GeoLookup
    ) -> None:
        from app.domains.traffic_flow.service import TrafficFlowLocationNotFoundError

        repo = _populated()
        service = _customer(repo, lookup)
        for venue in (OTHER_LOCATION, uuid.uuid4()):
            with pytest.raises(TrafficFlowLocationNotFoundError) as caught:
                await _venue(service, venue)
            assert caught.value.status_code == 404
        assert repo.calls == []

    async def test_a_caller_confined_to_one_venue_cannot_read_a_sibling(
        self, lookup: GeoLookup
    ) -> None:
        from app.domains.traffic_flow.service import TrafficFlowCrossLocationError

        repo = _populated()
        service = _customer(repo, lookup, confined_to=frozenset({LOCATION_ID}))
        assert (await _venue(service, LOCATION_ID))["measured"] is True
        repo.calls.clear()
        with pytest.raises(TrafficFlowCrossLocationError) as caught:
            await _venue(service, SIBLING_LOCATION)
        assert caught.value.status_code == 403 and repo.calls == []

    async def test_a_router_of_another_venue_only_narrows_within_the_own_venue(
        self, lookup: GeoLookup
    ) -> None:
        repo = _populated()
        foreign_router = uuid.uuid4()
        await _venue(_customer(repo, lookup), LOCATION_ID, router_id=foreign_router)
        for _name, scope in [(c[0], c[1]) for c in repo.calls if c[0] != "windows"]:
            assert scope.location_id == LOCATION_ID
            assert scope.organization_id == ORG_ID

    # -- the small-venue rule: networks only ------------------------------

    def test_networks_come_from_windows_with_enough_devices_only(self) -> None:
        rows = [
            _shown("IN", 55836, 600, 400, "Example Mobile Ltd"),
            _shown("IN", 45609, 100, 0, "Example Broadband Ltd"),  # small windows only
            _shown("IN", UNKNOWN_NETWORK_ASN, 60, 10),
            _shown("IN", OTHER_NETWORK_ASN, 40, 40),
            _shown("US", 15169, 100, 0, "Example Search LLC"),
            _shown(UNKNOWN_COUNTRY, UNKNOWN_NETWORK_ASN, 100, 30),
        ]
        out = _summary(rows, networks_min_devices=5, networks_withheld_windows=4)
        assert out["networks_min_devices"] == 5
        assert out["networks_withheld_windows"] == 4
        india, usa = out["countries"]["items"]
        # Country totals are whole: never withheld.
        assert (india["country_code"], india["bytes"], india["share"]) == (
            "IN",
            800,
            0.8,
        )
        assert out["totals"]["bytes"] == 1000 and out["unknown"]["bytes"] == 100
        # Networks: only what the shown windows carried.
        assert [(n["asn"], n["bytes"]) for n in india["networks"]["items"]] == [
            (55836, 400)
        ]
        assert india["networks"]["unknown_bytes"] == 10
        assert india["networks"]["other_bytes"] == 40
        assert india["networks"]["withheld_bytes"] == 350
        listed = sum(n["bytes"] for n in india["networks"]["items"])
        assert (
            listed
            + india["networks"]["other_bytes"]
            + india["networks"]["unknown_bytes"]
            + india["networks"]["withheld_bytes"]
            == india["bytes"]
        )
        # A country seen only in small windows: its total, and no network.
        assert usa["bytes"] == 100
        assert usa["networks"] == {
            "items": [],
            "other_bytes": 0,
            "unknown_bytes": 0,
            "withheld_bytes": 100,
        }
        assert "Example Broadband" not in repr(out)
        assert "Example Search" not in repr(out)

    def test_master_withholds_nothing_and_has_no_rule_fields(self) -> None:
        out = _summary(ROWS)
        assert "networks_min_devices" not in out
        assert "networks_withheld_windows" not in out
        assert "withheld_bytes" not in out["countries"]["items"][0]["networks"]

    async def test_withheld_windows_reach_the_customer_response(
        self, lookup: GeoLookup
    ) -> None:
        repo = _populated()
        repo.withheld[LOCATION_ID] = 2
        repo.rows[LOCATION_ID] = [
            _shown("IN", 55836, 600, 200, "Example Mobile Ltd"),
            _shown(UNKNOWN_COUNTRY, UNKNOWN_NETWORK_ASN, 0, 0),
        ]
        out = await _venue(_customer(repo, lookup), LOCATION_ID)
        assert out["networks_withheld_windows"] == 2
        (india,) = out["countries"]["items"]
        assert india["bytes"] == 600
        assert india["networks"]["items"][0]["bytes"] == 200
        assert india["networks"]["withheld_bytes"] == 400
        # The Master route, same data: nothing withheld.
        master = await _ask(_service(repo, lookup))
        assert "networks_withheld_windows" not in master

    async def test_not_measured_keeps_the_rule_fields_and_withholds_nothing(
        self, lookup: GeoLookup
    ) -> None:
        out = await _venue(
            _customer(_populated(), lookup),
            LOCATION_ID,
            since=NOW - timedelta(days=2),
            until=NOW - timedelta(days=1),
        )
        assert out["measured"] is False and out["totals"] is None
        assert out["networks_min_devices"] == 5
        assert out["networks_withheld_windows"] == 0

    def test_the_rule_is_the_destinations_condition_itself(self) -> None:
        from app.domains.traffic_flow.constants import (
            CUSTOMER_MIN_DEVICES_FOR_DESTINATIONS,
        )
        from app.domains.traffic_flow.destinations import DestinationScope

        scope = GeoScope(
            location_id=LOCATION_ID,
            organization_id=ORG_ID,
            min_devices=CUSTOMER_MIN_DEVICES_FOR_DESTINATIONS,
        )
        mine = _sql(scope.shown(TrafficFlowCountryBucket))
        (theirs,) = DestinationScope(
            location_id=LOCATION_ID, min_devices=CUSTOMER_MIN_DEVICES_FOR_DESTINATIONS
        ).visible(TrafficFlowCountryBucket)
        assert mine == _sql(theirs)
        assert "traffic_flow_windows.talker_count >=" in mine and "EXISTS" in mine
        assert GeoScope(location_id=LOCATION_ID).shown(TrafficFlowCountryBucket) is None

    def test_customer_statements_carry_organisation_venue_and_the_rule(self) -> None:
        scope = GeoScope(location_id=LOCATION_ID, organization_id=ORG_ID, min_devices=5)
        rows = _sql(
            country_rows_statement(scope, since=NOW - timedelta(hours=1), until=NOW)
        )
        assert "traffic_flow_country_buckets.organization_id =" in rows
        assert "traffic_flow_country_buckets.location_id =" in rows
        assert rows.count("FILTER (WHERE EXISTS") == 3
        # The rule is a FILTER on the network sums, never a WHERE: a country's
        # total must not shrink.
        where = rows[rows.rindex("WHERE") : rows.index("GROUP BY")]
        assert "talker_count" not in where
        counted = _sql(
            windows_looked_up_statement(
                scope, since=NOW - timedelta(hours=1), until=NOW
            )
        )
        assert "organization_id =" in counted
        assert "FILTER (WHERE NOT (EXISTS" in counted
        master = _sql(
            country_rows_statement(
                GeoScope(location_id=LOCATION_ID),
                since=NOW - timedelta(hours=1),
                until=NOW,
            )
        )
        assert "FILTER" not in master and "organization_id =" not in master

    # -- route, guards, add-on --------------------------------------------

    @staticmethod
    def _route() -> Any:
        from app.domains.traffic_flow.geo_customer_router import (
            traffic_flow_geo_customer_router as router,
        )

        (route,) = router.routes
        return route

    def test_read_only_and_only_this_one(self) -> None:
        route = self._route()
        assert route.path == "/traffic-flow/locations/{location_id}/geo"
        assert route.methods == {"GET"}

    def test_it_carries_the_customer_venue_routes_own_guards(self) -> None:
        """The very same three objects, so the add-on key and the permission
        cannot drift apart."""
        from app.domains.billing.constants import PlanFeatureKey
        from app.domains.rbac.dependencies import RequireOrganization
        from app.domains.traffic_flow import customer_router

        expected = [g.dependency for g in customer_router._GUARDS]  # noqa: SLF001

        def closure(call: Any) -> list[Any]:
            return [c.cell_contents for c in (getattr(call, "__closure__", None) or ())]

        assert len(expected) == 3 and expected[0] is RequireOrganization
        assert PlanFeatureKey.TRAFFIC_FLOW in closure(expected[1])
        assert "venue_traffic.read" in closure(expected[2])
        assert ScopeType.LOCATION in closure(expected[2])
        guards = [d.dependency for d in self._route().dependencies]
        assert len(guards) == 3
        for mine, theirs in zip(guards, expected, strict=True):
            assert mine is theirs

    async def test_add_on_off_is_a_402_naming_the_feature(self) -> None:
        from decimal import Decimal

        from app.domains.billing.constants import PlanFeatureKey
        from app.domains.billing.exceptions import FeatureNotEntitledError

        def closure(call: Any) -> list[Any]:
            return [c.cell_contents for c in (getattr(call, "__closure__", None) or ())]

        (guard,) = [
            d.dependency
            for d in self._route().dependencies
            if PlanFeatureKey.TRAFFIC_FLOW in closure(d.dependency)
        ]

        class Checker:
            def __init__(self, *features: str) -> None:
                self.features = features

            async def get_snapshot(self, organization_id: uuid.UUID) -> Any:
                return SimpleNamespace(
                    enabled_features=frozenset(self.features),
                    limits={"max_locations": Decimal(1)},
                    has_feature=lambda key: key.value in self.features,
                )

        with pytest.raises(FeatureNotEntitledError) as caught:
            await guard(organization_id=ORG_ID, checker=Checker("reports"))
        assert caught.value.status_code == 402
        assert caught.value.data == {
            "error_code": "feature_not_entitled",
            "feature_key": "traffic_flow",
        }
        assert await guard(organization_id=ORG_ID, checker=Checker("traffic_flow"))

    def test_it_resolves_organization_location_and_confinement(self) -> None:
        from app.domains.rbac.dependencies import (
            CurrentLocation,
            CurrentOrganization,
            RequireOrganization,
        )
        from app.domains.rbac.location_scope import CallerLocationScope

        calls = _dependency_calls(self._route().dependant)
        for needed in (
            RequireOrganization,
            CurrentOrganization,
            CurrentLocation,
            CallerLocationScope,
        ):
            assert needed in calls

    def test_it_takes_no_organisation_and_no_threshold(self) -> None:
        route = self._route()
        assert {p.name for p in route.dependant.path_params} == {"location_id"}
        assert {p.name for p in route.dependant.query_params} == {
            "router_id",
            "since",
            "until",
            "limit",
            "networks",
        }
        assert route.dependant.body_params == []

    async def test_a_header_naming_another_venue_is_refused(self) -> None:
        from app.domains.traffic_flow.geo_customer_router import get_venue_traffic_geo
        from app.domains.traffic_flow.service import TrafficFlowCrossLocationError

        class Never:
            async def by_country(self, *args: Any, **kwargs: Any) -> Any:
                raise AssertionError("nothing may be read")

        with pytest.raises(TrafficFlowCrossLocationError):
            await get_venue_traffic_geo(
                LOCATION_ID,
                SimpleNamespace(state=SimpleNamespace(request_id="r")),  # type: ignore[arg-type]
                since=None,
                until=None,
                limit=None,
                networks=None,
                router_id=None,
                organization_id=ORG_ID,
                header_location_id=SIBLING_LOCATION,
                service=Never(),  # type: ignore[arg-type]
            )
