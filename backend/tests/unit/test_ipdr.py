"""IPDR: join, formats, archive, tenant isolation, permission scope, audit.

All data here is obviously fake: 192.0.2.0/24 / 198.51.100.0/24 /
203.0.113.0/24 (RFC 5737), phones 90000000xx, @example.com, made-up MACs.
"""

from __future__ import annotations

import csv
import io
import pathlib
import uuid
from datetime import UTC, date, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest

from app.domains.ipdr import router as ipdr_routes
from app.domains.ipdr.archive import (
    ArchiveReader,
    LocalIpdrArchive,
    decode_day,
    encode_day,
)
from app.domains.ipdr.builder import (
    IpdrBuilder,
    ist_day_bounds,
    subject_digest,
    subjects_of,
)
from app.domains.ipdr.constants import (
    AUDIT_ACTION_IPDR_EXPORT_COMPLETED,
    AUDIT_ACTION_IPDR_EXPORTED,
    AUDIT_ACTION_IPDR_LISTED,
    IPDR_COLUMNS,
    IST,
    SUBJECT_PHONE,
    TRANSLATION_AMBIGUOUS,
    TRANSLATION_DERIVED,
    TRANSLATION_NAT_EVENT,
    TRANSLATION_NONE,
    UNKNOWN_USER,
)
from app.domains.ipdr.exceptions import (
    IpdrBadCursorError,
    IpdrLocationNotFoundError,
    IpdrRangeTooLongError,
    IpdrRouterNotFoundError,
)
from app.domains.ipdr.formatting import (
    csv_cells,
    ist_minute,
    list_item,
    mask_email,
    mask_phone,
    online_time,
)
from app.domains.ipdr.join import (
    FlowInput,
    SessionInput,
    build_records,
    fold_connections,
)
from app.domains.ipdr.repository import DayFileRow
from app.domains.ipdr.service import IpdrService, _LiveCache
from app.domains.ipdr.translation import ExactOrRouterPublicIp
from app.domains.rbac.enums import ScopeType

ORG_A = uuid.UUID("00000000-0000-0000-0000-00000000000a")
ORG_B = uuid.UUID("00000000-0000-0000-0000-00000000000b")
LOC_A = uuid.UUID("00000000-0000-0000-0000-0000000000a1")
LOC_A2 = uuid.UUID("00000000-0000-0000-0000-0000000000a2")
LOC_B = uuid.UUID("00000000-0000-0000-0000-0000000000b1")
R_A = uuid.UUID("00000000-0000-0000-0000-00000000aa01")
R_A2 = uuid.UUID("00000000-0000-0000-0000-00000000aa02")
R_B = uuid.UUID("00000000-0000-0000-0000-00000000bb01")
GRACE = timedelta(seconds=120)
PUBLIC = {R_A: "203.0.113.10", R_A2: "203.0.113.20", R_B: "203.0.113.30"}


def ist(y: int, mo: int, d: int, h: int = 0, mi: int = 0, s: int = 0) -> datetime:
    return datetime(y, mo, d, h, mi, s, tzinfo=IST).astimezone(UTC)


def flow(
    at: datetime,
    *,
    router: uuid.UUID = R_A,
    src: str = "192.168.88.24",
    sport: int | None = 51515,
    dst: str = "198.51.100.7",
    dport: int | None = 443,
    proto: int = 6,
    direction: str = "upload",
    end: datetime | None = None,
    nat: str | None = None,
    nat_port: int | None = None,
    timed: bool = True,
    nbytes: int = 100,
) -> FlowInput:
    window = at.replace(minute=at.minute - at.minute % 5, second=0)
    return FlowInput(
        router_id=router,
        window_start=window,
        flow_start=at if timed else None,
        flow_end=(end or at) if timed else None,
        direction=direction,
        src_address=src,
        src_port=sport,
        dst_address=dst,
        dst_port=dport,
        protocol=proto,
        nat_src_address=nat,
        nat_src_port=nat_port,
        bytes=nbytes,
        packets=1,
    )


def session(
    start: datetime,
    end: datetime | None,
    *,
    ip: str = "192.168.88.24",
    router: uuid.UUID = R_A,
    phone: str = "9000000011",
    name: str | None = "Test Guest One",
    email: str | None = "guest.one@example.com",
    mac: str | None = "02:00:00:00:00:11",
) -> SessionInput:
    return SessionInput(
        id=uuid.uuid4(),
        guest_id=uuid.uuid4(),
        router_id=router,
        ip_address=ip,
        started_at=start,
        ended_at=end,
        last_activity_at=end or start + timedelta(hours=1),
        identifier=phone,
        display_name=name,
        email=email,
        mac_address=mac,
    )


def build(flows, sessions, *, location=LOC_A, org=ORG_A, public=None, **kw):
    return build_records(
        flows,
        sessions,
        ExactOrRouterPublicIp(PUBLIC if public is None else public),
        organization_id=org,
        location_id=location,
        grace=GRACE,
        **kw,
    )


# -- formats ------------------------------------------------------------------


class TestFormats:
    def test_columns_are_exactly_the_brief_minus_address(self) -> None:
        expected = (
            '"Time Stamp (IST)","Name of Person/Organization","Contact No.",'
            '"Alternate Contact No.","E-mail Address","User ID for Internet '
            'Access","Source IP Address","Source Port","Translated IP Address",'
            '"Translated Port","Static/Dynamic IP Address Allocation",'
            '"Destination IP Address","Destination Port",Protocol,"IST Start '
            'Time & Date of IP Allocation","IST End Time & Date of IP '
            'Allocation","Total Online Time","Source MAC Address/IMEI/Device ID"'
        )
        assert next(csv.reader([expected])) == list(IPDR_COLUMNS)
        assert "Address" not in IPDR_COLUMNS
        assert len(IPDR_COLUMNS) == 18

    def test_ist_minute(self) -> None:
        moment = datetime(2026, 10, 17, 18, 31, 59, tzinfo=UTC)
        assert ist_minute(moment) == "18-10-2026 00:01"
        assert ist_minute(moment.isoformat()) == "18-10-2026 00:01"
        assert ist_minute(None) == ""

    @pytest.mark.parametrize(
        ("seconds", "text"),
        [
            (1 * 86400 + 9 * 3600 + 7 * 60 + 1, "1d 9h 7m 1s"),
            (86400 + 5, "1d 0h 0m 5s"),
            (421, "7m 1s"),
            (45, "45s"),
            (0, "0s"),
            (None, ""),
        ],
    )
    def test_online_time(self, seconds, text) -> None:
        assert online_time(seconds) == text

    def test_masks(self) -> None:
        assert mask_phone("9812345620") == "98xxxxxx20"
        assert mask_phone("+91 98123 45620") == "91xxxxxxxx20"
        assert mask_email("guest.one@example.com") == "g***@example.com"

    def test_formula_injection_is_neutralised(self) -> None:
        record = _known_record(name="=HYPERLINK(1)")
        assert csv_cells(record)[1] == "'=HYPERLINK(1)"


def _known_record(**over: Any) -> dict[str, Any]:
    start = ist(2026, 10, 17, 21, 0)
    records = build(
        [flow(ist(2026, 10, 17, 22, 15))],
        [session(start, ist(2026, 10, 18, 6, 7, 1))],
    )
    return {**records[0], **over}


class TestCsvRow:
    def test_a_matched_row_in_column_order(self) -> None:
        cells = csv_cells(_known_record())
        assert dict(zip(IPDR_COLUMNS, cells, strict=True)) == {
            "Time Stamp (IST)": "17-10-2026 22:15",
            "Name of Person/Organization": "Test Guest One",
            "Contact No.": "9000000011",
            "Alternate Contact No.": "",
            "E-mail Address": "guest.one@example.com",
            "User ID for Internet Access": "9000000011",
            "Source IP Address": "192.168.88.24",
            "Source Port": "51515",
            "Translated IP Address": "203.0.113.10",
            "Translated Port": "51515",
            "Static/Dynamic IP Address Allocation": "Dynamic",
            "Destination IP Address": "198.51.100.7",
            "Destination Port": "443",
            "Protocol": "TCP",
            "IST Start Time & Date of IP Allocation": "17-10-2026 21:00",
            "IST End Time & Date of IP Allocation": "18-10-2026 06:07",
            "Total Online Time": "9h 7m 1s",
            "Source MAC Address/IMEI/Device ID": "02:00:00:00:00:11",
        }

    def test_provenance_columns_only_on_request(self) -> None:
        record = _known_record()
        assert len(csv_cells(record)) == 18
        assert csv_cells(record, provenance=True)[18:] == [
            TRANSLATION_DERIVED,
            "matched",
        ]

    def test_list_item_masks_phone_and_email_only(self) -> None:
        item = list_item(_known_record())
        assert item["contact_no"] == "90xxxxxx11"
        assert item["user_id"] == "90xxxxxx11"
        assert item["email"] == "g***@example.com"
        assert item["source_ip"] == "192.168.88.24"
        assert item["mac"] == "02:00:00:00:00:11"
        assert "9000000011" not in repr(item)
        assert "guest.one@" not in repr(item)


# -- join ---------------------------------------------------------------------


class TestJoin:
    def test_ip_reused_by_two_guests_in_one_day(self) -> None:
        one = session(ist(2026, 10, 17, 9), ist(2026, 10, 17, 11), phone="9000000011")
        two = session(
            ist(2026, 10, 17, 14),
            ist(2026, 10, 17, 16),
            phone="9000000022",
            mac="02:00:00:00:00:22",
        )
        records = build(
            [flow(ist(2026, 10, 17, 10)), flow(ist(2026, 10, 17, 15))],
            [one, two],
        )
        by_hour = {ist_minute(r["ts"])[-5:]: r["phone"] for r in records}
        assert by_hour == {"10:00": "9000000011", "15:00": "9000000022"}

    def test_a_flow_with_no_session_is_unknown(self) -> None:
        records = build(
            [flow(ist(2026, 10, 17, 12))],
            [session(ist(2026, 10, 17, 9), ist(2026, 10, 17, 11))],
        )
        (record,) = records
        assert record["user_known"] is False
        cells = dict(zip(IPDR_COLUMNS, csv_cells(record), strict=True))
        assert cells["User ID for Internet Access"] == UNKNOWN_USER
        assert cells["Contact No."] == cells["Name of Person/Organization"] == ""
        assert cells["Total Online Time"] == ""
        assert cells["Source IP Address"] == "192.168.88.24"

    def test_session_crossing_midnight_matches_both_days(self) -> None:
        crossing = session(ist(2026, 10, 17, 23, 30), ist(2026, 10, 18, 1, 0))
        flows = [flow(ist(2026, 10, 17, 23, 45)), flow(ist(2026, 10, 18, 0, 10))]
        for day in (date(2026, 10, 17), date(2026, 10, 18)):
            start, end = ist_day_bounds(day)
            (record,) = build(flows, [crossing], start=start, end=end)
            cells = dict(zip(IPDR_COLUMNS, csv_cells(record), strict=True))
            assert cells["IST Start Time & Date of IP Allocation"] == (
                "17-10-2026 23:30"
            )
            assert cells["IST End Time & Date of IP Allocation"] == "18-10-2026 01:00"
            assert cells["Total Online Time"] == "1h 30m 0s"

    def test_latest_start_wins_over_a_stale_active_row(self) -> None:
        stale = session(ist(2026, 10, 17, 8), None, phone="9000000011")
        newer = session(ist(2026, 10, 17, 12), None, phone="9000000022")
        (record,) = build([flow(ist(2026, 10, 17, 13))], [stale, newer])
        assert record["phone"] == "9000000022"

    def test_grace_after_end_and_not_beyond(self) -> None:
        ended = session(ist(2026, 10, 17, 9), ist(2026, 10, 17, 10))
        inside = build([flow(ist(2026, 10, 17, 10, 1, 59))], [ended])
        outside = build([flow(ist(2026, 10, 17, 10, 2, 1))], [ended])
        assert inside[0]["user_known"] and not outside[0]["user_known"]

    def test_same_ip_on_another_router_is_not_this_guest(self) -> None:
        other = session(ist(2026, 10, 17, 9), None, router=R_A2)
        (record,) = build([flow(ist(2026, 10, 17, 10))], [other])
        assert record["user_known"] is False

    def test_download_is_mirrored_and_folded_into_the_upload(self) -> None:
        at = ist(2026, 10, 17, 10)
        up = flow(at)
        down = flow(
            at + timedelta(seconds=1),
            src="198.51.100.7",
            sport=443,
            dst="192.168.88.24",
            dport=51515,
            direction="download",
            nbytes=900,
        )
        (conn,) = fold_connections([up, down])
        assert (conn.guest_ip, conn.guest_port) == ("192.168.88.24", 51515)
        assert (conn.remote_ip, conn.remote_port) == ("198.51.100.7", 443)
        assert conn.bytes == 1000

    def test_internal_and_platform_records_are_dropped(self) -> None:
        at = ist(2026, 10, 17, 10)
        assert (
            fold_connections(
                [flow(at, direction="internal"), flow(at, direction="platform")]
            )
            == []
        )

    def test_stitches_within_20s_and_splits_beyond(self) -> None:
        at = ist(2026, 10, 17, 10)
        a = flow(at, end=at + timedelta(seconds=60))
        b = flow(at + timedelta(seconds=75))  # 15 s gap: one connection
        c = flow(at + timedelta(seconds=120))  # 45 s gap: a new one
        conns = sorted(fold_connections([a, b, c]), key=lambda x: x.ts)
        assert len(conns) == 2
        assert conns[0].ts_end == at + timedelta(seconds=75)

    def test_window_only_records_stitch_within_their_window_only(self) -> None:
        at = ist(2026, 10, 17, 10, 1)
        same = [flow(at, timed=False), flow(at + timedelta(minutes=1), timed=False)]
        assert len(fold_connections(same)) == 1
        apart = [flow(at, timed=False), flow(at + timedelta(minutes=5), timed=False)]
        assert len(fold_connections(apart)) == 2
        assert fold_connections(same)[0].ts_source == "window"


class TestTranslation:
    def test_observed_translation_is_used(self) -> None:
        (record,) = build(
            [flow(ist(2026, 10, 17, 10), nat="203.0.113.99", nat_port=40001)], []
        )
        assert (record["nat_ip"], record["nat_port"]) == ("203.0.113.99", 40001)
        assert record["nat_source"] == TRANSLATION_NAT_EVENT

    def test_post_nat_equal_to_source_is_not_a_translation(self) -> None:
        (record,) = build(
            [flow(ist(2026, 10, 17, 10), nat="192.168.88.24", nat_port=51515)], []
        )
        assert record["nat_source"] == TRANSLATION_DERIVED
        assert (record["nat_ip"], record["nat_port"]) == ("203.0.113.10", 51515)

    def test_no_public_address_means_blank(self) -> None:
        (record,) = build([flow(ist(2026, 10, 17, 10))], [], public={})
        assert record["nat_source"] == TRANSLATION_NONE
        assert record["nat_ip"] is None and record["nat_port"] is None

    def test_fixed_source_port_is_ambiguous(self) -> None:
        (record,) = build([flow(ist(2026, 10, 17, 10), sport=123, proto=17)], [])
        assert record["nat_source"] == TRANSLATION_AMBIGUOUS

    def test_two_guests_on_one_port_and_destination_are_ambiguous(self) -> None:
        at = ist(2026, 10, 17, 10)
        records = build(
            [
                flow(at, src="192.168.88.24"),
                flow(at + timedelta(seconds=5), src="192.168.88.25"),
                flow(at, src="192.168.88.26", sport=40000),
            ],
            [],
        )
        by_src = {r["src_ip"]: r["nat_source"] for r in records}
        assert by_src == {
            "192.168.88.24": TRANSLATION_AMBIGUOUS,
            "192.168.88.25": TRANSLATION_AMBIGUOUS,
            "192.168.88.26": TRANSLATION_DERIVED,
        }


# -- fakes ---------------------------------------------------------------------


class FakeRepo:
    def __init__(self) -> None:
        self.locations = {LOC_A: ORG_A, LOC_A2: ORG_A, LOC_B: ORG_B}
        self.routers = {R_A: (ORG_A, LOC_A), R_A2: (ORG_A, LOC_A2), R_B: (ORG_B, LOC_B)}
        self.flow_rows: dict[uuid.UUID, list[FlowInput]] = {}
        self.session_rows: list[SessionInput] = []
        self.files: dict[tuple[uuid.UUID, date], DayFileRow] = {}
        self.subjects: dict[int, set[tuple[str, str]]] = {}
        self.calls: list[str] = []

    async def location_organization(self, location_id):
        return self.locations.get(location_id)

    async def router_owner(self, router_id):
        return self.routers.get(router_id)

    async def organization_location_ids(self, organization_id):
        return sorted(
            (k for k, v in self.locations.items() if v == organization_id), key=str
        )

    async def locations_with_flows(self, start, end):
        out = []
        for loc, rows in self.flow_rows.items():
            if any(start - timedelta(minutes=10) <= r.window_start < end for r in rows):
                out.append((loc, self.locations[loc]))
        return sorted(out, key=lambda p: str(p[0]))

    async def flows(self, location_id, start, end):
        self.calls.append(f"flows:{location_id}")
        return [
            r
            for r in self.flow_rows.get(location_id, [])
            if start - timedelta(minutes=10) <= r.window_start < end
        ]

    async def sessions(self, router_ids, start, end, *, grace):
        ids = set(router_ids)
        return [s for s in self.session_rows if s.router_id in ids]

    async def router_public_ips(self, router_ids):
        return {r: PUBLIC.get(r) for r in router_ids}

    async def records_incomplete(self, location_id, start, end):
        return False

    async def day_files(self, organization_id, location_ids, first, last):
        return [
            row
            for (loc, day), row in self.files.items()
            if row.organization_id == organization_id
            and (location_ids is None or loc in location_ids)
            and first <= day <= last
        ]

    async def day_file(self, location_id, day):
        return self.files.get((location_id, day))

    async def days_with_subject(self, organization_id, first, last, kind, digest):
        return {
            (row.location_id, row.day)
            for row in self.files.values()
            if row.organization_id == organization_id
            and first <= row.day <= last
            and (kind, digest) in self.subjects.get(row.id, set())
        }

    async def save_day_file(self, values, subjects):
        key = (values["location_id"], values["day"])
        row_id = len(self.files) + 1
        self.files[key] = DayFileRow(
            id=row_id,
            organization_id=values["organization_id"],
            location_id=values["location_id"],
            day=values["day"],
            store=values["store"],
            object_key=values["object_key"],
            sha256=values["sha256"],
            row_count=values["row_count"],
            records_incomplete=values["records_incomplete"],
        )
        self.subjects[row_id] = set(subjects)
        return row_id


def _settings(tmp_path: pathlib.Path) -> SimpleNamespace:
    return SimpleNamespace(
        ipdr_session_grace_seconds=120,
        ipdr_archive_prefix="ipdr/",
        ipdr_local_dir=str(tmp_path),
        ipdr_archive_bucket="",
        traffic_flow_record_retention_days=7,
    )


NOW = ist(2026, 10, 18, 12, 0)


def _env(tmp_path: pathlib.Path, repo: FakeRepo | None = None):
    repo = repo or FakeRepo()
    settings = _settings(tmp_path)
    archive = LocalIpdrArchive(tmp_path)
    builder = IpdrBuilder(
        repo,  # type: ignore[arg-type]
        settings,  # type: ignore[arg-type]
        archive,
        clock=lambda: NOW,
    )
    service = IpdrService(
        repo,  # type: ignore[arg-type]
        settings,  # type: ignore[arg-type]
        builder,
        ArchiveReader({"local": archive}),
        clock=lambda: NOW,
        live_cache=_LiveCache(),
    )
    return repo, builder, service


def _seed(repo: FakeRepo) -> None:
    """Org A: LOC_A has guest one (17th) and guest two (18th, today);
    LOC_A2 has guest three. Org B: LOC_B reuses the very same LAN address
    and phone-shaped identifier space."""
    repo.flow_rows[LOC_A] = [
        flow(ist(2026, 10, 17, 10, m)) for m in range(0, 30, 3)
    ] + [flow(ist(2026, 10, 18, 9, m), src="192.168.88.30") for m in range(0, 15, 3)]
    repo.flow_rows[LOC_A2] = [
        flow(ist(2026, 10, 17, 11), router=R_A2, src="192.168.10.5")
    ]
    repo.flow_rows[LOC_B] = [flow(ist(2026, 10, 17, 10, 5), router=R_B)]
    repo.session_rows = [
        session(ist(2026, 10, 17, 9), ist(2026, 10, 17, 12)),
        session(
            ist(2026, 10, 18, 8),
            None,
            ip="192.168.88.30",
            phone="9000000022",
            mac="02:00:00:00:00:22",
        ),
        session(
            ist(2026, 10, 17, 10),
            None,
            router=R_A2,
            ip="192.168.10.5",
            phone="9000000033",
        ),
        session(ist(2026, 10, 17, 9), None, router=R_B, phone="9000000099"),
    ]


# -- builder / archive --------------------------------------------------------


class TestBuilder:
    async def test_build_day_archives_and_indexes(self, tmp_path) -> None:
        repo, builder, _ = _env(tmp_path)
        _seed(repo)
        result = await builder.build_day(LOC_A, ORG_A, date(2026, 10, 17))
        assert result["rows"] == 10
        row = repo.files[(LOC_A, date(2026, 10, 17))]
        assert row.object_key.startswith(
            f"ipdr/v1/org={ORG_A}/loc={LOC_A}/date=2026-10-17/ipdr-"
        )
        records = decode_day((tmp_path / row.object_key).read_bytes())
        assert {r["phone"] for r in records} == {"9000000011"}
        assert (SUBJECT_PHONE, subject_digest(SUBJECT_PHONE, "9000000011")) in (
            repo.subjects[row.id]
        )
        # Hashes only: the index never holds the value.
        assert not any("9000000011" in d for _, d in repo.subjects[row.id])

    async def test_closed_days_are_inside_flow_retention(self, tmp_path) -> None:
        _, builder, _ = _env(tmp_path)
        days = builder.closed_days()
        assert days[-1] == date(2026, 10, 17)
        assert days[0] == date(2026, 10, 12)
        assert date(2026, 10, 18) not in days

    async def test_run_skips_built_days_and_survives_a_failure(self, tmp_path) -> None:
        repo, builder, _ = _env(tmp_path)
        _seed(repo)
        commits: list[int] = []

        async def commit() -> None:
            commits.append(1)

        first = await builder.run_closed_days(commit=commit)
        assert first["built"] == 3 and first["failed"] == 0
        again = await builder.run_closed_days(commit=commit)
        assert again["built"] == 0 and again["skipped"] == 3
        assert len(commits) == 3

    def test_encoding_is_deterministic(self) -> None:
        records = [_known_record()]
        assert encode_day(records) == encode_day(records)
        assert decode_day(encode_day(records)) == records

    def test_subjects_cover_phone_user_mac_and_ips(self) -> None:
        kinds = {k for k, _ in subjects_of([_known_record()])}
        assert kinds == {"phone", "user", "mac", "ip"}


# -- service: tenant isolation, filters, paging --------------------------------


async def _page(service, **kw):
    limit = kw.pop("limit", None)
    f = await service.build_filters(organization_id=kw.pop("org", ORG_A), **kw)
    return f, await service.list_page(f, limit=limit)


class TestTenantIsolation:
    async def test_another_orgs_location_or_router_is_404(self, tmp_path) -> None:
        _, _, service = _env(tmp_path)
        with pytest.raises(IpdrLocationNotFoundError):
            await service.build_filters(organization_id=ORG_A, location_id=LOC_B)
        with pytest.raises(IpdrRouterNotFoundError):
            await service.build_filters(organization_id=ORG_A, router_id=R_B)
        with pytest.raises(IpdrLocationNotFoundError):
            await service.build_filters(organization_id=ORG_A, location_id=uuid.uuid4())

    async def test_rows_never_cross_organizations(self, tmp_path) -> None:
        repo, builder, service = _env(tmp_path)
        _seed(repo)
        await builder.run_closed_days()
        since = ist(2026, 10, 17)
        _, page_a = await _page(service, since=since, until=NOW, limit=200)
        _, page_b = await _page(service, org=ORG_B, since=since, until=NOW, limit=200)
        locs_a = {i["location_id"] for i in page_a["items"]}
        locs_b = {i["location_id"] for i in page_b["items"]}
        assert locs_a == {str(LOC_A), str(LOC_A2)}
        assert locs_b == {str(LOC_B)}
        # Same LAN address in both orgs, each matched to its own guest.
        assert {i["contact_no"] for i in page_b["items"]} == {"90xxxxxx99"}
        assert "90xxxxxx99" not in {i["contact_no"] for i in page_a["items"]}

    async def test_a_subject_of_another_org_finds_nothing(self, tmp_path) -> None:
        repo, builder, service = _env(tmp_path)
        _seed(repo)
        await builder.run_closed_days()
        _, page = await _page(
            service, phone="9000000099", since=ist(2026, 10, 17), until=NOW
        )
        assert page["items"] == []


class TestFiltersAndPaging:
    async def test_range_is_at_most_730_days(self, tmp_path) -> None:
        _, _, service = _env(tmp_path)
        with pytest.raises(IpdrRangeTooLongError):
            await service.build_filters(
                organization_id=ORG_A, since=NOW - timedelta(days=731), until=NOW
            )
        await service.build_filters(
            organization_id=ORG_A, since=NOW - timedelta(days=730), until=NOW
        )

    async def test_bad_cursor(self, tmp_path) -> None:
        _, _, service = _env(tmp_path)
        with pytest.raises(IpdrBadCursorError):
            await service.build_filters(organization_id=ORG_A, cursor="nope")

    async def test_keyset_pages_cover_everything_once(self, tmp_path) -> None:
        repo, builder, service = _env(tmp_path)
        _seed(repo)
        await builder.run_closed_days()  # the 17th archived, today live
        seen: list[str] = []
        cursor = None
        coverage = {}
        while True:
            _, page = await _page(
                service, since=ist(2026, 10, 17), until=NOW, limit=4, cursor=cursor
            )
            seen += [i["ts"] + i["source_ip"] for i in page["items"]]
            coverage.update({c["day"]: c["status"] for c in page["coverage"]})
            cursor = page["next_cursor"]
            if not cursor:
                break
        assert len(seen) == len(set(seen)) == 10 + 1 + 5
        assert seen == sorted(seen, reverse=True)
        assert coverage == {"2026-10-18": "live", "2026-10-17": "archived"}

    async def test_filters(self, tmp_path) -> None:
        repo, builder, service = _env(tmp_path)
        _seed(repo)
        await builder.run_closed_days()
        since = ist(2026, 10, 17)
        for kw, count in (
            ({"phone": "+91 90000 00022"}, 5),
            ({"user_id": "9000000033"}, 1),
            ({"mac": "02-00-00-00-00-22"}, 5),
            ({"ip": "192.168.10.5"}, 1),
            ({"ip": "203.0.113.20"}, 1),  # the derived translated address
            ({"dst_ip": "198.51.100.7"}, 16),
            ({"location_id": LOC_A2}, 1),
            ({"router_id": R_A}, 15),
        ):
            _, page = await _page(service, since=since, until=NOW, limit=200, **kw)
            assert len(page["items"]) == count, kw

    async def test_a_missing_day_says_so(self, tmp_path) -> None:
        _, _, service = _env(tmp_path)
        _, page = await _page(
            service, since=ist(2026, 9, 1), until=ist(2026, 9, 2), limit=10
        )
        assert [c["status"] for c in page["coverage"]] == ["missing"]

    async def test_a_page_opens_at_most_31_days(self, tmp_path) -> None:
        _, _, service = _env(tmp_path)
        _, page = await _page(
            service, since=NOW - timedelta(days=400), until=NOW, phone="9000000011"
        )
        assert len(page["coverage"]) == 31
        assert page["next_cursor"]


# -- route guards, permission scope, audit -------------------------------------


def _closure(call) -> set[str]:
    return {str(cell.cell_contents) for cell in (call.__closure__ or ())}


class TestRouteGuards:
    def test_each_route_pins_its_key_at_organization_scope(self) -> None:
        from app.domains.rbac.dependencies import RequireOrganization

        routes = {r.path: r for r in ipdr_routes.ipdr_router.routes}
        assert set(routes) == {"/ipdr/connections", "/ipdr/export.csv"}
        for path, key in (
            ("/ipdr/connections", "ipdr.read"),
            ("/ipdr/export.csv", "ipdr.export"),
        ):
            deps = [d.dependency for d in routes[path].dependencies]
            assert deps[0] is RequireOrganization
            closure = _closure(deps[1])
            assert key in closure, path
            assert ScopeType.ORGANIZATION.value in closure, path

    def test_no_route_accepts_an_organization_parameter(self) -> None:
        for route in ipdr_routes.ipdr_router.routes:
            names = {p.name for p in route.dependant.query_params}
            names |= {p.name for p in route.dependant.path_params}
            for dep in route.dependant.dependencies:
                names |= {p.name for p in dep.query_params}
            assert "organization_id" not in names, route.path

    def test_routes_are_mounted(self) -> None:
        from app.api.v1.router import api_v1_router

        paths = {getattr(r, "path", "") for r in api_v1_router.routes}
        assert {"/ipdr/connections", "/ipdr/export.csv"} <= paths


class TestRbacSeed:
    def test_module_shape(self) -> None:
        from app.domains.rbac.enums import PermissionModule
        from app.domains.rbac.seed import MODULE_ACTIONS, MODULE_NARROWEST_SCOPE

        assert [a.value for a in MODULE_ACTIONS[PermissionModule.IPDR]] == [
            "read",
            "export",
        ]
        assert MODULE_NARROWEST_SCOPE[PermissionModule.IPDR] == ScopeType.ORGANIZATION

    def test_owner_and_admin_only(self) -> None:
        from app.domains.rbac.enums import PermissionModule
        from app.domains.rbac.seed import SYSTEM_ROLES

        holders = {
            r.slug: {a.value for a in r.grants()[PermissionModule.IPDR]}
            for r in SYSTEM_ROLES
            if PermissionModule.IPDR in r.grants()
        }
        assert holders == {
            "super-admin": {"read", "export"},
            "organization-owner": {"read", "export"},
            "organization-admin": {"read", "export"},
        }


class FakeAudit:
    def __init__(self, log: list[Any]) -> None:
        self.log = log

    async def create_audit_log_entry(self, **fields: Any) -> None:
        self.log.append(("audit", fields))


class FakeDb:
    def __init__(self, log: list[Any]) -> None:
        self.log = log

    async def commit(self) -> None:
        self.log.append(("commit", None))


class TestAudit:
    async def test_list_writes_a_masked_audit_row(self, tmp_path) -> None:
        repo, builder, service = _env(tmp_path)
        _seed(repo)
        log: list[Any] = []
        request = SimpleNamespace(headers={}, state=SimpleNamespace(request_id="r"))
        await ipdr_routes.list_connections(
            request,  # type: ignore[arg-type]
            query={"since": ist(2026, 10, 18), "until": NOW, "phone": "9000000022"},
            cursor=None,
            limit=10,
            organization_id=ORG_A,
            user=SimpleNamespace(id=str(uuid.UUID(int=7))),  # type: ignore[arg-type]
            service=service,
            audit=FakeAudit(log),  # type: ignore[arg-type]
        )
        ((kind, row),) = log
        assert row["action"] == AUDIT_ACTION_IPDR_LISTED
        assert row["organization_id"] == ORG_A
        assert row["actor_user_id"] == uuid.UUID(int=7)
        assert row["event_metadata"]["row_count"] == 5
        assert row["event_metadata"]["filters"]["phone"] == "90xxxxxx22"
        assert "9000000022" not in repr(row)

    async def test_export_is_audited_and_committed_before_any_byte(
        self, tmp_path, monkeypatch
    ) -> None:
        repo, builder, service = _env(tmp_path)
        _seed(repo)
        log: list[Any] = []

        class OwnSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def commit(self):
                log.append(("stream-commit", None))

        import app.database.session as db_session

        monkeypatch.setattr(db_session, "SessionLocal", OwnSession)
        monkeypatch.setattr(ipdr_routes, "ipdr_service_for", lambda s, st: service)
        monkeypatch.setattr(ipdr_routes, "RBACRepository", lambda s: FakeAudit(log))
        response = await ipdr_routes.export_csv(
            query={"since": ist(2026, 10, 17), "until": NOW},
            include_provenance=False,
            organization_id=ORG_A,
            user=SimpleNamespace(id=str(uuid.UUID(int=7))),  # type: ignore[arg-type]
            service=service,
            audit=FakeAudit(log),  # type: ignore[arg-type]
            db=FakeDb(log),  # type: ignore[arg-type]
        )
        # Before the body is iterated: the audit row exists and is committed.
        assert [k for k, _ in log] == ["audit", "commit"]
        assert log[0][1]["action"] == AUDIT_ACTION_IPDR_EXPORTED
        body = "".join([chunk async for chunk in response.body_iterator])
        rows = list(csv.reader(io.StringIO(body)))
        assert rows[0] == list(IPDR_COLUMNS)
        assert len(rows) == 1 + 16
        # Unmasked in the download.
        assert "9000000011" in body and "guest.one@example.com" in body
        assert response.headers["cache-control"] == "no-store"
        assert "attachment;" in response.headers["content-disposition"]
        done = [f for k, f in log if k == "audit"][-1]
        assert done["action"] == AUDIT_ACTION_IPDR_EXPORT_COMPLETED
        assert done["event_metadata"]["row_count"] == 16
        assert log[-1][0] == "stream-commit"


# -- migration chain, beat, nat-events gate -------------------------------------

VERSIONS = pathlib.Path("alembic/versions")


class TestMigration:
    def test_0169_chains_on_0168_and_nothing_else_claims_0168(self) -> None:
        text = (VERSIONS / "0169_create_ipdr_tables.py").read_text()
        parent = "0168_router_remote_logging_firewall_logging"
        assert f'down_revision = "{parent}"' in text
        children = [
            p.name
            for p in VERSIONS.glob("*.py")
            if f'down_revision = "{parent}"' in p.read_text()
        ]
        assert children == ["0169_create_ipdr_tables.py"]

    def test_0169_is_the_head(self) -> None:
        children = [
            p.name
            for p in VERSIONS.glob("*.py")
            if 'down_revision = "0169_create_ipdr_tables"' in p.read_text()
        ]
        assert not children

    def test_tables_are_registered(self) -> None:
        import app.domains.ipdr.models  # noqa: F401
        from app.database.base import Base

        assert {"ipdr_day_files", "ipdr_day_subjects"} <= set(Base.metadata.tables)


class TestBeat:
    def test_daily_build_is_scheduled_and_registered(self) -> None:
        from app.core.celery_app import celery_app
        from app.domains.ipdr.constants import TASK_IPDR_DAILY_BUILD

        tasks = {e["task"] for e in celery_app.conf.beat_schedule.values()}
        assert TASK_IPDR_DAILY_BUILD in tasks
        assert "app.domains.ipdr.tasks" in celery_app.conf.include

    async def test_task_is_a_no_op_when_disabled(self, monkeypatch) -> None:
        from app.domains.ipdr import tasks

        monkeypatch.setattr(
            tasks, "get_settings", lambda: SimpleNamespace(ipdr_enabled=False)
        )
        assert await tasks._run_daily_build_async() == {"enabled": False}


class TestNatEventsGate:
    def _target(self):
        from app.domains.traffic_flow.routeros import TrafficFlowTarget

        return TrafficFlowTarget("10.20.0.1", 2055, "10.20.0.40")

    def test_default_ipfix_set_is_unchanged(self) -> None:
        from app.domains.traffic_flow.routeros import desired_config

        assert desired_config(self._target()).ipfix == {
            "nat-src-address": "yes",
            "nat-src-port": "yes",
        }

    def test_gate_adds_nat_events(self) -> None:
        from app.domains.traffic_flow.routeros import desired_config, nat_events_on

        ipfix = desired_config(self._target(), nat_events=True).ipfix
        assert ipfix["nat-events"] == "yes"
        assert ipfix["nat-dst-address"] == ipfix["nat-dst-port"] == "yes"
        assert nat_events_on(SimpleNamespace()) is False
        assert nat_events_on(SimpleNamespace(traffic_flow_ipfix_nat_events=True))

    def test_setting_defaults_off(self) -> None:
        from app.core.config import Settings

        assert Settings.model_fields["traffic_flow_ipfix_nat_events"].default is False
        assert Settings.model_fields["ipdr_enabled"].default is False
