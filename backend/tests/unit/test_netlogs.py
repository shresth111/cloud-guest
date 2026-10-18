"""Customer NetLogs: classifier, customer scoping/tenant isolation, location
grants, Super-Admin-without-org refusal, route guards, summary/export,
partition planning + maintenance, RADIUS/portal server rows, RBAC seed.

The tenant-isolation tests run the service against an in-memory repository
that applies ``CustomerFilters`` exactly as the SQL does; ``TestSqlConditions``
pins the SQL itself; ``TestRealPostgres`` (opt-in, ``NETLOGS_TEST_PG_DSN``)
runs the real queries against a Postgres with the 0167 schema."""

from __future__ import annotations

import os
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest

from app.domains.device_logs import customer_router as cr
from app.domains.device_logs.classifier import classify, summary_for
from app.domains.device_logs.constants import (
    CUSTOMER_MAX_QUERY_WINDOW_DAYS,
    DEFAULT_PARTITION,
    Attribution,
)
from app.domains.device_logs.customer_scope import (
    LogsConfinement,
    confinement_from_grants,
)
from app.domains.device_logs.customer_service import NetLogsCustomerService
from app.domains.device_logs.exceptions import (
    DeviceLogsDisabledError,
    NetLogsBadFilterError,
    NetLogsLocationForbiddenError,
    NetLogsLocationNotFoundError,
    NetLogsRouterNotFoundError,
)
from app.domains.device_logs.partitions import (
    add_months,
    maintain_partitions,
    month_of,
    partition_name,
    plan_partitions,
)
from app.domains.device_logs.repository import CustomerFilters, customer_conditions
from app.domains.device_logs.server_events import (
    PortalLoginEventRecorder,
    RadiusEventRecorder,
    normalize_mac,
    portal_failure_row,
    radius_row,
)
from app.domains.device_logs.service import encode_cursor
from app.domains.rbac.enums import ScopeType

NOW = datetime(2026, 10, 18, 6, 0, 0, tzinfo=UTC)

ORG_A, ORG_B = uuid.uuid4(), uuid.uuid4()
LOC_A1, LOC_A2, LOC_B1 = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
RTR_A1, RTR_A2, RTR_B1 = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
LOCATIONS = {LOC_A1: ORG_A, LOC_A2: ORG_A, LOC_B1: ORG_B}
ROUTERS = {RTR_A1: (ORG_A, LOC_A1), RTR_A2: (ORG_A, LOC_A2), RTR_B1: (ORG_B, LOC_B1)}


# -- classifier ---------------------------------------------------------------


class TestClassifier:
    @pytest.mark.parametrize(
        ("message", "topics", "expected"),
        [
            (
                "dhcp-guest assigned 10.5.50.12 for 3C:22:FB:11:22:33 Rahuls-iPhone",
                None,
                ("dhcp", "DHCP", None, "10.5.50.12", "success", "3C:22:FB:11:22:33"),
            ),
            (
                "dhcp1 deassigned 10.5.50.12 for 3c:22:fb:11:22:33",
                None,
                ("dhcp", "DHCP", None, "10.5.50.12", "released", "3C:22:FB:11:22:33"),
            ),
            (
                "98XXXXXX10 (10.5.50.12): logged in",
                None,
                ("hotspot_auth", "HOTSPOT", "10.5.50.12", None, "success", None),
            ),
            (
                "98XXXXXX10 (10.5.50.12): logged out: keepalive timeout",
                None,
                ("hotspot_auth", "HOTSPOT", "10.5.50.12", None, "disconnected", None),
            ),
            (
                "98XXXXXX10 (10.5.50.12): login failed: invalid username or password",
                None,
                ("hotspot_auth", "HOTSPOT", "10.5.50.12", None, "failure", None),
            ),
            (
                "DROP-GUEST forward: in:bridge out:ether1, connection-state:new "
                "src-mac 3c:22:fb:11:22:33, proto TCP (SYN), "
                "10.5.50.12:51544->142.250.183.4:443, len 60",
                None,
                (
                    "firewall",
                    "TCP",
                    "10.5.50.12",
                    "142.250.183.4",
                    "blocked",
                    "3C:22:FB:11:22:33",
                ),
            ),
            (
                "forward: in:bridge out:ether1, proto UDP, "
                "10.5.50.12:5353->8.8.8.8:53, NAT (10.5.50.12:5353->"
                "103.1.2.3:5353)->8.8.8.8:53, len 70",
                "firewall,info",
                ("firewall", "UDP", "10.5.50.12", "8.8.8.8", None, None),
            ),
            (
                "accept-mgmt input: in:wg0 out:(unknown 0), proto ICMP "
                "(type 8, code 0), 10.20.0.1->10.20.0.31, len 84",
                None,
                ("firewall", "ICMP", "10.20.0.1", "10.20.0.31", "allowed", None),
            ),
            (
                "3C:22:FB:11:22:33@wifi1 connected, signal strength -55",
                None,
                ("wireless", "WLAN", None, None, "connected", "3C:22:FB:11:22:33"),
            ),
            (
                "3C:22:FB:11:22:33@wlan1: disconnected, received deauth: "
                "sending station leaving (3)",
                "wireless,info",
                ("wireless", "WLAN", None, None, "disconnected", "3C:22:FB:11:22:33"),
            ),
            (
                "user admin logged in from 1.2.3.4 via winbox",
                "system,info,account",
                ("system", "WINBOX", "1.2.3.4", None, "success", None),
            ),
            (
                "login failure for user admin from 1.2.3.4 via ssh",
                "system,error,critical",
                ("system", "SSH", "1.2.3.4", None, "failure", None),
            ),
            (
                "router rebooted",
                "system,info",
                ("system", None, None, None, None, None),
            ),
            (
                "fetch: file \"x\" downloaded",
                None,
                ("other", None, None, None, None, None),
            ),
        ],
    )
    def test_shapes(self, message, topics, expected) -> None:
        c = classify(message, topics=topics)
        assert (
            c.category,
            c.protocol,
            c.src_ip,
            c.dst_ip,
            c.status,
            c.device_mac,
        ) == expected

    def test_tag_prefix_left_in_old_messages_is_skipped(self) -> None:
        c = classify("Office wyfy-8a199617: dhcp1 assigned 10.0.0.9 for AA:BB:CC:DD:EE:FF")
        assert c.category == "dhcp" and c.dst_ip == "10.0.0.9"

    def test_a_topic_list_naming_something_else_never_becomes_dhcp(self) -> None:
        c = classify(
            "dhcp1 assigned 10.0.0.9 for AA:BB:CC:DD:EE:FF", topics="system,info"
        )
        assert c.category == "system" and c.status is None

    def test_firewall_status_is_never_guessed(self) -> None:
        c = classify(
            "forward: in:a out:b, proto TCP (ACK), 1.1.1.1:1->2.2.2.2:2, len 40"
        )
        assert c.category == "firewall" and c.status is None

    def test_garbage_never_raises(self) -> None:
        for junk in ("", " ", "@@@", "proto TCP, ->", "x" * 5000):
            assert classify(junk).category == "other"

    def test_summary_headlines(self) -> None:
        assert summary_for("firewall", "blocked") == "Traffic denied"
        assert summary_for("dhcp", "success") == "IP assigned"
        assert summary_for("radius", "reject") == "RADIUS rejected"
        assert summary_for("other", None) is None


class TestIngestFillsColumns:
    async def test_ingest_rows_carry_classification(self) -> None:
        from app.domains.device_logs.repository import PeerOwner
        from app.domains.device_logs.schemas import IngestEvent
        from app.domains.device_logs.service import DeviceLogsService

        captured: list[dict[str, Any]] = []

        class Repo:
            async def owners_by_tunnel_ip(self, ips):
                return {"10.20.0.31": [PeerOwner(RTR_A1, ORG_A, LOC_A1)]}

            async def insert_events(self, rows):
                captured.extend(rows)
                return list(range(1, len(rows) + 1))

            async def insert_guest_events(self, rows):
                return len(rows)

        service = DeviceLogsService(
            Repo(),  # type: ignore[arg-type]
            SimpleNamespace(device_logs_enabled=True),  # type: ignore[arg-type]
        )
        await service.ingest(
            [
                IngestEvent(
                    received_at=NOW,
                    source_ip="10.20.0.31",
                    raw="<174>Oct 18 11:29:58 r forward: in:a out:b, proto TCP "
                    "(SYN), 10.5.50.2:1->1.1.1.1:443, len 60",
                )
            ]
        )
        row = captured[0]
        assert row["category"] == "firewall"
        assert (row["protocol"], row["src_ip"], row["dst_ip"]) == (
            "TCP",
            "10.5.50.2",
            "1.1.1.1",
        )
        # source_ip stays the router's tunnel address, never the traffic's.
        assert row["source_ip"] == "10.20.0.31"


# -- in-memory customer repository ---------------------------------------------


@dataclass
class Row:
    id: int
    received_at: datetime
    organization_id: uuid.UUID | None
    location_id: uuid.UUID | None
    router_id: uuid.UUID | None
    message: str = "line"
    category: str | None = "other"
    protocol: str | None = None
    status: str | None = None
    severity: int | None = 6
    src_ip: str | None = None
    dst_ip: str | None = None
    device_mac: str | None = None
    hostname: str | None = "r"
    device_time: datetime | None = None
    source: str = "syslog"
    source_ip: str = "10.20.0.31"
    claimed_tag: str | None = "8a199617"
    attribution: str = "tunnel_ip"


def _matches(r: Row, f: CustomerFilters) -> bool:
    """Mirror of ``customer_conditions``."""
    if r.organization_id is None or r.organization_id != f.organization_id:
        return False
    if not (f.since <= r.received_at <= f.until):
        return False
    if f.allowed_location_ids is not None and r.location_id not in (
        f.allowed_location_ids
    ):
        return False
    if f.location_id is not None and r.location_id != f.location_id:
        return False
    if f.router_id is not None and r.router_id != f.router_id:
        return False
    if f.severities and r.severity not in f.severities:
        return False
    if f.max_severity is not None and (r.severity is None or r.severity > f.max_severity):
        return False
    if f.categories:
        cat = r.category or "other"
        if cat not in f.categories:
            return False
    if f.protocols and r.protocol not in f.protocols:
        return False
    if f.statuses and r.status not in f.statuses:
        return False
    if f.text and f.text.lower() not in r.message.lower():
        return False
    if f.cursor is not None:
        at, rid = f.cursor
        if not (r.received_at < at or (r.received_at == at and r.id < rid)):
            return False
    return True


@dataclass
class FakeCustomerRepo:
    rows: list[Row] = field(default_factory=list)
    seen_filters: list[CustomerFilters] = field(default_factory=list)

    def _select(self, f: CustomerFilters) -> list[Row]:
        self.seen_filters.append(f)
        out = [r for r in self.rows if _matches(r, f)]
        return sorted(out, key=lambda r: (r.received_at, r.id), reverse=True)

    async def list_events(self, f, *, limit):
        return [
            {"event": r, "router_name": f"router-{r.router_id}", "location_name": "L"}
            for r in self._select(f)[:limit]
        ]

    async def summary_buckets(self, f, *, tz):
        counts: dict[tuple, int] = {}
        for r in self._select(f):
            key = (r.received_at.date(), r.category or "other", r.severity)
            counts[key] = counts.get(key, 0) + 1
        return [(*k, v) for k, v in counts.items()]

    async def top_routers(self, f, *, limit):
        agg: dict[uuid.UUID, list[int]] = {}
        for r in self._select(f):
            if r.router_id is None:
                continue
            a = agg.setdefault(r.router_id, [0, 0, 0])
            a[0] += 1
            a[1] += int(r.severity is not None and r.severity <= 3)
            a[2] += int(r.severity == 4)
        ranked = sorted(agg.items(), key=lambda kv: -kv[1][0])[:limit]
        return [
            (rid, "n", ROUTERS[rid][1], "L", t, e, w) for rid, (t, e, w) in ranked
        ]

    async def router_owner(self, router_id):
        return ROUTERS.get(router_id)

    async def location_organization(self, location_id):
        return LOCATIONS.get(location_id)

    async def organization_location_ids(self, organization_id):
        return [loc for loc, org in LOCATIONS.items() if org == organization_id]


def _seed() -> FakeCustomerRepo:
    rows: list[Row] = []
    n = 0
    for org, loc, rtr in (
        (ORG_A, LOC_A1, RTR_A1),
        (ORG_A, LOC_A2, RTR_A2),
        (ORG_B, LOC_B1, RTR_B1),
    ):
        for i in range(5):
            n += 1
            rows.append(
                Row(
                    id=n,
                    received_at=NOW - timedelta(hours=i + 1),
                    organization_id=org,
                    location_id=loc,
                    router_id=rtr,
                    message=f"msg {org} {i}",
                    severity=3 if i == 0 else 6,
                    category="firewall" if i % 2 else None,
                )
            )
    # Unattributed line (no org) -- must never show to any customer.
    rows.append(
        Row(
            id=999,
            received_at=NOW - timedelta(minutes=5),
            organization_id=None,
            location_id=None,
            router_id=None,
            attribution="unattributed",
        )
    )
    return FakeCustomerRepo(rows=rows)


def _service(repo=None, *, enabled=True) -> NetLogsCustomerService:
    return NetLogsCustomerService(
        repo or _seed(),  # type: ignore[arg-type]
        SimpleNamespace(device_logs_enabled=enabled),  # type: ignore[arg-type]
        clock=lambda: NOW,
    )


WHOLE_ORG = LogsConfinement(allowed=None)


async def _list(service, *, org=ORG_A, confinement=WHOLE_ORG, limit=None, **kw):
    f = await service.build_filters(organization_id=org, confinement=confinement, **kw)
    return await service.list_events(f, limit=limit)


# -- tenant isolation ---------------------------------------------------------


class TestTenantIsolation:
    async def test_list_only_returns_own_org_and_never_unattributed(self) -> None:
        page = await _list(_service())
        assert len(page["items"]) == 10
        assert {i["router_id"] for i in page["items"]} == {str(RTR_A1), str(RTR_A2)}
        assert all(i["id"] != 999 for i in page["items"])

    async def test_view_hides_tunnel_internals(self) -> None:
        item = (await _list(_service()))["items"][0]
        for hidden in ("source_ip", "claimed_tag", "attribution", "organization_id"):
            assert hidden not in item

    async def test_null_category_reads_other(self) -> None:
        items = (await _list(_service()))["items"]
        assert {i["category"] for i in items} == {"other", "firewall"}

    @pytest.mark.parametrize("foreign", [RTR_B1, uuid.uuid4()])
    async def test_router_of_another_org_or_unknown_is_404(self, foreign) -> None:
        with pytest.raises(NetLogsRouterNotFoundError) as err:
            await _list(_service(), router_id=foreign)
        assert err.value.status_code == 404

    @pytest.mark.parametrize("foreign", [LOC_B1, uuid.uuid4()])
    async def test_location_of_another_org_or_unknown_is_404(self, foreign) -> None:
        with pytest.raises(NetLogsLocationNotFoundError) as err:
            await _list(_service(), location_id=foreign)
        assert err.value.status_code == 404

    async def test_own_router_filter(self) -> None:
        items = (await _list(_service(), router_id=RTR_A2))["items"]
        assert len(items) == 5 and {i["router_id"] for i in items} == {str(RTR_A2)}

    async def test_summary_never_blends_orgs(self) -> None:
        service = _service()
        f = await service.build_filters(organization_id=ORG_B, confinement=WHOLE_ORG)
        s = await service.summary(f)
        assert s["totals"] == {"events": 5, "errors": 1, "warnings": 0}
        assert [r["router_id"] for r in s["top_routers"]] == [str(RTR_B1)]
        assert sum(d["total"] for d in s["by_day"]) == 5
        assert s["by_category"]["firewall"] == 2 and s["by_category"]["other"] == 3

    async def test_export_never_blends_orgs(self) -> None:
        repo = _seed()
        service = _service(repo)
        f = await service.build_filters(organization_id=ORG_B, confinement=WHOLE_ORG)

        @asynccontextmanager
        async def opener():
            yield repo

        lines = [line async for line in service.export_csv(f, opener, chunk=2)]
        assert lines[0].startswith("received_at,device_time,location,router")
        assert len(lines) == 6  # header + 5
        body = "".join(lines[1:])
        assert str(ORG_B) in body and str(ORG_A) not in body
        assert all(s.organization_id == ORG_B for s in repo.seen_filters)

    async def test_export_says_when_it_was_truncated(self) -> None:
        repo = _seed()
        service = _service(repo)
        f = await service.build_filters(organization_id=ORG_A, confinement=WHOLE_ORG)

        @asynccontextmanager
        async def opener():
            yield repo

        lines = [x async for x in service.export_csv(f, opener, max_rows=4, chunk=3)]
        assert len(lines) == 1 + 4 + 1
        assert lines[-1].startswith("# truncated at 4 rows")

    async def test_export_neutralises_formula_cells(self) -> None:
        repo = FakeCustomerRepo(
            rows=[
                Row(
                    id=1,
                    received_at=NOW - timedelta(minutes=1),
                    organization_id=ORG_A,
                    location_id=LOC_A1,
                    router_id=RTR_A1,
                    message="=HYPERLINK(\"http://x\")",
                )
            ]
        )
        service = _service(repo)
        f = await service.build_filters(organization_id=ORG_A, confinement=WHOLE_ORG)

        @asynccontextmanager
        async def opener():
            yield repo

        lines = [x async for x in service.export_csv(f, opener)]
        assert "'=HYPERLINK" in lines[1]

    async def test_export_refused_while_feature_off(self) -> None:
        with pytest.raises(DeviceLogsDisabledError):
            _service(enabled=False).require_enabled()


# -- location grants ----------------------------------------------------------


def _grant(key, scope_type, *, org=None, loc=None):
    return SimpleNamespace(
        permission_key=key,
        scope=SimpleNamespace(
            scope_type=scope_type.value, organization_id=org, location_id=loc
        ),
    )


def _grants(allow=(), deny=()):
    return SimpleNamespace(allow=tuple(allow), deny=tuple(deny))


class TestLocationGrants:
    def test_org_grant_is_unconfined(self) -> None:
        c = confinement_from_grants(
            _grants([_grant("network_logs.read", ScopeType.ORGANIZATION, org=ORG_A)]),
            organization_id=ORG_A,
        )
        assert c.allowed is None

    def test_org_grant_for_another_org_does_not_count(self) -> None:
        c = confinement_from_grants(
            _grants([_grant("network_logs.read", ScopeType.ORGANIZATION, org=ORG_B)]),
            organization_id=ORG_A,
        )
        assert c.allowed == frozenset()

    def test_only_locations_holding_this_key_count(self) -> None:
        # Network Admin at A1 (has the key) + Reception at A2 (does not):
        # A2 must not be readable.
        c = confinement_from_grants(
            _grants(
                [
                    _grant("network_logs.read", ScopeType.LOCATION, loc=LOC_A1),
                    _grant("guest_sessions.read", ScopeType.LOCATION, loc=LOC_A2),
                ]
            ),
            organization_id=ORG_A,
        )
        assert c.allowed == frozenset({LOC_A1})

    def test_deny_at_org_wins(self) -> None:
        c = confinement_from_grants(
            _grants(
                allow=[_grant("network_logs.read", ScopeType.GLOBAL)],
                deny=[_grant("network_logs.read", ScopeType.ORGANIZATION, org=ORG_A)],
            ),
            organization_id=ORG_A,
        )
        assert c.nothing is True

    async def test_location_confined_user_sees_only_their_sites(self) -> None:
        page = await _list(
            _service(), confinement=LogsConfinement(allowed=frozenset({LOC_A1}))
        )
        assert {i["location_id"] for i in page["items"]} == {str(LOC_A1)}

    async def test_naming_a_site_outside_the_grant_is_403(self) -> None:
        with pytest.raises(NetLogsLocationForbiddenError) as err:
            await _list(
                _service(),
                confinement=LogsConfinement(allowed=frozenset({LOC_A1})),
                location_id=LOC_A2,
            )
        assert err.value.status_code == 403

    async def test_naming_a_router_outside_the_grant_is_403(self) -> None:
        with pytest.raises(NetLogsLocationForbiddenError):
            await _list(
                _service(),
                confinement=LogsConfinement(allowed=frozenset({LOC_A1})),
                router_id=RTR_A2,
            )

    async def test_org_wide_with_a_location_deny_excludes_it(self) -> None:
        page = await _list(
            _service(),
            confinement=LogsConfinement(allowed=None, denied=frozenset({LOC_A2})),
        )
        assert {i["location_id"] for i in page["items"]} == {str(LOC_A1)}

    async def test_nothing_means_nothing(self) -> None:
        page = await _list(
            _service(), confinement=LogsConfinement(allowed=frozenset(), nothing=True)
        )
        assert page["items"] == []

    async def test_summary_is_confined_too(self) -> None:
        service = _service()
        f = await service.build_filters(
            organization_id=ORG_A,
            confinement=LogsConfinement(allowed=frozenset({LOC_A2})),
        )
        s = await service.summary(f)
        assert s["totals"]["events"] == 5
        assert [r["router_id"] for r in s["top_routers"]] == [str(RTR_A2)]


# -- filters, window, pagination ---------------------------------------------


class TestFilters:
    async def test_window_is_clamped_to_730_days(self) -> None:
        service = _service()
        f = await service.build_filters(
            organization_id=ORG_A,
            confinement=WHOLE_ORG,
            since=NOW - timedelta(days=2000),
            until=NOW,
        )
        assert f.until - f.since == timedelta(days=CUSTOMER_MAX_QUERY_WINDOW_DAYS)

    async def test_a_year_old_range_is_allowed(self) -> None:
        service = _service()
        since = NOW - timedelta(days=400)
        f = await service.build_filters(
            organization_id=ORG_A, confinement=WHOLE_ORG, since=since, until=NOW
        )
        assert f.since == since

    @pytest.mark.parametrize(
        ("field_name", "value"),
        [("category", "dnsx"), ("status", "ok"), ("severity", "loud")],
    )
    async def test_unknown_enum_values_are_422(self, field_name, value) -> None:
        with pytest.raises(NetLogsBadFilterError) as err:
            await _list(_service(), **{field_name: [value]})
        assert err.value.status_code == 422

    async def test_list_values_accept_commas_and_repeats(self) -> None:
        service = _service()
        f = await service.build_filters(
            organization_id=ORG_A,
            confinement=WHOLE_ORG,
            category=["dhcp,firewall", "radius"],
            severity=["error", "warning"],
            protocol=["tcp"],
            status=["blocked"],
        )
        assert f.categories == ("dhcp", "firewall", "radius")
        assert f.severities == (3, 4)
        assert f.protocols == ("TCP",)

    async def test_keyset_pagination_walks_every_row_once(self) -> None:
        service = _service()
        seen: list[int] = []
        cursor = None
        while True:
            page = await _list(service, limit=3, cursor=cursor)
            seen += [i["id"] for i in page["items"]]
            cursor = page["next_cursor"]
            if cursor is None:
                break
        assert len(seen) == len(set(seen)) == 10

    async def test_feature_off_is_said_not_shown_as_empty(self) -> None:
        page = await _list(_service(enabled=False))
        assert page["feature_enabled"] is False and page["items"] == []

    async def test_cursor_round_trip(self) -> None:
        f = await _service().build_filters(
            organization_id=ORG_A,
            confinement=WHOLE_ORG,
            cursor=encode_cursor(NOW, 7),
        )
        assert f.cursor == (NOW, 7)

    async def test_bad_timezone_is_422(self) -> None:
        service = _service()
        f = await service.build_filters(organization_id=ORG_A, confinement=WHOLE_ORG)
        with pytest.raises(NetLogsBadFilterError):
            await service.summary(f, tz="Mars/Olympus")


class TestSqlConditions:
    def _sql(self, f: CustomerFilters) -> str:
        from sqlalchemy import and_
        from sqlalchemy.dialects import postgresql

        return str(
            and_(*customer_conditions(f)).compile(
                dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}
            )
        )

    def test_org_is_always_a_predicate(self) -> None:
        sql = self._sql(CustomerFilters(organization_id=ORG_A, since=NOW, until=NOW))
        assert f"device_log_events.organization_id = '{ORG_A}'" in sql
        assert "device_log_events.organization_id IS NOT NULL" in sql

    def test_confinement_is_an_in_list_and_empty_matches_nothing(self) -> None:
        sql = self._sql(
            CustomerFilters(
                organization_id=ORG_A,
                since=NOW,
                until=NOW,
                allowed_location_ids=(LOC_A1,),
            )
        )
        assert f"device_log_events.location_id IN ('{LOC_A1}')" in sql
        empty = self._sql(
            CustomerFilters(
                organization_id=ORG_A, since=NOW, until=NOW, allowed_location_ids=()
            )
        )
        assert "location_id IN" in empty  # IN (empty set) -> false

    def test_other_category_includes_unclassified_rows(self) -> None:
        sql = self._sql(
            CustomerFilters(
                organization_id=ORG_A, since=NOW, until=NOW, categories=("other",)
            )
        )
        assert "device_log_events.category IS NULL" in sql


# -- guards / Super Admin -----------------------------------------------------


def _closure(call) -> set[str]:
    return {str(cell.cell_contents) for cell in (call.__closure__ or ())}


class TestRouteGuards:
    def test_every_customer_route_pins_network_logs_read_at_location(self) -> None:
        from app.domains.rbac.dependencies import RequireOrganization

        routes = cr.netlogs_customer_router.routes
        assert {r.path for r in routes} == {
            "/device-logs",
            "/device-logs/summary",
            "/device-logs/export.csv",
        }
        for route in routes:
            deps = [d.dependency for d in route.dependencies]
            assert deps[0] is RequireOrganization, route.path
            closure = _closure(deps[1])
            assert "network_logs.read" in closure, route.path
            # Explicit scope -- never inferred from the caller's headers.
            assert ScopeType.LOCATION.value in closure, route.path
            assert "device_logs.read" not in closure

    def test_no_route_accepts_an_organization_parameter(self) -> None:
        for route in cr.netlogs_customer_router.routes:
            names = {p.name for p in route.dependant.query_params}
            names |= {p.name for p in route.dependant.path_params}
            assert "organization_id" not in names, route.path
            assert "organization_scope" not in names, route.path

    async def test_global_admin_asking_for_all_orgs_is_refused(self) -> None:
        from app.domains.rbac.dependencies import RequireOrganization
        from app.domains.rbac.organization_scope import OrganizationScope

        with pytest.raises(Exception) as err:
            await RequireOrganization(scope=OrganizationScope.all())
        assert getattr(err.value, "status_code", None) == 400

    async def test_global_admin_naming_no_org_is_refused(self, monkeypatch) -> None:
        """CurrentOrganizationScope (behind RequireOrganization) raises for a
        GLOBAL-role caller whose request names no organization."""
        from app.domains.rbac import dependencies as rbac_deps

        class Resolver:
            def __init__(self, repo):
                pass

            async def get_active_assignments(self, user_id):
                return [SimpleNamespace(role=SimpleNamespace(scope_type="global"))]

        monkeypatch.setattr(rbac_deps, "RoleResolver", Resolver)
        request = SimpleNamespace(
            headers={}, query_params={}, scope={}, path_params={}
        )
        monkeypatch.setattr(rbac_deps, "_requested_organization_id", lambda r: None)
        with pytest.raises(Exception) as err:
            await rbac_deps.CurrentOrganizationScope(
                request=request,  # type: ignore[arg-type]
                user=SimpleNamespace(id=str(uuid.uuid4())),  # type: ignore[arg-type]
                db=None,  # type: ignore[arg-type]
                repository=None,  # type: ignore[arg-type]
            )
        assert type(err.value).__name__ == "UnspecifiedOrganizationScopeError"
        assert err.value.status_code == 400

    def test_routes_are_mounted(self) -> None:
        from app.api.v1.router import api_v1_router

        paths = {getattr(r, "path", "") for r in api_v1_router.routes}
        assert {"/device-logs", "/device-logs/summary", "/device-logs/export.csv"} <= (
            paths
        )


class TestRbacSeed:
    def test_network_logs_is_location_scoped_read_only(self) -> None:
        from app.domains.rbac.enums import PermissionModule
        from app.domains.rbac.seed import MODULE_ACTIONS, MODULE_NARROWEST_SCOPE

        assert [a.value for a in MODULE_ACTIONS[PermissionModule.NETWORK_LOGS]] == [
            "read"
        ]
        assert MODULE_NARROWEST_SCOPE[PermissionModule.NETWORK_LOGS] == (
            ScopeType.LOCATION
        )
        assert MODULE_NARROWEST_SCOPE[PermissionModule.DEVICE_LOGS] == ScopeType.GLOBAL

    def test_who_holds_it(self) -> None:
        from app.domains.rbac.enums import PermissionModule
        from app.domains.rbac.seed import SYSTEM_ROLES

        holders = {
            r.slug for r in SYSTEM_ROLES if PermissionModule.NETWORK_LOGS in r.grants()
        }
        assert {
            "organization-owner",
            "organization-admin",
            "network-administrator",
            "location-manager",
        } <= holders
        assert not {"reception-staff", "guest-operator", "helpdesk"} & holders
        # The Master key stays Master-only.
        for r in SYSTEM_ROLES:
            if PermissionModule.DEVICE_LOGS in r.grants():
                assert r.scope_type == ScopeType.GLOBAL, r.slug


# -- partitions ---------------------------------------------------------------


class TestPartitionPlan:
    def test_names_round_trip(self) -> None:
        assert partition_name(date(2026, 1, 1)) == "device_log_events_p202601"
        assert month_of("device_log_events_p202612") == date(2026, 12, 1)
        assert month_of("device_log_events_p202613") is None
        assert month_of("something_else") is None
        assert add_months(date(2026, 11, 1), 3) == date(2027, 2, 1)
        assert add_months(date(2026, 1, 1), -24) == date(2024, 1, 1)

    def test_creates_ahead_and_drops_past_retention(self) -> None:
        existing = [
            partition_name(date(2024, 9, 1)),
            partition_name(date(2024, 10, 1)),
            partition_name(date(2026, 10, 1)),
            DEFAULT_PARTITION,
            "device_log_events_manual_copy",
        ]
        plan = plan_partitions(existing, now=NOW, retention_months=24, ahead=3)
        assert plan.create == (
            date(2026, 11, 1),
            date(2026, 12, 1),
            date(2027, 1, 1),
        )
        # Cutoff 2024-10-01: September 2024 ends on it -> dropped; October
        # 2024 is still inside the 24 months -> kept.
        assert plan.cutoff == date(2024, 10, 1)
        assert plan.drop == (date(2024, 9, 1),)
        assert plan.unknown == ("device_log_events_manual_copy",)

    def test_retention_is_configurable(self) -> None:
        existing = [partition_name(date(2026, m, 1)) for m in range(1, 11)]
        plan = plan_partitions(existing, now=NOW, retention_months=6, ahead=0)
        assert plan.cutoff == date(2026, 4, 1)
        assert plan.drop == tuple(date(2026, m, 1) for m in range(1, 4))
        assert plan.create == ()

    def test_zero_retention_is_refused(self) -> None:
        with pytest.raises(ValueError):
            plan_partitions([], now=NOW, retention_months=0, ahead=1)


class FakeSession:
    """Records SQL; answers the few SELECTs maintenance issues."""

    def __init__(self, *, existing, default_rows=0, locked=False):
        self.existing = existing
        self.default_rows = default_rows
        self.locked = locked
        self.sql: list[str] = []

    async def execute(self, statement, params=None):
        text = str(statement)
        self.sql.append(text)
        if "pg_try_advisory_xact_lock" in text:
            return SimpleNamespace(scalar_one=lambda: not self.locked)
        if "pg_inherits" in text:
            return SimpleNamespace(all=lambda: [(n,) for n in self.existing])
        if "to_regclass" in text:
            return SimpleNamespace(scalar_one=lambda: True)
        if text.startswith("SELECT count(*)"):
            return SimpleNamespace(scalar_one=lambda: self.default_rows)
        return SimpleNamespace(rowcount=0)


class TestPartitionMaintenance:
    async def test_derived_rows_are_deleted_before_the_partition_is_dropped(
        self,
    ) -> None:
        session = FakeSession(
            existing=[partition_name(date(2024, 9, 1)), DEFAULT_PARTITION]
            + [partition_name(add_months(date(2026, 10, 1), i)) for i in range(4)]
        )
        summary = await maintain_partitions(
            session,  # type: ignore[arg-type]
            now=NOW,
            retention_months=24,
            ahead=3,
        )
        assert summary["dropped"] == ["device_log_events_p202409"]
        assert summary["created"] == []
        delete_at = next(
            i for i, s in enumerate(session.sql) if "DELETE FROM guest_device_events" in s
        )
        drop_at = next(i for i, s in enumerate(session.sql) if "DROP TABLE" in s)
        assert delete_at < drop_at
        assert "device_log_events_p202409" in session.sql[drop_at]
        assert any("lock_timeout" in s for s in session.sql)

    async def test_create_uses_partition_of_when_default_is_clean(self) -> None:
        session = FakeSession(existing=[DEFAULT_PARTITION])
        summary = await maintain_partitions(
            session,  # type: ignore[arg-type]
            now=NOW,
            retention_months=24,
            ahead=1,
        )
        assert summary["created"] == [
            "device_log_events_p202610",
            "device_log_events_p202611",
        ]
        creates = [s for s in session.sql if "PARTITION OF device_log_events" in s]
        assert len(creates) == 2
        assert "FROM ('2026-10-01 00:00:00+00') TO ('2026-11-01 00:00:00+00')" in (
            creates[0]
        )

    async def test_rows_stuck_in_default_are_moved_then_attached(self) -> None:
        session = FakeSession(existing=[DEFAULT_PARTITION], default_rows=3)
        summary = await maintain_partitions(
            session,  # type: ignore[arg-type]
            now=NOW,
            retention_months=24,
            ahead=0,
        )
        assert summary["moved_from_default"] == 3
        joined = "\n".join(session.sql)
        assert "INCLUDING DEFAULTS" in joined
        assert "ATTACH PARTITION device_log_events_p202610" in joined

    async def test_a_concurrent_run_is_skipped(self) -> None:
        session = FakeSession(existing=[], locked=True)
        summary = await maintain_partitions(
            session,  # type: ignore[arg-type]
            now=NOW,
            retention_months=24,
            ahead=3,
        )
        assert summary == {"locked": True}
        assert len(session.sql) == 1

    def test_task_is_scheduled_and_registered(self) -> None:
        from app.core.celery_app import celery_app
        from app.domains.device_logs.constants import (
            TASK_DEVICE_LOGS_PARTITION_MAINTENANCE,
        )

        tasks = {e["task"] for e in celery_app.conf.beat_schedule.values()}
        assert TASK_DEVICE_LOGS_PARTITION_MAINTENANCE in tasks
        assert "app.domains.device_logs.tasks" in celery_app.conf.include

    async def test_task_uses_configured_retention(self, monkeypatch) -> None:
        from app.domains.device_logs import tasks

        seen: dict[str, Any] = {}

        async def fake_maintain(session, **kw):
            seen.update(kw)
            return {"locked": False}

        class S:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def commit(self):
                seen["committed"] = True

            async def rollback(self):
                pass

        monkeypatch.setattr(tasks, "maintain_partitions", fake_maintain)
        monkeypatch.setattr(tasks, "SessionLocal", S)
        monkeypatch.setattr(
            tasks,
            "get_settings",
            lambda: SimpleNamespace(
                device_logs_retention_months=12, device_logs_partitions_ahead=2
            ),
        )
        await tasks._run_partition_maintenance_async()
        assert seen == {"retention_months": 12, "ahead": 2, "committed": True}


# -- server-written rows ------------------------------------------------------


class _Router(SimpleNamespace):
    pass


ROUTER = _Router(id=RTR_A1, organization_id=ORG_A, location_id=LOC_A1)


class _NestedOk:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class RecordingSession:
    def __init__(self, fail=False):
        self.fail = fail
        self.inserted: list[Any] = []
        self.committed = False

    def begin_nested(self):
        if self.fail:
            raise RuntimeError("no partition for this month")
        return _NestedOk()

    async def execute(self, stmt, params=None):
        self.inserted.append(stmt.compile().params)
        return SimpleNamespace()

    async def commit(self):
        self.committed = True

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


ON = SimpleNamespace(device_logs_enabled=True)
OFF = SimpleNamespace(device_logs_enabled=False)


class TestServerEvents:
    def test_radius_reject_row(self) -> None:
        row = radius_row(
            now=NOW,
            router=ROUTER,
            nas_identifier="nas-1",
            nas_ip="10.20.0.31",
            accepted=False,
            reason="Guest is blocked",
            calling_station_id="3c-22-fb-11-22-33",
        )
        assert (row["organization_id"], row["location_id"], row["router_id"]) == (
            ORG_A,
            LOC_A1,
            RTR_A1,
        )
        assert (row["category"], row["protocol"], row["status"]) == (
            "radius",
            "RADIUS",
            "reject",
        )
        assert row["message"] == "Access-Reject: Guest is blocked"
        assert row["device_mac"] == "3C:22:FB:11:22:33"
        assert row["attribution"] == Attribution.SERVER.value

    def test_mac_normalisation(self) -> None:
        assert normalize_mac("3c22fb112233") == "3C:22:FB:11:22:33"
        assert normalize_mac("not-a-mac") is None
        assert normalize_mac(None) is None

    async def test_radius_recorder_writes_in_a_savepoint(self) -> None:
        session = RecordingSession()
        await RadiusEventRecorder(session, ON, clock=lambda: NOW).record_decision(  # type: ignore[arg-type]
            router=ROUTER,
            nas_identifier="nas-1",
            nas_ip=None,
            accepted=True,
            reason=None,
            calling_station_id=None,
        )
        assert len(session.inserted) == 1
        assert session.inserted[0]["status"] == "accept"

    async def test_radius_recorder_swallows_failures(self) -> None:
        session = RecordingSession(fail=True)
        await RadiusEventRecorder(session, ON).record_decision(  # type: ignore[arg-type]
            router=ROUTER,
            nas_identifier="nas-1",
            nas_ip=None,
            accepted=False,
            reason="x",
            calling_station_id=None,
        )
        assert session.inserted == []

    async def test_radius_recorder_is_off_with_the_flag(self) -> None:
        session = RecordingSession()
        await RadiusEventRecorder(session, OFF).record_decision(  # type: ignore[arg-type]
            router=ROUTER,
            nas_identifier=None,
            nas_ip=None,
            accepted=True,
            reason=None,
            calling_station_id=None,
        )
        assert session.inserted == []

    def test_portal_row_carries_no_identifier(self) -> None:
        row = portal_failure_row(
            now=NOW,
            organization_id=ORG_A,
            location_id=LOC_A1,
            auth_method="otp_sms",
            reason="OtpCodeMismatchError",
            ip_address="10.5.50.12",
        )
        assert row["message"] == "otp_sms sign-in failed: Invalid OTP"
        assert row["status"] == "failure" and row["category"] == "hotspot_auth"
        assert row["src_ip"] == "10.5.50.12"
        assert "identifier" not in row

    async def test_portal_recorder_commits_its_own_session(self) -> None:
        session = RecordingSession()
        await PortalLoginEventRecorder(
            ON,  # type: ignore[arg-type]
            session_factory=lambda: session,
            clock=lambda: NOW,
        ).record_login_failure(
            organization_id=ORG_A,
            location_id=LOC_A1,
            auth_method="otp_sms",
            reason="OtpExpiredError",
            ip_address=None,
        )
        assert session.committed is True
        assert session.inserted[0]["message"].endswith("OTP expired")

    async def test_portal_recorder_never_raises(self) -> None:
        def broken():
            raise RuntimeError("pool exhausted")

        await PortalLoginEventRecorder(
            ON,  # type: ignore[arg-type]
            session_factory=broken,
        ).record_login_failure(
            organization_id=ORG_A,
            location_id=None,
            auth_method="otp_sms",
            reason="x",
            ip_address=None,
        )


class TestGuestWiring:
    """The real GuestService/RadiusService paths, on test_guest's fakes."""

    async def _nas(self, fx):
        await fx.radius_service.register_nas(
            actor_user_id=uuid.uuid4(),
            router_id=fx.router.id,
            nas_identifier="nas-1",
            shared_secret="supersecret123",
        )
        return await fx.radius_service.authenticate_nas(
            nas_identifier="nas-1", shared_secret="supersecret123"
        )

    async def test_radius_reject_and_accept_are_recorded(self) -> None:
        from tests.unit.test_guest import GuestAuthMethod, make_fixture

        calls: list[dict[str, Any]] = []

        class Recorder:
            async def record_decision(self, **kw):
                calls.append(kw)

        fx = make_fixture()
        fx.radius_service.radius_event_recorder = Recorder()
        nas = await self._nas(fx)
        rejected = await fx.radius_service.authorize(
            nas_client=nas, username="nobody", calling_station_id="AA:BB:CC:DD:EE:01"
        )
        assert rejected.authorized is False
        await fx.guest_service.login_via_otp(
            identifier="+15553334444",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        accepted = await fx.radius_service.authorize(
            nas_client=nas, username="+15553334444"
        )
        assert accepted.authorized is True
        assert [c["accepted"] for c in calls] == [False, True]
        assert calls[0]["reason"]
        assert calls[0]["router"].id == fx.router.id
        assert all("username" not in c for c in calls)

    async def test_a_broken_recorder_never_changes_the_verdict(self) -> None:
        from tests.unit.test_guest import GuestAuthMethod, make_fixture

        class Exploding:
            async def record_decision(self, **kw):
                raise RuntimeError("db down")

        fx = make_fixture()
        fx.radius_service.radius_event_recorder = Exploding()
        nas = await self._nas(fx)
        await fx.guest_service.login_via_otp(
            identifier="+15553334444",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        authz = await fx.radius_service.authorize(
            nas_client=nas, username="+15553334444"
        )
        assert authz.authorized is True

    async def test_wrong_otp_is_mirrored_without_the_identifier(self) -> None:
        from tests.unit.test_guest import GuestAuthMethod, make_fixture

        calls: list[dict[str, Any]] = []

        class Recorder:
            async def record_login_failure(self, **kw):
                calls.append(kw)

        fx = make_fixture()
        fx.guest_service.login_event_recorder = Recorder()
        with pytest.raises(Exception):
            await fx.guest_service.login_via_otp(
                identifier="+15553334444",
                code="BAD",
                auth_method=GuestAuthMethod.OTP_SMS,
                organization_id=None,
                location_id=fx.location_id,
                router_id=fx.router.id,
            )
        assert len(calls) == 1
        assert calls[0]["reason"] == "OtpCodeMismatchError"
        assert calls[0]["location_id"] == fx.location_id
        assert "+15553334444" not in repr(calls[0])


# -- opt-in: real Postgres with the 0167 schema --------------------------------

_DSN = os.environ.get("NETLOGS_TEST_PG_DSN")


@pytest.mark.skipif(not _DSN, reason="set NETLOGS_TEST_PG_DSN to run")
class TestRealPostgres:
    """Runs the real repository SQL. Expects a database where migration 0167
    ran on top of minimal organizations/locations/routers tables (the test
    adds the name/organization columns it joins on)."""

    async def test_queries_isolate_tenants(self) -> None:
        from sqlalchemy import text
        from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

        from app.domains.device_logs.repository import CustomerLogsRepository

        engine = create_async_engine(_DSN)  # type: ignore[arg-type]
        try:
            async with AsyncSession(engine) as session:
                await session.execute(
                    text(
                        "ALTER TABLE locations ADD COLUMN IF NOT EXISTS name text, "
                        "ADD COLUMN IF NOT EXISTS organization_id uuid"
                    )
                )
                await session.execute(
                    text(
                        "ALTER TABLE routers ADD COLUMN IF NOT EXISTS name text, "
                        "ADD COLUMN IF NOT EXISTS location_id uuid, "
                        "ADD COLUMN IF NOT EXISTS organization_id uuid"
                    )
                )
                for org in (ORG_A, ORG_B):
                    await session.execute(
                        text("INSERT INTO organizations (id) VALUES (:i)"), {"i": org}
                    )
                for loc, org in LOCATIONS.items():
                    await session.execute(
                        text(
                            "INSERT INTO locations (id, name, organization_id) "
                            "VALUES (:i, 'L', :o)"
                        ),
                        {"i": loc, "o": org},
                    )
                for rtr, (org, loc) in ROUTERS.items():
                    await session.execute(
                        text(
                            "INSERT INTO routers (id, name, location_id, "
                            "organization_id) VALUES (:i, 'R', :l, :o)"
                        ),
                        {"i": rtr, "l": loc, "o": org},
                    )
                for rtr, (org, loc) in ROUTERS.items():
                    for sev in (3, 6, 6):
                        await session.execute(
                            text(
                                "INSERT INTO device_log_events (received_at, "
                                "organization_id, location_id, router_id, source_ip,"
                                " vendor, source, severity, message, attribution, "
                                "category) VALUES (now() - interval '1 hour', :o, :l,"
                                " :r, 'x', 'mikrotik', 'syslog', :s, 'hello', "
                                "'tunnel_ip', 'firewall')"
                            ),
                            {"o": org, "l": loc, "r": rtr, "s": sev},
                        )
                repo = CustomerLogsRepository(session)
                now = datetime.now(UTC)
                f = CustomerFilters(
                    organization_id=ORG_B,
                    since=now - timedelta(days=1),
                    until=now,
                    text="hell",
                )
                rows = await repo.list_events(f, limit=50)
                assert {r["event"].organization_id for r in rows} == {ORG_B}
                buckets = await repo.summary_buckets(f, tz="Asia/Kolkata")
                assert sum(b[3] for b in buckets) == 3
                top = await repo.top_routers(f, limit=10)
                assert [t[0] for t in top] == [RTR_B1]
                confined = CustomerFilters(
                    organization_id=ORG_A,
                    since=now - timedelta(days=1),
                    until=now,
                    allowed_location_ids=(LOC_A2,),
                )
                rows = await repo.list_events(confined, limit=50)
                assert {r["event"].location_id for r in rows} == {LOC_A2}
                await session.rollback()
        finally:
            await engine.dispose()
