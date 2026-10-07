"""Guest device events: the DHCP/hotspot subset of device logs, linked to one
guest session for the customer's Guest Connection Records.

Covers the parser (accepted shapes, and the look-alike lines that must stay
out), derivation at ingest and in the backfill, the session matching rule
(exactly one session or nothing) and its honest coverage states, and the
route's permission + scoping wiring."""

from __future__ import annotations

import inspect
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest

from app.domains.device_logs.constants import Attribution
from app.domains.device_logs.guest_events import (
    GuestEventKind,
    guest_event_row,
    message_body,
    parse_guest_event,
)
from app.domains.device_logs.parser import parse_line
from app.domains.device_logs.repository import PeerOwner
from app.domains.device_logs.schemas import IngestEvent, SessionDeviceEvents
from app.domains.device_logs.service import DeviceLogsService
from app.domains.device_logs.session_events import (
    LEAD,
    TRAIL,
    Coverage,
    GuestDeviceEventsReader,
    session_window,
)

NOW = datetime(2026, 10, 7, 9, 0, 0, tzinfo=UTC)
ORG_ID = uuid.uuid4()
LOC_ID = uuid.uuid4()
ROUTER_ID = uuid.UUID("412d5133-0000-4000-8000-000000000001")
MAC = "3C:22:FB:11:22:33"

# The one real line shape we have from the fleet (prod, Office Router,
# RouterOS 7.21.4, remote-log-format=syslog, 2026-10-07): the identity has
# spaces, there is no topic list, and this "logged in" is a router ADMIN
# login -- it must never become a guest event.
PROD_ADMIN_LOGIN = (
    "<174>Oct  7 10:40:58 Signature Global Office wyfy-412d5133: "
    "user cloudguest-api logged in from 10.20.0.1 via api"
)


# -- parser: identity with spaces (prod shape) ---------------------------------


class TestIdentityWithSpaces:
    def test_tag_is_found_after_a_multi_word_identity(self) -> None:
        p = parse_line(PROD_ADMIN_LOGIN, received_at=NOW)
        assert p.hostname == "Signature Global Office"
        assert p.tag == "412d5133"
        assert p.message == "user cloudguest-api logged in from 10.20.0.1 via api"

    def test_single_word_identity_unchanged(self) -> None:
        p = parse_line(
            "<174>Oct  7 14:29:58 Hall-Router wyfy-8a199617 dhcp,info x y",
            received_at=NOW,
        )
        assert (p.hostname, p.tag, p.topics, p.message) == (
            "Hall-Router",
            "8a199617",
            "dhcp,info",
            "x y",
        )

    def test_tag_deep_inside_the_message_is_message_text(self) -> None:
        p = parse_line(
            "<174>Oct  7 14:29:58 r one two three four five six seven "
            "wyfy-412d5133: x",
            received_at=NOW,
        )
        assert p.tag is None
        assert p.hostname == "r"


# -- parser: guest events ------------------------------------------------------


class TestGuestEventParser:
    @pytest.mark.parametrize(
        ("message", "kind", "ip", "mac"),
        [
            # RouterOS 7: "for <mac>" plus the client's host name (dropped).
            (
                "dhcp-guest assigned 10.5.50.12 for 3c:22:fb:11:22:33 Rahuls-iPhone",
                GuestEventKind.IP_ASSIGNED,
                "10.5.50.12",
                MAC,
            ),
            (
                "dhcp-guest deassigned 10.5.50.12 for 3C:22:FB:11:22:33",
                GuestEventKind.IP_RELEASED,
                "10.5.50.12",
                MAC,
            ),
            # RouterOS 6 prepositions.
            (
                "dhcp1 assigned 192.168.88.254 to 3C:22:FB:11:22:33",
                GuestEventKind.IP_ASSIGNED,
                "192.168.88.254",
                MAC,
            ),
            (
                "dhcp1 deassigned 192.168.88.254 from 3C:22:FB:11:22:33",
                GuestEventKind.IP_RELEASED,
                "192.168.88.254",
                MAC,
            ),
            # Hotspot: the user name arrives already masked and is dropped.
            (
                "98******47 (10.5.50.12): logged in",
                GuestEventKind.ROUTER_SIGN_IN,
                "10.5.50.12",
                None,
            ),
            (
                "98******47 (10.5.50.12): logged out: keepalive timeout",
                GuestEventKind.ROUTER_SIGN_OUT,
                "10.5.50.12",
                None,
            ),
            # Stored before the identity fix: identity remainder + tag still
            # in the message.
            (
                "Global Office wyfy-412d5133: dhcp-guest assigned 10.5.50.9 "
                "for 3C:22:FB:11:22:33 Pixel-7",
                GuestEventKind.IP_ASSIGNED,
                "10.5.50.9",
                MAC,
            ),
        ],
    )
    def test_accepted_shapes(self, message, kind, ip, mac) -> None:
        event = parse_guest_event(message)
        assert event is not None
        assert (event.kind, event.ip_address, event.mac_address) == (kind, ip, mac)

    def test_sign_out_reason_kept_only_when_it_reads_like_routeros(self) -> None:
        good = parse_guest_event("u (10.5.50.12): logged out: user request")
        assert good is not None and good.detail == "user request"
        odd = parse_guest_event("u (10.5.50.12): logged out: <script>")
        assert odd is not None and odd.detail is None

    @pytest.mark.parametrize(
        "message",
        [
            # Router admin logins also say "logged in" -- never guest events.
            "user cloudguest-api logged in from 10.20.0.1 via api",
            "user admin logged out from 10.20.0.1 via winbox",
            "login failure for user admin from 10.20.0.1 via ssh",
            # Hotspot lines that are not a completed sign-in/out.
            "98******47 (10.5.50.12): trying to log in by http-chap",
            "98******47 (10.5.50.12): login failed: invalid username or password",
            "98******47 (10.5.50.12): logged in extra",
            # DHCP lines that are not an assignment.
            "dhcp-guest offering lease 10.5.50.12 for 3C:22:FB:11:22:33 "
            "without success",
            "dhcp-guest deassigned 10.5.50.12 to 3C:22:FB:11:22:33",
            "dhcp-guest assigned 10.5.50.312 for 3C:22:FB:11:22:33",
            "dhcp-guest assigned 10.5.50.12 for 3C:22:FB:11:22",
            # Anything else.
            "Download from master.wyfyguest.com FINISHED",
            "input: in:ether1 out:(unknown 0), src-mac 3C:22:FB:11:22:33, proto TCP",
        ],
    )
    def test_look_alikes_produce_nothing(self, message) -> None:
        assert parse_guest_event(message) is None

    def test_a_non_guest_topic_list_rejects_matching_text(self) -> None:
        msg = "dhcp-guest assigned 10.5.50.12 for 3C:22:FB:11:22:33"
        assert parse_guest_event(msg, topics="system,info") is None
        assert parse_guest_event(msg, topics="dhcp,info") is not None
        assert parse_guest_event(msg, topics=None) is not None

    def test_message_body_strips_only_a_leading_tag(self) -> None:
        assert message_body("A B wyfy-412d5133: x y") == "x y"
        assert message_body("x wyfy-zzzz y") == "x wyfy-zzzz y"


def _row(**over: Any) -> dict[str, Any]:
    base = {
        "device_log_event_id": 7,
        "attribution": Attribution.TUNNEL_IP.value,
        "organization_id": ORG_ID,
        "location_id": LOC_ID,
        "router_id": ROUTER_ID,
        "received_at": NOW,
        "device_time": None,
        "topics": None,
        "message": "dhcp-guest assigned 10.5.50.12 for 3C:22:FB:11:22:33 Phone",
    }
    return {**base, **over}


class TestGuestEventRow:
    def test_attributed_line_becomes_a_row_without_host_name(self) -> None:
        row = guest_event_row(**_row())
        assert row is not None
        assert row["kind"] == "ip_assigned" and row["mac_address"] == MAC
        assert row["occurred_at"] == NOW and row["device_log_event_id"] == 7
        assert "Phone" not in str(row.values())

    @pytest.mark.parametrize(
        "over",
        [
            {"attribution": Attribution.TAG_MISMATCH.value},
            {"attribution": Attribution.UNATTRIBUTED.value, "router_id": None},
            {"location_id": None},
            {"organization_id": None},
        ],
    )
    def test_line_with_doubtful_owner_is_not_derived(self, over) -> None:
        assert guest_event_row(**_row(**over)) is None


# -- ingest + backfill ---------------------------------------------------------


class _IngestRepo:
    def __init__(self) -> None:
        self.owners = {"10.20.0.38": [PeerOwner(ROUTER_ID, ORG_ID, LOC_ID)]}
        self.lines: list[dict[str, Any]] = []
        self.guest_rows: list[dict[str, Any]] = []

    async def owners_by_tunnel_ip(self, ips):
        return {ip: self.owners[ip] for ip in ips if ip in self.owners}

    async def insert_events(self, rows):
        start = len(self.lines)
        self.lines.extend(rows)
        return list(range(100 + start, 100 + start + len(rows)))

    async def insert_guest_events(self, rows):
        self.guest_rows.extend(rows)
        return len(rows)


def _settings() -> Any:
    return SimpleNamespace(device_logs_enabled=True)


class TestIngestDerivesGuestEvents:
    @pytest.mark.asyncio
    async def test_only_guest_lines_derive_and_ids_line_up(self) -> None:
        repo = _IngestRepo()
        service = DeviceLogsService(repo, _settings(), clock=lambda: NOW)  # type: ignore[arg-type]
        raws = [
            PROD_ADMIN_LOGIN,
            "<174>Oct  7 14:29:58 Signature Global Office wyfy-412d5133: "
            "dhcp-guest assigned 10.5.50.12 for 3C:22:FB:11:22:33 Rahuls-iPhone",
            "<174>Oct  7 14:29:59 Signature Global Office wyfy-412d5133: "
            "9876598647 (10.5.50.12): logged in",
        ]
        await service.ingest(
            [IngestEvent(received_at=NOW, source_ip="10.20.0.38", raw=r) for r in raws]
        )
        assert [r["kind"] for r in repo.guest_rows] == [
            "ip_assigned",
            "router_sign_in",
        ]
        assert [r["device_log_event_id"] for r in repo.guest_rows] == [101, 102]
        # The phone never reaches either table.
        assert "9876598647" not in str(repo.lines) + str(repo.guest_rows)

    @pytest.mark.asyncio
    async def test_unattributed_source_derives_nothing(self) -> None:
        repo = _IngestRepo()
        service = DeviceLogsService(repo, _settings(), clock=lambda: NOW)  # type: ignore[arg-type]
        await service.ingest(
            [
                IngestEvent(
                    received_at=NOW,
                    source_ip="172.31.0.9",
                    raw="<174>Oct  7 14:29:58 r wyfy-412d5133: "
                    "dhcp1 assigned 10.5.50.12 for 3C:22:FB:11:22:33",
                )
            ]
        )
        assert repo.guest_rows == []


class _BackfillRepo:
    def __init__(self, lines: list[Any]) -> None:
        self.lines = lines
        self.pages: list[int] = []
        self.guest_rows: list[dict[str, Any]] = []

    async def lines_without_guest_event(self, *, after_id, limit):
        self.pages.append(after_id)
        done = {r["device_log_event_id"] for r in self.guest_rows}
        page = [
            line for line in self.lines if line.id > after_id and line.id not in done
        ]
        return page[:limit]

    async def insert_guest_events(self, rows):
        self.guest_rows.extend(rows)
        return len(rows)


def _line(event_id: int, message: str) -> Any:
    return SimpleNamespace(
        id=event_id,
        attribution="tunnel_ip",
        organization_id=ORG_ID,
        location_id=LOC_ID,
        router_id=ROUTER_ID,
        received_at=NOW,
        device_time=None,
        topics=None,
        message=message,
    )


class TestBackfill:
    @pytest.mark.asyncio
    async def test_pages_through_and_is_idempotent(self) -> None:
        lines = [
            _line(1, "Global Office wyfy-412d5133: user admin logged in from x"),
            _line(2, "Global Office wyfy-412d5133: d assigned 10.5.50.2 for " + MAC),
            _line(3, "u (10.5.50.2): logged out: user request"),
        ]
        repo = _BackfillRepo(lines)
        service = DeviceLogsService(repo, _settings(), clock=lambda: NOW)  # type: ignore[arg-type]
        assert await service.backfill_guest_events(batch_size=2) == 2
        assert repo.pages == [0, 2, 3]
        assert await service.backfill_guest_events(batch_size=2) == 0
        assert len(repo.guest_rows) == 2


# -- matching + coverage -----------------------------------------------------------


def _session(**over: Any) -> Any:
    base = {
        "id": uuid.uuid4(),
        "organization_id": ORG_ID,
        "location_id": LOC_ID,
        "router_id": ROUTER_ID,
        "device_id": uuid.uuid4(),
        "ip_address": "10.5.50.12",
        "status": "disconnected",
        "started_at": NOW - timedelta(hours=2),
        "ended_at": NOW - timedelta(hours=1),
        "last_activity_at": NOW - timedelta(hours=1),
    }
    return SimpleNamespace(**{**base, **over})


class TestSessionWindow:
    def test_ended_session(self) -> None:
        s = _session()
        assert session_window(s, NOW) == (s.started_at - LEAD, s.ended_at + TRAIL)

    def test_open_session_runs_to_now(self) -> None:
        s = _session(status="active", ended_at=None)
        assert session_window(s, NOW)[1] == NOW + TRAIL

    def test_stale_session_without_end_stops_at_last_activity(self) -> None:
        s = _session(status="expired", ended_at=None)
        assert session_window(s, NOW)[1] == s.last_activity_at + TRAIL


class _ReaderRepo:
    def __init__(self, *, first_line, candidates=(), matches=None, mac=MAC):
        self.first_line = first_line
        self.candidates = list(candidates)
        self.matches = matches or {}
        self.mac = mac
        self.keys: list[Any] = []

    async def device_mac(self, device_id):
        return self.mac

    async def first_guest_line_at(self, *, organization_id, location_id):
        return self.first_line

    async def candidate_guest_events(self, key, *, limit):
        self.keys.append(key)
        return self.candidates

    async def sessions_matching_events(self, ids, **_):
        return {i: self.matches.get(i, 1) for i in ids}


def _candidate(event_id: int, kind: str = "ip_assigned") -> Any:
    return SimpleNamespace(
        id=event_id,
        occurred_at=NOW - timedelta(minutes=90),
        device_time=None,
        kind=kind,
        ip_address="10.5.50.12",
        mac_address=MAC if kind.startswith("ip_") else None,
        detail=None,
    )


class TestReader:
    @pytest.mark.asyncio
    async def test_venue_never_sent_logs(self) -> None:
        repo = _ReaderRepo(first_line=None)
        data = await GuestDeviceEventsReader(repo).for_session(_session(), now=NOW)  # type: ignore[arg-type]
        assert data["coverage"] == Coverage.NOT_SENDING
        assert data["events"] == [] and repo.keys == []

    @pytest.mark.asyncio
    async def test_logs_started_after_the_session(self) -> None:
        repo = _ReaderRepo(first_line=NOW - timedelta(minutes=5))
        data = await GuestDeviceEventsReader(repo).for_session(_session(), now=NOW)  # type: ignore[arg-type]
        assert data["coverage"] == Coverage.NOT_SENDING_DURING_SESSION
        assert repo.keys == []

    @pytest.mark.asyncio
    async def test_ambiguous_events_are_held_back_not_guessed(self) -> None:
        repo = _ReaderRepo(
            first_line=NOW - timedelta(days=1),
            candidates=[_candidate(1), _candidate(2, "router_sign_in")],
            matches={2: 2},
        )
        session = _session()
        data = await GuestDeviceEventsReader(repo).for_session(session, now=NOW)  # type: ignore[arg-type]
        assert data["coverage"] == Coverage.COVERED
        assert [e["kind"] for e in data["events"]] == ["ip_assigned"]
        assert data["ambiguous_count"] == 1
        key = repo.keys[0]
        # Keyed on the fetched session row only.
        assert (key.organization_id, key.location_id, key.router_id) == (
            session.organization_id,
            session.location_id,
            session.router_id,
        )
        assert (key.mac_address, key.ip_address) == (MAC, "10.5.50.12")
        SessionDeviceEvents.model_validate({"session_id": "x", **data})

    @pytest.mark.asyncio
    async def test_event_matching_no_session_in_sql_is_not_shown(self) -> None:
        repo = _ReaderRepo(
            first_line=NOW - timedelta(days=1),
            candidates=[_candidate(1)],
            matches={1: 0},
        )
        data = await GuestDeviceEventsReader(repo).for_session(_session(), now=NOW)  # type: ignore[arg-type]
        assert data["events"] == [] and data["ambiguous_count"] == 1

    @pytest.mark.asyncio
    async def test_session_without_mac_or_ip_is_not_linkable(self) -> None:
        repo = _ReaderRepo(first_line=NOW - timedelta(days=1), mac=None)
        data = await GuestDeviceEventsReader(repo).for_session(
            _session(ip_address=None, device_id=None),  # type: ignore[arg-type]
            now=NOW,
        )
        assert data["linkable"] is False


# -- route wiring -------------------------------------------------------------------


def _permission_key_and_scope(route) -> tuple[str | None, str | None]:
    for dependency in route.dependant.dependencies:
        call = dependency.call
        freevars = getattr(getattr(call, "__code__", None), "co_freevars", ())
        if "permission_key" in freevars:
            key = call.__closure__[freevars.index("permission_key")].cell_contents
            scope = None
            if "scope" in freevars:
                value = call.__closure__[freevars.index("scope")].cell_contents
                scope = value.value if value is not None else None
            return key, scope
    return None, None


@pytest.fixture(scope="module")
def app_routes():
    from app.main import create_app

    return {
        (route.path, method): route
        for route in create_app().routes
        if getattr(route, "methods", None)
        for method in route.methods
    }


class TestRoute:
    PATH = "/api/v1/guest-sessions/{session_id}/device-events"

    def test_uses_the_reports_own_read_permission(self, app_routes) -> None:
        detail_key, detail_scope = _permission_key_and_scope(
            app_routes[("/api/v1/guest-sessions/{session_id}", "GET")]
        )
        key, scope = _permission_key_and_scope(app_routes[(self.PATH, "GET")])
        assert key == "guest_sessions.read" == detail_key
        # Same scope handling as the session detail it hangs off; the tenant
        # boundary is the scoped getter below, not a broader pin.
        assert scope == detail_scope

    def test_declares_an_organization_dependency(self, app_routes) -> None:
        from app.domains.rbac.dependencies import CurrentOrganization

        route = app_routes[(self.PATH, "GET")]
        calls = {d.call for d in route.dependant.dependencies}
        assert CurrentOrganization in calls

    def test_takes_no_org_location_or_router_from_the_request(self, app_routes) -> None:
        route = app_routes[(self.PATH, "GET")]
        params = {p.name for p in route.dependant.query_params} | {
            p.name for p in route.dependant.path_params
        }
        assert params == {"session_id"}
        assert route.dependant.body_params == []

    def test_raw_device_logs_stay_master_only(self, app_routes) -> None:
        for (path, _method), route in app_routes.items():
            if path.startswith("/api/v1/platform/device-logs"):
                key, scope = _permission_key_and_scope(route)
                assert key in {"device_logs.read", "device_logs.manage"}
                assert scope == "global", path

    @pytest.mark.asyncio
    async def test_foreign_session_never_reaches_the_reader(self) -> None:
        from app.domains.guest import router as guest_router
        from app.domains.guest.exceptions import GuestSessionNotFoundError

        class _Service:
            async def get_session(self, session_id, *, requesting_organization_id):
                assert requesting_organization_id == ORG_ID
                raise GuestSessionNotFoundError(session_id)

        class _Reader:
            called = False

            async def for_session(self, *_a, **_k):
                _Reader.called = True
                return {}

        request = SimpleNamespace(headers={}, state=SimpleNamespace(request_id="r"))
        with pytest.raises(GuestSessionNotFoundError):
            await guest_router.get_guest_session_device_events(
                request,  # type: ignore[arg-type]
                uuid.uuid4(),
                requesting_organization_id=ORG_ID,
                service=_Service(),  # type: ignore[arg-type]
                reader=_Reader(),  # type: ignore[arg-type]
            )
        assert _Reader.called is False

    @pytest.mark.asyncio
    async def test_reader_gets_the_scoped_session_row(self) -> None:
        from app.domains.guest import router as guest_router

        session = _session()
        seen: list[Any] = []

        class _Service:
            async def get_session(self, session_id, *, requesting_organization_id):
                return session

        class _Reader:
            async def for_session(self, s, *, now):
                seen.append(s)
                return {
                    "coverage": "covered",
                    "logging_since": NOW,
                    "linkable": True,
                    "window_start": NOW,
                    "window_end": NOW,
                    "events": [],
                    "ambiguous_count": 0,
                }

        request = SimpleNamespace(headers={}, state=SimpleNamespace(request_id="r"))
        response = await guest_router.get_guest_session_device_events(
            request,  # type: ignore[arg-type]
            session.id,
            requesting_organization_id=ORG_ID,
            service=_Service(),  # type: ignore[arg-type]
            reader=_Reader(),  # type: ignore[arg-type]
        )
        assert seen == [session]
        assert inspect.isawaitable(response) is False
