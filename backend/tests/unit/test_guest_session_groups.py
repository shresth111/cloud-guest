"""``GET /guest-session-groups``: the venue Guests table, one row per guest.

The owner, at the Aruba venue (2026-10-05): "isme guest baar baar dikh rahe
hai" -- the same guest listed again and again. The Guests table read
``GET /guest-sessions`` (one row per SESSION) under a "Total guests" tile that
counts people, so a guest who reconnected six times was six rows. The
frontend's adjacent-rows reconnect merge could not fix it: it only saw one
page, only merged rows a few minutes apart, and a guest alternating between a
phone and a laptop was never adjacent. The fix is a grouped listing paged by
guest, in SQL.

What is pinned here:

* the route: registered, mounted, gated exactly like ``GET /guest-sessions``
  (``guest_sessions.read``), and building one row per guest with the primary
  session's full ``GuestSessionResponse``;
* the service: the caller's organization and *confined* location filter, as
  ``list_sessions`` applies them;
* the statements: grouped by guest, ACTIVE guests first, the primary picked
  per guest with ``row_number()`` (ACTIVE first, then newest), the
  active/ended filter as a ``HAVING``, soft-deleted rows excluded, tenant in
  every WHERE. (Behaviour against a real PostgreSQL was checked by hand on a
  migrated database; see the PR.)
* ``instant_on_cloud_disconnect``: False unless every Instant On cloud-control
  gate is open for the location -- the Aruba Disconnect copy depends on it.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy.dialects import postgresql

from app.domains.guest import router as guest_router
from app.domains.guest.models import GuestSession
from app.domains.guest.repository import GuestRepository, GuestSessionGroupRow
from app.domains.guest.service import GuestService

ORG = uuid.uuid4()
LOC = uuid.uuid4()
ROUTER = uuid.uuid4()
NOW = datetime(2026, 10, 5, 10, 0, tzinfo=UTC)


def _session(guest_id: uuid.UUID, *, status: str = "active", minutes_ago: int = 5):
    return GuestSession(
        id=uuid.uuid4(),
        guest_id=guest_id,
        device_id=None,
        router_id=ROUTER,
        location_id=LOC,
        organization_id=ORG,
        auth_method="otp",
        voucher_id=None,
        status=status,
        started_at=NOW - timedelta(minutes=minutes_ago),
        ended_at=None if status == "active" else NOW,
        last_activity_at=NOW,
        ip_address="10.0.0.2",
        bytes_uploaded=1,
        bytes_downloaded=2,
        data_limit_mb=None,
        session_timeout_minutes=240,
        disconnect_reason=None,
        disconnect_enforced=None,
        user_agent="iPhone",
        created_at=NOW,
    )


def _group(
    primary: GuestSession, *, sessions: int, active_ids=()
) -> GuestSessionGroupRow:
    return GuestSessionGroupRow(
        guest_id=primary.guest_id,
        session_count=sessions,
        active_session_count=len(active_ids),
        device_count=2,
        first_started_at=NOW - timedelta(hours=3),
        last_started_at=primary.started_at,
        bytes_downloaded_total=6_000_000,
        bytes_uploaded_total=60,
        primary=primary,
        active_session_ids=tuple(active_ids),
    )


# ============================================================================
# The route
# ============================================================================


def _route(path: str):
    return next(
        r
        for r in guest_router.admin_router.routes
        if getattr(r, "path", None) == path and "GET" in getattr(r, "methods", set())
    )


def _permission_key(route) -> str | None:  # noqa: ANN001
    for dependency in route.dependant.dependencies:
        call = dependency.call
        freevars = getattr(call.__code__, "co_freevars", ())
        if "permission_key" in freevars:
            return call.__closure__[freevars.index("permission_key")].cell_contents
    return None


class TestRouteRegistration:
    def test_gated_exactly_like_the_sessions_list_it_summarises(self) -> None:
        assert _permission_key(_route("/guest-session-groups")) == "guest_sessions.read"
        assert _permission_key(_route("/guest-session-groups")) == _permission_key(
            _route("/guest-sessions")
        )

    def test_mounted_under_api_v1(self) -> None:
        from app.api.v1.router import api_v1_router

        paths = {getattr(r, "path", "") for r in api_v1_router.routes}
        assert any(p.endswith("/guest-session-groups") for p in paths)

    def test_does_not_collide_with_the_session_id_route(self) -> None:
        """``/guest-sessions/{session_id}`` types its id as a UUID, so a
        ``/guest-sessions/grouped`` path would 422 there. A sibling path
        cannot be captured by it."""
        assert _route("/guest-session-groups").path != "/guest-sessions/{session_id}"


class _FakeService:
    def __init__(self, groups: list[GuestSessionGroupRow]) -> None:
        self.groups = groups
        self.calls: list[dict[str, Any]] = []

    async def list_session_groups(self, **kwargs: Any):  # noqa: ANN202
        self.calls.append(kwargs)
        meta = SimpleNamespace(
            page=kwargs["page"],
            page_size=kwargs["page_size"],
            total_items=len(self.groups),
            total_pages=1,
            has_next=False,
            has_previous=False,
        )
        return self.groups, meta


@pytest.fixture
def _no_lookups(monkeypatch):  # noqa: ANN001, ANN202
    async def _empty(*_a, **_k):  # noqa: ANN002, ANN003, ANN202
        return {}

    async def _identifiers(sessions, **_k):  # noqa: ANN001, ANN003, ANN202
        return {str(s.guest_id): "+919999955613" for s in sessions}

    for name in (
        "_resolve_session_macs",
        "_resolve_router_names",
        "_resolve_session_presence",
        "_resolve_ap_names",
    ):
        monkeypatch.setattr(guest_router, name, _empty)
    monkeypatch.setattr(
        guest_router, "_resolve_session_guest_identifiers", _identifiers
    )


async def _call(service, monkeypatch, *, cloud: bool = False, **kwargs):  # noqa: ANN001, ANN003, ANN202
    from app.domains.network_integration import instant_on_control

    asked: list[dict[str, Any]] = []

    async def _present(_db, **kw):  # noqa: ANN001, ANN003, ANN202
        asked.append(kw)
        return cloud

    monkeypatch.setattr(instant_on_control, "instant_on_control_present", _present)
    params: dict[str, Any] = {
        "page": 1,
        "page_size": 8,
        "location_id": LOC,
        "session_state": None,
        "search": None,
        "ap_mac": None,
        "requesting_organization_id": ORG,
        "scope_location_id": None,
        "service": service,
        "db": object(),
    }
    params.update(kwargs)
    request = SimpleNamespace(state=SimpleNamespace(request_id="r1"))
    response = await guest_router.list_guest_session_groups(request, **params)
    body = response if isinstance(response, dict) else response.body
    return body["data"], asked


@pytest.mark.usefixtures("_no_lookups")
class TestRouteBody:
    async def test_one_row_per_guest_with_the_primary_session(
        self, monkeypatch
    ) -> None:  # noqa: ANN001
        g1, g2 = uuid.uuid4(), uuid.uuid4()
        live = _session(g1)
        ended = _session(g2, status="disconnected", minutes_ago=90)
        service = _FakeService(
            [_group(live, sessions=6, active_ids=[live.id]), _group(ended, sessions=3)]
        )
        data, _ = await _call(service, monkeypatch)

        assert [i["guest_id"] for i in data["items"]] == [str(g1), str(g2)]
        first = data["items"][0]
        assert first["session_count"] == 6
        assert first["active_session_count"] == 1
        assert first["active_session_ids"] == [str(live.id)]
        assert first["device_count"] == 2
        assert first["bytes_downloaded_total"] == 6_000_000
        assert first["guest_identifier"] == "+919999955613"
        assert first["latest_session"]["id"] == str(live.id)
        assert first["latest_session"]["is_online"] is True
        assert first["latest_session"]["session_timeout_minutes"] == 240
        assert data["items"][1]["latest_session"]["is_online"] is False
        assert data["items"][1]["active_session_ids"] == []
        assert data["total_items"] == 2

    async def test_status_maps_to_the_active_flag_and_ap_mac_is_canonical(
        self, monkeypatch
    ) -> None:  # noqa: ANN001
        service = _FakeService([])
        await _call(service, monkeypatch, session_state="active", ap_mac="AABBCCDDEE01")
        await _call(service, monkeypatch, session_state="ended")
        await _call(service, monkeypatch, search="  ravi ")
        assert service.calls[0]["active"] is True
        assert service.calls[0]["ap_mac"] == "AA:BB:CC:DD:EE:01"  # as /guest-sessions
        assert service.calls[1]["active"] is False
        assert service.calls[1]["ap_mac"] is None
        assert service.calls[2]["active"] is None
        assert service.calls[2]["search"] == "  ravi "  # stripped by the service
        assert all(c["requesting_organization_id"] == ORG for c in service.calls)

    async def test_cloud_disconnect_flag_reports_the_gate(self, monkeypatch) -> None:  # noqa: ANN001
        data, asked = await _call(_FakeService([]), monkeypatch, cloud=False)
        assert data["instant_on_cloud_disconnect"] is False
        assert asked == [{"location_id": LOC, "organization_id": ORG}]
        data, _ = await _call(_FakeService([]), monkeypatch, cloud=True)
        assert data["instant_on_cloud_disconnect"] is True

    async def test_cloud_flag_never_asked_without_a_location_or_tenant(
        self, monkeypatch
    ) -> None:  # noqa: ANN001
        data, asked = await _call(_FakeService([]), monkeypatch, location_id=None)
        assert data["instant_on_cloud_disconnect"] is False
        data, asked2 = await _call(
            _FakeService([]), monkeypatch, requesting_organization_id=None
        )
        assert asked == [] and asked2 == []


# ============================================================================
# The service
# ============================================================================


class TestService:
    async def test_scoped_like_list_sessions(self) -> None:
        captured: dict[str, Any] = {}

        class _Repo:
            async def list_session_groups(self, **kwargs: Any):  # noqa: ANN202
                captured.update(kwargs)
                return [], None

        service = GuestService.__new__(GuestService)
        service.repository = _Repo()
        other = uuid.uuid4()
        service._confined_location_filter = lambda loc: [loc, other]  # type: ignore[method-assign]
        await service.list_session_groups(
            requesting_organization_id=ORG,
            location_id=LOC,
            active=True,
            search="  ",
            page=2,
            page_size=8,
            ap_mac=None,
        )
        assert captured == {
            "organization_id": ORG,
            "location_id": [LOC, other],
            "ap_mac": None,
            "active": True,
            "search": None,
            "page": 2,
            "page_size": 8,
        }


# ============================================================================
# The statements
# ============================================================================


class _Result:
    def __init__(self, value: Any) -> None:
        self.value = value

    def scalar_one(self) -> Any:
        return self.value

    def mappings(self) -> _Result:
        return self

    def scalars(self) -> _Result:
        return self

    def all(self) -> Any:
        return self.value


class _RecordingSession:
    def __init__(self, results: list[Any]) -> None:
        self.results = list(results)
        self.statements: list[str] = []

    async def execute(self, statement: Any) -> _Result:
        self.statements.append(
            str(
                statement.compile(
                    dialect=postgresql.dialect(),
                    compile_kwargs={"literal_binds": False},
                )
            )
        )
        return _Result(self.results.pop(0))


def _repo(results: list[Any]) -> tuple[GuestRepository, _RecordingSession]:
    session = _RecordingSession(results)
    repo = GuestRepository.__new__(GuestRepository)
    repo.session = session  # type: ignore[assignment]
    return repo, session


class TestStatements:
    async def test_grouped_by_guest_active_first_tenant_scoped(self) -> None:
        g1 = uuid.uuid4()
        primary = _session(g1)
        repo, recorder = _repo(
            [
                1,
                [
                    {
                        "guest_id": g1,
                        "session_count": 6,
                        "active_count": 1,
                        "device_count": 2,
                        "first_started_at": NOW,
                        "last_started_at": NOW,
                        "bytes_down": 10,
                        "bytes_up": 1,
                    }
                ],
                [primary],
                [(primary.id, g1)],
            ]
        )
        rows, meta = await repo.list_session_groups(
            organization_id=ORG,
            location_id=LOC,
            ap_mac="aa:bb:cc:dd:ee:01",
            active=None,
            search="ravi",
            page=1,
            page_size=8,
        )
        assert meta.total_items == 1
        assert rows[0].primary is primary
        assert rows[0].active_session_ids == (primary.id,)
        assert rows[0].session_count == 6

        count_sql, page_sql, primary_sql, active_sql = recorder.statements
        for sql in recorder.statements:
            assert "guest_sessions.is_deleted IS false" in sql
            assert "guest_sessions.organization_id = " in sql
            assert "guest_sessions.location_id = " in sql
            assert "guest_sessions.ap_mac = " in sql
            assert "guests.identifier ILIKE" in sql
            assert "guests.organization_id = " in sql
        assert "GROUP BY guest_sessions.guest_id" in count_sql
        assert "HAVING" not in page_sql
        assert "ORDER BY guest_session_groups.active_count > " in page_sql
        assert "guest_session_groups.last_started_at DESC" in page_sql
        assert "LIMIT" in page_sql and "OFFSET" in page_sql
        assert "row_number() OVER (PARTITION BY guest_sessions.guest_id" in primary_sql
        assert "ranked_guest_sessions.rank = " in primary_sql
        assert "guest_sessions.status = " in active_sql

    @pytest.mark.parametrize(("active", "having"), [(True, "> "), (False, "= ")])
    async def test_active_filter_is_a_having(self, active: bool, having: str) -> None:
        repo, recorder = _repo([0, []])
        rows, meta = await repo.list_session_groups(
            organization_id=ORG,
            location_id=LOC,
            ap_mac=None,
            active=active,
            search=None,
            page=1,
            page_size=8,
        )
        assert rows == [] and meta.total_items == 0
        # An empty page asks nothing more.
        assert len(recorder.statements) == 2
        assert (
            "HAVING coalesce(sum(CASE WHEN (guest_sessions.status = "
            in (recorder.statements[0])
        )
        assert f") {having}" in recorder.statements[0].split("HAVING", 1)[1]
        assert "guests.identifier" not in recorder.statements[0]

    async def test_a_global_caller_is_not_narrowed_to_a_tenant(self) -> None:
        repo, recorder = _repo([0, []])
        await repo.list_session_groups(
            organization_id=None,
            location_id=None,
            ap_mac=None,
            active=None,
            search=None,
            page=1,
            page_size=8,
        )
        assert "organization_id" not in recorder.statements[0]
