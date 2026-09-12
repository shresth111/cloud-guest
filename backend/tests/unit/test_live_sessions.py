"""Unit tests for the Live Sessions orchestration layer
(``app.domains.live_sessions.service``).

Follows this codebase's established service-layer testing convention (see
``tests/unit/test_monitoring.py``'s docstring): plain ``assert``/native
``async def`` tests exercised against a small, hand-rolled in-memory fake of
the one collaborator this thin layer composes -- ``GuestService`` -- with no
live Postgres/Redis.

Regression focus: ``LiveSessionService`` composes ``GuestService.list_sessions``,
whose organization filter parameter is the keyword-only
``requesting_organization_id`` (not ``organization_id``). The fake below
mirrors that exact keyword-only signature, so passing the wrong keyword would
raise ``TypeError`` -- which the service's own defensive ``except`` turns into
an empty result -- and every assertion here that active rows come back would
fail. This pins the bug where ``GET /sessions/live`` returned an empty list
even while active sessions existed.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from app.domains.guest.constants import GuestSessionStatus
from app.domains.live_sessions.service import LiveSessionService


@dataclass
class _FakeGuestSession:
    """Stand-in for a real ``GuestSession`` row.

    Deliberately mirrors the real model's **actual** column set. The previous
    version of this fake defined only the five attributes the adapter happened
    to read successfully, which is precisely why the adapter's other seven
    reads -- ``guest_username``, ``mac_address``, ``ssid``, ``nas_identifier``,
    ``router_name``, ``signal_strength``, ``session_duration_seconds``, none of
    which exist on ``GuestSession`` -- could return their ``getattr`` defaults
    forever without a single test noticing. A fake that is missing the same
    fields as the code under test cannot catch a field that does not exist.

    So: every attribute here corresponds to a real column, and any attribute
    the adapter invents will now raise ``AttributeError`` in these tests
    rather than silently becoming ``""``/``0`` in production.
    """

    id: uuid.UUID
    organization_id: uuid.UUID
    location_id: uuid.UUID
    guest_id: uuid.UUID = field(default_factory=uuid.uuid4)
    device_id: uuid.UUID | None = None
    router_id: uuid.UUID | None = None
    status: str = GuestSessionStatus.ACTIVE.value
    ip_address: str = "10.0.0.5"
    user_agent: str = "Mozilla/5.0"
    bytes_downloaded: int = 4096
    bytes_uploaded: int = 1024
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    ended_at: datetime | None = None


@dataclass
class _FakeGuestDevice:
    id: uuid.UUID
    mac_address: str


@dataclass
class _FakeMeta:
    total_items: int = 1


class _FakeGuestService:
    """Records the kwargs it was called with and returns a fixed page.

    ``list_sessions``'s signature deliberately mirrors the *real*
    ``GuestService.list_sessions`` -- keyword-only, org param named
    ``requesting_organization_id`` -- so the wrong keyword raises ``TypeError``
    exactly as it does in production.
    """

    def __init__(
        self,
        rows: list[_FakeGuestSession],
        devices: list[_FakeGuestDevice] | None = None,
    ) -> None:
        self._rows = rows
        self._devices = devices or []
        self.calls: list[dict[str, object]] = []
        # When set, stands in for a total larger than this page, so a test can
        # tell `meta.total_items` apart from `len(page)`.
        self.total_override: int | None = None

    async def list_devices_by_ids(
        self,
        *,
        device_ids: list[uuid.UUID],
        requesting_organization_id: uuid.UUID | None = None,
    ) -> list[_FakeGuestDevice]:
        return [d for d in self._devices if d.id in set(device_ids)]

    async def list_sessions(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        router_id: uuid.UUID | None = None,
        guest_id: uuid.UUID | None = None,
        status: GuestSessionStatus | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[_FakeGuestSession], _FakeMeta]:
        self.calls.append(
            {
                "requesting_organization_id": requesting_organization_id,
                "location_id": location_id,
                "status": status,
                "page": page,
                "page_size": page_size,
            }
        )
        rows = [
            r for r in self._rows if r.organization_id == requesting_organization_id
        ]
        return rows, _FakeMeta(
            total_items=self.total_override
            if self.total_override is not None
            else len(rows)
        )


async def test_live_sessions_returns_active_rows_and_forwards_correct_keyword():
    org_id = uuid.uuid4()
    loc_id = uuid.uuid4()
    row = _FakeGuestSession(id=uuid.uuid4(), organization_id=org_id, location_id=loc_id)
    guest_service = _FakeGuestService([row])
    service = LiveSessionService(guest_service=guest_service, rbac_service=None)

    result = await service.list_live_sessions(organization_id=org_id, status="active")

    # The active row must come back -- not be swallowed into an empty page by
    # the defensive ``except`` (the symptom of the wrong-keyword TypeError).
    assert result.total == 1
    assert len(result.items) == 1
    assert result.items[0].id == str(row.id)
    assert result.items[0].organization_id == str(org_id)
    assert result.items[0].started_at == row.started_at

    # The org filter must reach GuestService under its real keyword, and the
    # "active" status filter must be coerced to the enum and forwarded.
    assert len(guest_service.calls) == 1
    call = guest_service.calls[0]
    assert call["requesting_organization_id"] == org_id
    assert call["status"] == GuestSessionStatus.ACTIVE


async def test_live_sessions_unknown_status_becomes_no_filter():
    org_id = uuid.uuid4()
    guest_service = _FakeGuestService(
        [
            _FakeGuestSession(
                id=uuid.uuid4(), organization_id=org_id, location_id=uuid.uuid4()
            )
        ]
    )
    service = LiveSessionService(guest_service=guest_service, rbac_service=None)

    await service.list_live_sessions(organization_id=org_id, status="not-a-real-status")

    assert guest_service.calls[0]["status"] is None


# ---------------------------------------------------------------------------
# Session actions: disconnect / pause / resume / extend
#
# All four called GuestService positionally against keyword-only signatures,
# so every one raised TypeError before reaching any logic. A bare
# `except Exception` turned that into `success=False`, and the router then
# wrapped it in a hardcoded `success=True` envelope -- so an operator
# disconnecting an abusive guest saw a clean success and the guest stayed
# online.
#
# These tests pin all three layers of that: the call must use keywords, the
# caller's identity and organization must be threaded through (for scoping
# and audit), and a failure must propagate rather than be swallowed.
# ---------------------------------------------------------------------------


class _RecordingGuestService:
    """Keyword-only, exactly like the real GuestService. A positional call
    raises TypeError here for the same reason it did in production."""

    def __init__(self, raises: Exception | None = None) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []
        self._raises = raises

    async def disconnect_session(self, *, session_id, **kw):
        return self._record("disconnect_session", session_id, kw)

    async def pause_session(self, *, session_id, **kw):
        return self._record("pause_session", session_id, kw)

    async def resume_session(self, *, session_id, **kw):
        return self._record("resume_session", session_id, kw)

    async def extend_session(self, *, session_id, **kw):
        return self._record("extend_session", session_id, kw)

    def _record(self, name, session_id, kw):
        self.calls.append((name, {"session_id": session_id, **kw}))
        if self._raises is not None:
            raise self._raises
        return object()


def _service(raises: Exception | None = None):
    guest_service = _RecordingGuestService(raises=raises)
    return (
        LiveSessionService(guest_service=guest_service, rbac_service=None),
        guest_service,
    )


async def test_disconnect_actually_reaches_the_guest_service():
    service, guest = _service()
    session_id, actor, org = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()

    result = await service.disconnect_session(
        session_id, actor_user_id=actor, requesting_organization_id=org
    )

    assert len(guest.calls) == 1, "the guest service was never called at all"
    name, kwargs = guest.calls[0]
    assert name == "disconnect_session"
    assert kwargs["session_id"] == session_id
    # Threaded through for tenant scoping and for the audit trail -- without
    # these the action is both unscoped and unattributable.
    assert kwargs["actor_user_id"] == actor
    assert kwargs["requesting_organization_id"] == org
    assert result.success is True


async def test_pause_resume_and_extend_reach_the_guest_service():
    session_id, actor, org = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()

    for method, expected in (
        ("pause_session", "pause_session"),
        ("resume_session", "resume_session"),
    ):
        service, guest = _service()
        await getattr(service, method)(
            session_id, actor_user_id=actor, requesting_organization_id=org
        )
        assert [c[0] for c in guest.calls] == [expected]
        assert guest.calls[0][1]["requesting_organization_id"] == org

    service, guest = _service()
    await service.extend_session(
        session_id, minutes=45, actor_user_id=actor, requesting_organization_id=org
    )
    name, kwargs = guest.calls[0]
    assert name == "extend_session"
    # The guest service's parameter is `additional_minutes`, not `minutes` --
    # passing the wrong name is the same class of bug as the positional call.
    assert kwargs["additional_minutes"] == 45


async def test_a_failed_disconnect_is_not_reported_as_success():
    """The whole point. A failure must propagate so the handler returns a
    real non-2xx -- not be swallowed into a response the router then wraps
    in `success=True`, which the frontend interceptor cannot see through."""
    service, _ = _service(raises=RuntimeError("device unreachable"))

    with pytest.raises(RuntimeError, match="device unreachable"):
        await service.disconnect_session(
            uuid.uuid4(),
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=uuid.uuid4(),
        )


def test_every_session_action_route_resolves_the_caller():
    """Structural guard: each action route must depend on CurrentUser and
    CurrentOrganization, or the service has nothing to scope or attribute
    the action with."""
    from app.domains.rbac.dependencies import CurrentOrganization, CurrentUser
    from app.main import create_app

    app = create_app()

    def calls(dependant):
        found = {d.call for d in dependant.dependencies}
        for d in dependant.dependencies:
            found |= calls(d)
        return found

    for action in ("disconnect", "pause", "resume", "extend"):
        path = f"/api/v1/sessions/{{session_id}}/{action}"
        route = next(
            r
            for r in app.routes
            if getattr(r, "path", None) == path
            and "POST" in getattr(r, "methods", set())
        )
        resolved = calls(route.dependant)
        assert CurrentUser in resolved, f"{action} does not resolve the actor"
        assert CurrentOrganization in resolved, f"{action} is unscoped"


# ---------------------------------------------------------------------------
# The connected-guest row must carry real data, or say it has none
# ---------------------------------------------------------------------------
#
# Every field below was previously read with `getattr(session, "<name>",
# <default>)` for a name that does not exist on `GuestSession`. The defaults
# rendered a complete-looking row: session length always 0, MAC/SSID/NAS/
# router always "", username the session's own UUID. `/how-it-works` sells
# this screen as "who's on, which device, for how long, and how much data
# used", so each of these is a shipped claim.


async def test_session_time_is_derived_from_started_at_not_a_zero_default():
    """The "for how long" column. `session_duration_seconds` is not a column
    on `GuestSession`, so this was 0 for every session ever listed."""
    org_id = uuid.uuid4()
    started = datetime.now(UTC) - timedelta(minutes=42)
    row = _FakeGuestSession(
        id=uuid.uuid4(),
        organization_id=org_id,
        location_id=uuid.uuid4(),
        started_at=started,
    )
    service = LiveSessionService(
        guest_service=_FakeGuestService([row]), rbac_service=None
    )

    result = await service.list_live_sessions(organization_id=org_id)

    assert result.items[0].session_time_seconds == pytest.approx(42 * 60, abs=5)


async def test_a_finished_session_measures_to_its_end_not_to_now():
    org_id = uuid.uuid4()
    started = datetime.now(UTC) - timedelta(hours=3)
    row = _FakeGuestSession(
        id=uuid.uuid4(),
        organization_id=org_id,
        location_id=uuid.uuid4(),
        started_at=started,
        ended_at=started + timedelta(minutes=10),
    )
    service = LiveSessionService(
        guest_service=_FakeGuestService([row]), rbac_service=None
    )

    result = await service.list_live_sessions(organization_id=org_id)

    assert result.items[0].session_time_seconds == 600


async def test_mac_comes_from_the_guest_device_row():
    """"which device". MAC lives on `GuestDevice`, reachable through the
    session's `device_id` -- never on `GuestSession` itself."""
    org_id = uuid.uuid4()
    device_id = uuid.uuid4()
    row = _FakeGuestSession(
        id=uuid.uuid4(),
        organization_id=org_id,
        location_id=uuid.uuid4(),
        device_id=device_id,
    )
    guest_service = _FakeGuestService(
        [row], devices=[_FakeGuestDevice(id=device_id, mac_address="AA:BB:CC:DD:EE:FF")]
    )
    service = LiveSessionService(guest_service=guest_service, rbac_service=None)

    result = await service.list_live_sessions(organization_id=org_id)

    assert result.items[0].mac == "AA:BB:CC:DD:EE:FF"


async def test_a_session_with_no_device_reports_no_mac_rather_than_empty_string():
    org_id = uuid.uuid4()
    row = _FakeGuestSession(
        id=uuid.uuid4(), organization_id=org_id, location_id=uuid.uuid4()
    )
    service = LiveSessionService(
        guest_service=_FakeGuestService([row]), rbac_service=None
    )

    result = await service.list_live_sessions(organization_id=org_id)

    assert result.items[0].mac is None


async def test_username_is_never_the_session_uuid():
    """It used to fall back to `str(session.id)`, so the UI showed a UUID as a
    guest's name. The real identifier is PII and only ever leaves through a
    `MaskedIdentifier`-annotated field."""
    org_id = uuid.uuid4()
    row = _FakeGuestSession(
        id=uuid.uuid4(), organization_id=org_id, location_id=uuid.uuid4()
    )
    service = LiveSessionService(
        guest_service=_FakeGuestService([row]), rbac_service=None
    )

    result = await service.list_live_sessions(organization_id=org_id)

    assert result.items[0].username != str(row.id)
    assert result.items[0].username is None
    assert result.items[0].guest_id == str(row.guest_id)


async def test_a_failing_query_raises_instead_of_reporting_an_empty_venue():
    """The most dangerous line in the old adapter: a bare `except Exception`
    turned any failure into `items=[], total=0` -- "nobody is online" -- on
    the one screen an operator opens to find out who is online."""

    class _ExplodingGuestService:
        async def list_sessions(self, **_kwargs):
            raise RuntimeError("database is unreachable")

    service = LiveSessionService(
        guest_service=_ExplodingGuestService(), rbac_service=None
    )

    with pytest.raises(RuntimeError):
        await service.list_live_sessions(organization_id=uuid.uuid4())


async def test_total_is_the_matching_row_count_not_the_page_length():
    """`total=len(sessions)` told the client every result fit on one page."""
    org_id = uuid.uuid4()
    rows = [
        _FakeGuestSession(
            id=uuid.uuid4(), organization_id=org_id, location_id=uuid.uuid4()
        )
        for _ in range(3)
    ]
    guest_service = _FakeGuestService(rows)
    guest_service.total_override = 57
    service = LiveSessionService(guest_service=guest_service, rbac_service=None)

    result = await service.list_live_sessions(organization_id=org_id, page_size=3)

    assert result.total == 57
    assert len(result.items) == 3
