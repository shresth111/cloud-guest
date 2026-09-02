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
from datetime import UTC, datetime

import pytest

from app.domains.guest.constants import GuestSessionStatus
from app.domains.live_sessions.service import LiveSessionService


@dataclass
class _FakeGuestSession:
    """Minimal stand-in exposing only the attributes the live-session adapter
    reads off a real ``GuestSession`` row."""

    id: uuid.UUID
    organization_id: uuid.UUID
    location_id: uuid.UUID
    status: str = GuestSessionStatus.ACTIVE.value
    ip_address: str = "10.0.0.5"
    user_agent: str = "Mozilla/5.0"
    bytes_downloaded: int = 4096
    bytes_uploaded: int = 1024
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))


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

    def __init__(self, rows: list[_FakeGuestSession]) -> None:
        self._rows = rows
        self.calls: list[dict[str, object]] = []

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
        return rows, _FakeMeta(total_items=len(rows))


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
