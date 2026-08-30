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
