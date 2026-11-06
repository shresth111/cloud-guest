"""``DELETE /locations/{id}`` refuses while routers are still attached.

Archiving only soft-deletes the location row. The routers kept their
tunnel, RADIUS client and hotspot config and kept serving guests from a
location that no screen showed any more. The route now counts the
location's non-decommissioned routers first and answers ``409``.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from app.domains.location.exceptions import LocationHasRoutersError
from app.domains.location.router import archive_location


class FakeRouterService:
    def __init__(self, total: int) -> None:
        self.total = total
        self.calls: list[dict[str, object]] = []

    async def list_routers(self, **kwargs: object):
        self.calls.append(kwargs)
        return [], SimpleNamespace(total_items=self.total)


class FakeLocationService:
    def __init__(self) -> None:
        self.archived: list[uuid.UUID] = []

    async def archive_location(self, *, actor_user_id, location_id, **_: object):
        self.archived.append(location_id)


def _request() -> SimpleNamespace:
    return SimpleNamespace(state=SimpleNamespace())


def _user() -> SimpleNamespace:
    return SimpleNamespace(id=str(uuid.uuid4()))


async def test_refuses_when_routers_are_attached() -> None:
    location_id = uuid.uuid4()
    org_id = uuid.uuid4()
    routers = FakeRouterService(total=2)
    locations = FakeLocationService()
    with pytest.raises(LocationHasRoutersError) as exc:
        await archive_location(
            request=_request(),
            location_id=location_id,
            user=_user(),
            requesting_organization_id=org_id,
            location_service=locations,
            router_service=routers,
        )
    assert exc.value.status_code == 409
    assert "2 routers are still attached" in str(exc.value)
    assert locations.archived == []
    # The count is scoped through the caller's own organization.
    assert routers.calls[0]["location_id"] == location_id
    assert routers.calls[0]["requesting_organization_id"] == org_id


async def test_archives_when_no_router_is_attached() -> None:
    location_id = uuid.uuid4()
    locations = FakeLocationService()
    response = await archive_location(
        request=_request(),
        location_id=location_id,
        user=_user(),
        requesting_organization_id=None,
        location_service=locations,
        router_service=FakeRouterService(total=0),
    )
    assert locations.archived == [location_id]
    assert response is not None
