"""Unit tests for the Admin Logs domain: the customer dashboard's
"Admin Logs" page -- an organization-membership-filtered view over the
real ``login_attempts`` table (Dashboard Logins) and a real, bounded
location -> router -> event merge (Router Logs), plus a structural RBAC
check that every route requires the Owner-only dependency trio
(permission + role + entitlement).

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_controller_logs.py``); ``AdminLogsService`` is
exercised against small, hand-rolled in-memory fakes for each of its five
composed Protocols -- mirrors ``test_controller_logs.py``'s own identical
"fake the narrow Protocol boundary" precedent.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.admin_logs.constants import ERROR_EVENT_TYPES
from app.domains.admin_logs.router import router as admin_logs_router
from app.domains.admin_logs.service import AdminLogsService
from app.domains.organization.enums import MembershipStatus
from app.domains.router_provisioning.constants import RouterEventType


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass
class _Member:
    user_id: uuid.UUID = field(default_factory=uuid.uuid4)
    status: str = "active"


@dataclass
class _LoginAttempt:
    id: uuid.UUID = field(default_factory=uuid.uuid4)
    user_id: uuid.UUID | None = None
    email: str = "owner@example.com"
    created_at: datetime = field(default_factory=_now)


@dataclass
class _Location:
    id: uuid.UUID = field(default_factory=uuid.uuid4)
    name: str = "Sector 12"


@dataclass
class _Router:
    id: uuid.UUID = field(default_factory=uuid.uuid4)
    name: str = "mikrotik-1"


@dataclass
class _RouterEvent:
    id: uuid.UUID = field(default_factory=uuid.uuid4)
    event_type: str = RouterEventType.CONFIG_VERSION_DRAFTED.value
    message: str | None = None
    occurred_at: datetime = field(default_factory=_now)


class FakeMemberLookup:
    def __init__(self, members: list[_Member]) -> None:
        self.members = members
        self.calls: list[dict[str, object]] = []

    async def list_members(
        self, organization_id: uuid.UUID, *, status: MembershipStatus | None = None
    ) -> list[_Member]:
        self.calls.append({"organization_id": organization_id, "status": status})
        return self.members


class FakeLoginAttemptLookup:
    def __init__(self, attempts: list[_LoginAttempt]) -> None:
        self.attempts = attempts
        self.calls: list[dict[str, object]] = []

    async def list_login_attempts(
        self,
        *,
        user_ids: list[uuid.UUID] | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[_LoginAttempt], PaginationMeta]:
        self.calls.append({"user_ids": user_ids, "page": page, "page_size": page_size})
        matched = (
            [a for a in self.attempts if user_ids is not None and a.user_id in user_ids]
            if user_ids
            else self.attempts
        )
        params = PageParams(page=page, page_size=page_size)
        paged = matched[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(matched))


class FakeLocationLookup:
    def __init__(self, locations: list[_Location]) -> None:
        self.locations = locations

    async def list_locations(
        self,
        *,
        organization_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[_Location], PaginationMeta]:
        params = PageParams(page=page, page_size=page_size)
        return self.locations, PaginationMeta.from_total(params, len(self.locations))


class FakeRouterLookup:
    def __init__(self, routers_by_location: dict[uuid.UUID, list[_Router]]) -> None:
        self.routers_by_location = routers_by_location

    async def list_routers(
        self,
        *,
        location_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[_Router], PaginationMeta]:
        routers = self.routers_by_location.get(location_id, [])
        params = PageParams(page=page, page_size=page_size)
        return routers, PaginationMeta.from_total(params, len(routers))


class FakeRouterEventLookup:
    def __init__(self, events_by_router: dict[uuid.UUID, list[_RouterEvent]]) -> None:
        self.events_by_router = events_by_router
        self.calls: list[dict[str, object]] = []

    async def list_events(
        self,
        *,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[_RouterEvent], PaginationMeta]:
        self.calls.append(
            {
                "router_id": router_id,
                "requesting_organization_id": requesting_organization_id,
            }
        )
        events = self.events_by_router.get(router_id, [])
        params = PageParams(page=page, page_size=page_size)
        return events, PaginationMeta.from_total(params, len(events))


def _make_service(
    *,
    members: list[_Member] | None = None,
    login_attempts: list[_LoginAttempt] | None = None,
    locations: list[_Location] | None = None,
    routers_by_location: dict[uuid.UUID, list[_Router]] | None = None,
    events_by_router: dict[uuid.UUID, list[_RouterEvent]] | None = None,
) -> tuple[AdminLogsService, dict[str, object]]:
    fakes = {
        "members": FakeMemberLookup(members or []),
        "logins": FakeLoginAttemptLookup(login_attempts or []),
        "locations": FakeLocationLookup(locations or []),
        "routers": FakeRouterLookup(routers_by_location or {}),
        "events": FakeRouterEventLookup(events_by_router or {}),
    }
    service = AdminLogsService(
        fakes["members"],
        fakes["logins"],
        fakes["locations"],
        fakes["routers"],
        fakes["events"],
    )
    return service, fakes


# ============================================================================
# Dashboard Logins -- org-membership-filtered
# ============================================================================


class TestListDashboardLogins:
    async def test_filters_login_attempts_to_the_organizations_own_active_members(
        self,
    ) -> None:
        owner_id = uuid.uuid4()
        outsider_id = uuid.uuid4()
        owner_attempt = _LoginAttempt(user_id=owner_id, email="owner@xyz.com")
        outsider_attempt = _LoginAttempt(
            user_id=outsider_id, email="outsider@other.com"
        )
        service, fakes = _make_service(
            members=[_Member(user_id=owner_id)],
            login_attempts=[owner_attempt, outsider_attempt],
        )
        entries, meta = await service.list_dashboard_logins(
            organization_id=uuid.uuid4()
        )
        assert [e.id for e in entries] == [owner_attempt.id]
        assert meta.total_items == 1
        assert fakes["logins"].calls[0]["user_ids"] == [owner_id]

    async def test_requests_only_active_members(self) -> None:
        service, fakes = _make_service(members=[])
        await service.list_dashboard_logins(organization_id=uuid.uuid4())
        assert fakes["members"].calls[0]["status"] == MembershipStatus.ACTIVE

    async def test_no_active_members_returns_empty_without_querying_logins(
        self,
    ) -> None:
        service, fakes = _make_service(
            members=[], login_attempts=[_LoginAttempt(user_id=uuid.uuid4())]
        )
        entries, meta = await service.list_dashboard_logins(
            organization_id=uuid.uuid4()
        )
        assert entries == []
        assert meta.total_items == 0
        assert fakes["logins"].calls == []

    async def test_paginates_results(self) -> None:
        owner_id = uuid.uuid4()
        attempts = [
            _LoginAttempt(user_id=owner_id, created_at=_now() - timedelta(minutes=i))
            for i in range(5)
        ]
        service, _ = _make_service(
            members=[_Member(user_id=owner_id)], login_attempts=attempts
        )
        entries, meta = await service.list_dashboard_logins(
            organization_id=uuid.uuid4(), page=2, page_size=2
        )
        assert len(entries) == 2
        assert meta.page == 2
        assert meta.total_items == 5


# ============================================================================
# Router Logs -- bounded location -> router -> event merge
# ============================================================================


class TestListRouterErrorLogs:
    async def test_merges_events_across_every_router_at_every_location_tagged_correctly(
        self,
    ) -> None:
        loc_a, loc_b = _Location(name="Coloba"), _Location(name="Sector 12")
        router_a, router_b = _Router(name="mikrotik-a"), _Router(name="mikrotik-b")
        older = _RouterEvent(occurred_at=_now() - timedelta(hours=1))
        newer = _RouterEvent(occurred_at=_now())
        service, _ = _make_service(
            locations=[loc_a, loc_b],
            routers_by_location={loc_a.id: [router_a], loc_b.id: [router_b]},
            events_by_router={router_a.id: [older], router_b.id: [newer]},
        )
        rows, meta = await service.list_router_error_logs(organization_id=uuid.uuid4())
        assert meta.total_items == 2
        assert [row.event.id for row in rows] == [newer.id, older.id]
        newest_row = rows[0]
        assert newest_row.location_id == loc_b.id
        assert newest_row.location_name == "Sector 12"
        assert newest_row.router_id == router_b.id
        assert newest_row.router_name == "mikrotik-b"

    async def test_a_location_with_no_routers_contributes_no_rows(self) -> None:
        loc = _Location()
        service, _ = _make_service(locations=[loc], routers_by_location={})
        rows, meta = await service.list_router_error_logs(organization_id=uuid.uuid4())
        assert rows == []
        assert meta.total_items == 0

    async def test_passes_the_organization_through_to_every_router_event_lookup(
        self,
    ) -> None:
        org_id = uuid.uuid4()
        loc = _Location()
        router = _Router()
        service, fakes = _make_service(
            locations=[loc],
            routers_by_location={loc.id: [router]},
            events_by_router={router.id: [_RouterEvent()]},
        )
        await service.list_router_error_logs(organization_id=org_id)
        assert fakes["events"].calls[0]["requesting_organization_id"] == org_id

    async def test_paginates_the_merged_result(self) -> None:
        loc = _Location()
        router = _Router()
        events = [
            _RouterEvent(occurred_at=_now() - timedelta(minutes=i)) for i in range(5)
        ]
        service, _ = _make_service(
            locations=[loc],
            routers_by_location={loc.id: [router]},
            events_by_router={router.id: events},
        )
        rows, meta = await service.list_router_error_logs(
            organization_id=uuid.uuid4(), page=2, page_size=2
        )
        assert len(rows) == 2
        assert meta.page == 2
        assert meta.total_items == 5


# ============================================================================
# Error classification
# ============================================================================


class TestErrorEventTypes:
    def test_failure_event_types_are_classified_as_errors(self) -> None:
        for failure in (
            RouterEventType.ENROLLMENT_REJECTED,
            RouterEventType.CONFIG_APPLY_FAILED,
            RouterEventType.RESTORE_FAILED,
            RouterEventType.FACTORY_RESET_FAILED,
        ):
            assert failure.value in ERROR_EVENT_TYPES

    def test_normal_lifecycle_event_types_are_not_classified_as_errors(self) -> None:
        for normal in (
            RouterEventType.ENROLLMENT_APPROVED,
            RouterEventType.CONFIG_APPLIED,
            RouterEventType.RESTORE_COMPLETED,
            RouterEventType.FACTORY_RESET_COMPLETED,
            RouterEventType.BACKUP_CREATED,
        ):
            assert normal.value not in ERROR_EVENT_TYPES


# ============================================================================
# RBAC -- every route requires the Owner-only dependency trio
# ============================================================================


class TestEveryRouteIsOwnerOnly:
    def test_every_admin_logs_route_requires_all_three_owner_only_dependencies(
        self,
    ) -> None:
        assert len(admin_logs_router.routes) == 2
        for route in admin_logs_router.routes:
            assert (
                len(route.dependencies) == 3
            ), f"{route.path} ({route.methods}) is missing an owner-only dependency"


__all__: list[str] = []
