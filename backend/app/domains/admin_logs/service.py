"""Admin Logs business logic: two real, organization-scoped log
categories, each composed through a narrow, duck-typed Protocol
satisfied structurally by a real, already-existing service -- the
identical composition-over-duplication pattern
``app.domains.controller_logs.service`` already establishes. Nothing
here ever queries another domain's own table directly.

## Dashboard Logins: an org-membership filter over a platform-wide table

``LoginAttempt`` (``app.domains.auth.models``) has no ``organization_id``
column at all -- a login attempt is recorded by email/IP, not scoped to
one organization (see ``app.domains.auth.repository``'s own
``list_login_attempts`` docstring). Scoping "this organization's own
dashboard logins" therefore means resolving the organization's own
active member user ids first (via
``app.domains.organization.service.OrganizationService.list_members``)
and filtering ``login_attempts`` down to just those rows -- the
``user_ids`` seam added to ``AuthRepository.list_login_attempts``
specifically for this. An organization with no active members returns an
empty page without ever querying ``login_attempts`` at all (there is
nothing a ``user_id IN ()`` filter could ever match).

## Router Logs: a real, bounded fan-out across every location a router lives at

There is no single "router events for this whole organization" query
anywhere in this codebase -- ``app.domains.router_provisioning``'s own
``list_events`` is per-router. This composes
``app.domains.location.service.LocationService.list_locations`` +
``app.domains.router.service.RouterService.list_routers`` +
``RouterProvisioningService.list_events`` into one location-wide merge,
each router's events tagged with which location/router they came from
(see ``RouterLogRow``) -- real, bounded fan-out (``constants.py``'s own
``MAX_*_FOR_ROUTER_LOG_MERGE`` values), the same "merge, sort, paginate
in Python" shape ``ControllerLogsService.list_provision_logs`` already
uses for its own cross-job merge.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Protocol

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.organization.enums import MembershipStatus

from .constants import (
    MAX_EVENTS_PER_ROUTER_FOR_ROUTER_LOG_MERGE,
    MAX_LOCATIONS_FOR_ROUTER_LOG_MERGE,
    MAX_ROUTERS_PER_LOCATION_FOR_ROUTER_LOG_MERGE,
)


class OrganizationMemberLookupProtocol(Protocol):
    async def list_members(
        self,
        organization_id: uuid.UUID,
        *,
        status: MembershipStatus | None = None,
    ) -> list: ...


class DashboardLoginLookupProtocol(Protocol):
    async def list_login_attempts(
        self,
        *,
        user_ids: list[uuid.UUID] | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list, object]: ...


class LocationLookupProtocol(Protocol):
    async def list_locations(
        self,
        *,
        organization_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list, object]: ...


class RouterLookupProtocol(Protocol):
    async def list_routers(
        self,
        *,
        location_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list, object]: ...


class RouterEventLookupProtocol(Protocol):
    async def list_events(
        self,
        *,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list, object]: ...


@dataclass(frozen=True, slots=True)
class RouterLogRow:
    """One real ``RouterEvent`` paired with the location/router it came
    from -- ``RouterEvent`` itself carries only ``router_id``, so the
    merge step (the only place that already walked
    location -> router -> events) is what has the names/ids to attach."""

    event: object
    location_id: uuid.UUID
    location_name: str
    router_id: uuid.UUID
    router_name: str


class AdminLogsService:
    """Core Admin Logs business logic -- see module docstring."""

    def __init__(
        self,
        member_lookup: OrganizationMemberLookupProtocol,
        login_attempt_lookup: DashboardLoginLookupProtocol,
        location_lookup: LocationLookupProtocol,
        router_lookup: RouterLookupProtocol,
        router_event_lookup: RouterEventLookupProtocol,
    ) -> None:
        self.member_lookup = member_lookup
        self.login_attempt_lookup = login_attempt_lookup
        self.location_lookup = location_lookup
        self.router_lookup = router_lookup
        self.router_event_lookup = router_event_lookup

    async def list_dashboard_logins(
        self,
        *,
        organization_id: uuid.UUID,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list, PaginationMeta]:
        members = await self.member_lookup.list_members(
            organization_id, status=MembershipStatus.ACTIVE
        )
        member_user_ids = [m.user_id for m in members if m.user_id is not None]
        if not member_user_ids:
            params = PageParams(page=page, page_size=page_size)
            return [], PaginationMeta.from_total(params, 0)
        return await self.login_attempt_lookup.list_login_attempts(
            user_ids=member_user_ids, page=page, page_size=page_size
        )

    async def list_router_error_logs(
        self,
        *,
        organization_id: uuid.UUID,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[RouterLogRow], PaginationMeta]:
        locations, _ = await self.location_lookup.list_locations(
            organization_id=organization_id,
            requesting_organization_id=organization_id,
            page=1,
            page_size=MAX_LOCATIONS_FOR_ROUTER_LOG_MERGE,
        )
        merged: list[RouterLogRow] = []
        for location in locations:
            routers, _ = await self.router_lookup.list_routers(
                location_id=location.id,
                requesting_organization_id=organization_id,
                page=1,
                page_size=MAX_ROUTERS_PER_LOCATION_FOR_ROUTER_LOG_MERGE,
            )
            for router in routers:
                events, _ = await self.router_event_lookup.list_events(
                    router_id=router.id,
                    requesting_organization_id=organization_id,
                    page=1,
                    page_size=MAX_EVENTS_PER_ROUTER_FOR_ROUTER_LOG_MERGE,
                )
                merged.extend(
                    RouterLogRow(
                        event=event,
                        location_id=location.id,
                        location_name=location.name,
                        router_id=router.id,
                        router_name=router.name,
                    )
                    for event in events
                )
        merged.sort(key=lambda row: row.event.occurred_at, reverse=True)
        params = PageParams(page=page, page_size=page_size)
        paged = merged[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(merged))


__all__ = [
    "OrganizationMemberLookupProtocol",
    "DashboardLoginLookupProtocol",
    "LocationLookupProtocol",
    "RouterLookupProtocol",
    "RouterEventLookupProtocol",
    "RouterLogRow",
    "AdminLogsService",
]
