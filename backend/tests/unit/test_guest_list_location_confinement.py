"""An unfiltered guest listing must still be confined to the caller's sites.

``enforce_target_location`` compares a *named* location against the location
the permission check ran against. When the request names no location at all
(``GET /guests`` with no ``location_id``) it has nothing to compare and passes
through -- by design, since the dashboard lists guests without a filter. The
confinement for that case has to come from somewhere else, and before this
file it came from nowhere: the service filtered on organization only, so a
caller whose grant covers one site listed every site's guests.

The confinement is derived from the caller's role assignments
(``app.domains.rbac.location_scope.CallerLocationScope``), the same value
``GuestService._require_guest`` already applies to guest-by-id reads. The
listings now apply it too.

Every behaviour is checked for all three actor kinds, because the failure
this must never produce is locking an organization or platform caller out:

* LOCATION-scoped, one site  -> that site's rows only;
* LOCATION-scoped, two sites -> exactly those two sites' rows;
* explicit foreign ``location_id`` -> 403;
* ORGANIZATION / GLOBAL -> unchanged (every site in the organization).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from app.domains.guest.exceptions import CrossLocationGuestAccessError
from app.domains.guest.models import Guest, GuestLoginHistory, GuestSession
from app.domains.guest.router import list_guests as list_guests_route
from app.domains.guest.service import GuestService
from app.domains.location.exceptions import CrossLocationScopeAccessError
from app.domains.rbac.enums import ScopeType
from app.domains.rbac.location_scope import CallerLocationScope

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


def _matches(row: object, filters: dict[str, object] | None) -> bool:
    """``apply_filters`` semantics: a list/tuple/set is ``IN``, else ``==``."""
    for key, value in (filters or {}).items():
        if value is None:
            continue
        actual = getattr(row, key)
        if isinstance(value, list | tuple | set):
            if actual not in value:
                return False
        elif actual != value:
            return False
    return True


def _location_matches(row: object, location_id: object) -> bool:
    if location_id is None:
        return True
    if isinstance(location_id, list | tuple | set | frozenset):
        return row.location_id in location_id
    return row.location_id == location_id


def _meta(total: int, page: int = 1, page_size: int = 25) -> SimpleNamespace:
    return SimpleNamespace(
        page=page,
        page_size=page_size,
        total_items=total,
        total_pages=1,
        has_next=False,
        has_previous=False,
    )


class _Repo:
    def __init__(self) -> None:
        self.guests: list[Guest] = []
        self.sessions: list[GuestSession] = []
        self.login_history: list[GuestLoginHistory] = []

    async def list_guests(self, *, page, page_size, filters=None, search=None, **_):
        items = [g for g in self.guests if _matches(g, filters)]
        return items, _meta(len(items), page, page_size)

    async def list_devices_for_guest_ids(self, *, guest_ids, organization_id):
        return []

    async def list_sessions(self, *, page, page_size, filters=None, **_):
        items = [s for s in self.sessions if _matches(s, filters)]
        return items, _meta(len(items), page, page_size)

    async def list_sessions_in_range(
        self, *, organization_id, location_id, start, end, page, page_size
    ):
        items = [
            s
            for s in self.sessions
            if s.organization_id == organization_id
            and start <= s.started_at < end
            and _location_matches(s, location_id)
        ]
        return items, _meta(len(items), page, page_size)

    async def list_login_history(
        self, *, organization_id, location_id=None, guest_id=None, page, page_size
    ):
        items = [
            e
            for e in self.login_history
            if (organization_id is None or e.organization_id == organization_id)
            and _location_matches(e, location_id)
        ]
        return items, _meta(len(items), page, page_size)

    async def list_login_history_in_range(
        self, *, organization_id, location_id, start, end, page, page_size
    ):
        items = [
            e
            for e in self.login_history
            if e.organization_id == organization_id
            and start <= e.attempted_at < end
            and _location_matches(e, location_id)
        ]
        return items, _meta(len(items), page, page_size)


class _RbacRepo:
    """What ``RoleResolver.get_active_assignments`` reads."""

    def __init__(self, rows) -> None:
        self._rows = rows

    async def get_active_user_roles(self, user_id, *, now=None):
        return self._rows


def _assignment(scope_type: ScopeType, *, organization_id=None, location_id=None):
    return SimpleNamespace(
        scope_type=scope_type.value,
        organization_id=organization_id,
        location_id=location_id,
        router_id=None,
        role=SimpleNamespace(is_active=True, is_deleted=False),
    )


# ---------------------------------------------------------------------------
# World: one organization, three sites, one guest (and session, and login
# attempt) at each.
# ---------------------------------------------------------------------------

NOW = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)


class _World:
    def __init__(self) -> None:
        self.org = uuid.uuid4()
        self.site_a = uuid.uuid4()
        self.site_b = uuid.uuid4()
        self.site_c = uuid.uuid4()
        self.repo = _Repo()
        for index, site in enumerate((self.site_a, self.site_b, self.site_c)):
            guest = Guest(
                id=uuid.uuid4(),
                organization_id=self.org,
                location_id=site,
                identifier=f"+1555000000{index}",
                display_name=None,
                first_seen_at=NOW,
                last_seen_at=NOW,
                total_visit_count=1,
                is_blocked=False,
                blocked_reason=None,
                created_at=NOW,
                updated_at=NOW,
            )
            self.repo.guests.append(guest)
            self.repo.sessions.append(
                GuestSession(
                    id=uuid.uuid4(),
                    guest_id=guest.id,
                    organization_id=self.org,
                    location_id=site,
                    started_at=NOW - timedelta(minutes=5),
                )
            )
            self.repo.login_history.append(
                GuestLoginHistory(
                    id=uuid.uuid4(),
                    guest_id=guest.id,
                    organization_id=self.org,
                    location_id=site,
                    attempted_at=NOW - timedelta(minutes=5),
                )
            )

    async def service_for(self, *assignments) -> GuestService:
        scope = await CallerLocationScope(
            user=SimpleNamespace(id=str(uuid.uuid4())),
            repository=_RbacRepo(list(assignments)),
        )
        return GuestService(
            self.repo,
            otp_service=None,
            voucher_service=None,
            captive_portal_service=None,
            router_lookup=None,
            caller_location_scope=scope,
        )

    async def location_caller(self, *sites) -> GuestService:
        return await self.service_for(
            *(
                _assignment(ScopeType.LOCATION, organization_id=self.org, location_id=s)
                for s in sites
            )
        )

    async def organization_caller(self) -> GuestService:
        return await self.service_for(
            _assignment(ScopeType.ORGANIZATION, organization_id=self.org)
        )

    async def platform_caller(self) -> GuestService:
        return await self.service_for(_assignment(ScopeType.GLOBAL))


def _sites(rows) -> set[uuid.UUID]:
    return {r.location_id for r in rows}


# ---------------------------------------------------------------------------
# GET /guests -- through the real route handler
# ---------------------------------------------------------------------------


async def _call_list_guests_route(
    service: GuestService,
    *,
    organization_id: uuid.UUID | None,
    scope_location_id: uuid.UUID | None,
    location_id: uuid.UUID | None = None,
) -> set[str]:
    response = await list_guests_route(
        request=SimpleNamespace(state=SimpleNamespace(request_id="t")),
        page=1,
        page_size=25,
        location_id=location_id,
        is_blocked=None,
        search=None,
        requesting_organization_id=organization_id,
        scope_location_id=scope_location_id,
        service=service,
    )
    body = response if isinstance(response, dict) else response.model_dump()
    return {item["location_id"] for item in body["data"]["items"]}


class TestListGuestsRoute:
    async def test_single_site_caller_without_a_filter_sees_only_their_site(
        self,
    ) -> None:
        """The reported leak. The caller's only grant is LOCATION on site A;
        they send their own ``X-Location-Id`` (so the permission check passes)
        and no ``location_id`` filter. They must not receive sites B and C."""
        world = _World()
        service = await world.location_caller(world.site_a)

        seen = await _call_list_guests_route(
            service, organization_id=world.org, scope_location_id=world.site_a
        )

        assert seen == {str(world.site_a)}

    async def test_organization_caller_still_sees_every_site(self) -> None:
        world = _World()
        service = await world.organization_caller()

        seen = await _call_list_guests_route(
            service, organization_id=world.org, scope_location_id=None
        )

        assert seen == {str(s) for s in (world.site_a, world.site_b, world.site_c)}

    async def test_organization_caller_viewing_one_site_is_not_narrowed_to_it(
        self,
    ) -> None:
        """``X-Location-Id`` is what the admin is looking at, not what they are
        entitled to. Narrowing on it would be the lockout failure."""
        world = _World()
        service = await world.organization_caller()

        seen = await _call_list_guests_route(
            service, organization_id=world.org, scope_location_id=world.site_a
        )

        assert seen == {str(s) for s in (world.site_a, world.site_b, world.site_c)}

    async def test_platform_caller_still_sees_every_site(self) -> None:
        world = _World()
        service = await world.platform_caller()

        seen = await _call_list_guests_route(
            service, organization_id=world.org, scope_location_id=None
        )

        assert seen == {str(s) for s in (world.site_a, world.site_b, world.site_c)}

    async def test_explicit_foreign_location_is_refused(self) -> None:
        """Either guard may be the one to say no -- the header-vs-query guard
        in the route, or the grant-derived confinement in the service -- but
        it must be a 403."""
        world = _World()
        service = await world.location_caller(world.site_a)

        with pytest.raises(
            (CrossLocationGuestAccessError, CrossLocationScopeAccessError)
        ) as exc_info:
            await _call_list_guests_route(
                service,
                organization_id=world.org,
                scope_location_id=world.site_a,
                location_id=world.site_b,
            )
        assert exc_info.value.status_code == 403

    async def test_explicit_own_location_is_allowed(self) -> None:
        world = _World()
        service = await world.location_caller(world.site_a)

        seen = await _call_list_guests_route(
            service,
            organization_id=world.org,
            scope_location_id=world.site_a,
            location_id=world.site_a,
        )

        assert seen == {str(world.site_a)}


# ---------------------------------------------------------------------------
# The service layer -- every listing, not just the one that was reported
# ---------------------------------------------------------------------------


class TestListGuestsService:
    async def test_multi_site_caller_sees_exactly_their_sites(self) -> None:
        world = _World()
        service = await world.location_caller(world.site_a, world.site_c)

        guests, meta = await service.list_guests(requesting_organization_id=world.org)

        assert _sites(guests) == {world.site_a, world.site_c}
        assert meta.total_items == 2

    async def test_multi_site_caller_may_filter_to_either_of_their_sites(
        self,
    ) -> None:
        world = _World()
        service = await world.location_caller(world.site_a, world.site_c)

        guests, _ = await service.list_guests(
            requesting_organization_id=world.org, location_id=world.site_c
        )

        assert _sites(guests) == {world.site_c}

    async def test_multi_site_caller_is_refused_a_third_site(self) -> None:
        world = _World()
        service = await world.location_caller(world.site_a, world.site_c)

        with pytest.raises(CrossLocationGuestAccessError):
            await service.list_guests(
                requesting_organization_id=world.org, location_id=world.site_b
            )


class TestSessionAndLoginHistoryListings:
    """The same listings carry the same guest identifiers (phone/email)."""

    @pytest.mark.parametrize("method", ["list_sessions", "list_login_history"])
    async def test_unfiltered_listing_is_confined(self, method: str) -> None:
        world = _World()
        service = await world.location_caller(world.site_a)

        rows, _ = await getattr(service, method)(requesting_organization_id=world.org)

        assert _sites(rows) == {world.site_a}

    @pytest.mark.parametrize(
        "method", ["list_sessions_in_range", "list_login_history_in_range"]
    )
    async def test_unfiltered_ranged_listing_is_confined(self, method: str) -> None:
        world = _World()
        service = await world.location_caller(world.site_a, world.site_b)

        rows, _ = await getattr(service, method)(
            organization_id=world.org,
            start=NOW - timedelta(hours=1),
            end=NOW,
        )

        assert _sites(rows) == {world.site_a, world.site_b}

    @pytest.mark.parametrize(
        ("method", "kwargs"),
        [
            ("list_sessions", {"requesting_organization_id": None}),
            ("list_login_history", {"requesting_organization_id": None}),
            (
                "list_sessions_in_range",
                {"start": NOW - timedelta(hours=1), "end": NOW},
            ),
            (
                "list_login_history_in_range",
                {"start": NOW - timedelta(hours=1), "end": NOW},
            ),
        ],
    )
    async def test_foreign_location_filter_is_refused(self, method, kwargs) -> None:
        world = _World()
        service = await world.location_caller(world.site_a)
        if "start" in kwargs:
            kwargs = {**kwargs, "organization_id": world.org}
        else:
            kwargs = {**kwargs, "requesting_organization_id": world.org}

        with pytest.raises(CrossLocationGuestAccessError):
            await getattr(service, method)(location_id=world.site_b, **kwargs)

    @pytest.mark.parametrize("method", ["list_sessions", "list_login_history"])
    async def test_organization_caller_is_unconfined(self, method: str) -> None:
        world = _World()
        service = await world.organization_caller()

        rows, _ = await getattr(service, method)(requesting_organization_id=world.org)

        assert _sites(rows) == {world.site_a, world.site_b, world.site_c}

    @pytest.mark.parametrize(
        "method", ["list_sessions_in_range", "list_login_history_in_range"]
    )
    async def test_organization_caller_ranged_is_unconfined(self, method) -> None:
        world = _World()
        service = await world.organization_caller()

        rows, _ = await getattr(service, method)(
            organization_id=world.org,
            start=NOW - timedelta(hours=1),
            end=NOW,
        )

        assert _sites(rows) == {world.site_a, world.site_b, world.site_c}


class TestCallerWithNoSites:
    async def test_a_location_confined_caller_with_no_sites_sees_nothing(
        self,
    ) -> None:
        """An empty confinement set means "no site", never "every site". A
        frozenset that is falsy must not be read as "unconfined"."""
        world = _World()
        service = await world.service_for()

        guests, _ = await service.list_guests(requesting_organization_id=world.org)

        assert guests == []


class TestNasListing:
    """``GET /radius/nas`` shares the listing shape and the guard."""

    async def _service(self, scope):
        from app.domains.guest.service import RadiusService

        world = _World()
        nas_rows = [
            SimpleNamespace(organization_id=world.org, location_id=site)
            for site in (world.site_a, world.site_b, world.site_c)
        ]

        class _NasRepo:
            async def list_nas_clients(self, *, page, page_size, filters=None, **_):
                items = [n for n in nas_rows if _matches(n, filters)]
                return items, _meta(len(items), page, page_size)

        confinement = scope(world)
        service = RadiusService(
            _NasRepo(), None, None, None, None, caller_location_scope=confinement
        )
        return world, service

    async def test_location_caller_is_confined(self) -> None:
        world, service = await self._service(lambda w: frozenset({w.site_b}))

        rows, _ = await service.list_nas_clients(requesting_organization_id=world.org)

        assert _sites(rows) == {world.site_b}

    async def test_foreign_location_is_refused(self) -> None:
        world, service = await self._service(lambda w: frozenset({w.site_b}))

        with pytest.raises(CrossLocationGuestAccessError):
            await service.list_nas_clients(
                requesting_organization_id=world.org, location_id=world.site_a
            )

    async def test_organization_caller_is_unconfined(self) -> None:
        world, service = await self._service(lambda w: None)

        rows, _ = await service.list_nas_clients(requesting_organization_id=world.org)

        assert _sites(rows) == {world.site_a, world.site_b, world.site_c}
