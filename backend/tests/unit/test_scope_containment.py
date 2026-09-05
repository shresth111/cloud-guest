"""The scope a permission check runs against is the target's, not the caller's.

This is the root of the defect class the per-handler guards were compensating
for, and the reason a colleague found that a LOCATION-scoped account could run
``POST /network-diagnostics/routers/{router at another site}/ping`` -- command
execution on hardware at a site the caller has no grant on.

The mechanics of that bug, none of which involve the diagnostics domain:

1. the router id came from the path, so ``_infer_scope_type`` resolved ROUTER;
2. the location id came from the caller's own ``X-Location-Id`` header;
3. ``ScopeResolver.satisfies`` let a LOCATION grant satisfy a ROUTER check by
   comparing **only** ``location_id`` -- the caller's header against the
   caller's own grant.

Nothing about the router was ever checked. Cross-*tenant* was caught only
because ``RouterService._enforce_organization_scope`` happened to re-check it
at the service layer; cross-*site* within one tenant was not caught at all.

The fix is not to compare more ids in ``satisfies`` -- it had nothing truthful
to compare. It is to build the context from the entity being acted on, so
``location_id`` means "the location this router is actually at" rather than
"the location this caller says they are in". ``satisfies`` is then sound as
written.

These tests exercise the resolver directly and never touch
``network_diagnostics`` -- that endpoint is being fixed separately, and this
change lands underneath it.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from starlette.requests import Request

from app.domains.location.models import Location
from app.domains.rbac.authorization import ScopeResolver
from app.domains.rbac.context import GrantScope
from app.domains.rbac.dependencies import _current_scope_context
from app.domains.rbac.enums import ScopeType
from app.domains.router.models import Router


def _make_request(*, headers=None, path_params=None, query_string=b"") -> Request:
    raw_headers = [
        (k.lower().encode(), v.encode()) for k, v in (headers or {}).items()
    ]
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/",
        "headers": raw_headers,
        "query_string": query_string,
        "path_params": path_params or {},
    }
    return Request(scope)


class _FakeDb:
    """Stands in for the session, resolving containment the way ``db.get`` does."""

    def __init__(self, rows: dict) -> None:
        self._rows = rows
        self.gets: list[tuple] = []

    async def get(self, model, pk):
        self.gets.append((model.__name__, pk))
        return self._rows.get((model, pk))


def _router(router_id, *, location_id, organization_id):
    return SimpleNamespace(
        id=router_id, location_id=location_id, organization_id=organization_id
    )


class TestContextIsDerivedFromTheTarget:
    async def test_a_routers_location_overrides_the_callers_header(self) -> None:
        """The diagnostics bug, at the level it actually lives.

        The caller is at site A and names a router that sits at site B. The
        resolved context must say site B -- otherwise the check is the
        caller's header compared against the caller's own grant.
        """
        site_a, site_b, org = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        router_id = uuid.uuid4()
        db = _FakeDb(
            {
                (Router, router_id): _router(
                    router_id, location_id=site_b, organization_id=org
                )
            }
        )
        request = _make_request(
            headers={"X-Location-Id": str(site_a), "X-Organization-Id": str(org)},
            path_params={"router_id": str(router_id)},
        )

        context = await _current_scope_context(request, db)

        assert context.router_id == router_id
        assert context.location_id == site_b, "the caller's header won again"
        assert context.organization_id == org

    async def test_a_location_grant_no_longer_satisfies_a_foreign_routers_check(
        self,
    ) -> None:
        """End to end: resolve the context, then ask the real resolver."""
        site_a, site_b, org = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        router_id = uuid.uuid4()
        db = _FakeDb(
            {
                (Router, router_id): _router(
                    router_id, location_id=site_b, organization_id=org
                )
            }
        )
        request = _make_request(
            headers={"X-Location-Id": str(site_a)},
            path_params={"router_id": str(router_id)},
        )
        context = await _current_scope_context(request, db)

        grant_at_site_a = GrantScope(
            scope_type=ScopeType.LOCATION,
            organization_id=org,
            location_id=site_a,
            router_id=None,
        )

        assert not ScopeResolver.satisfies(grant_at_site_a, ScopeType.ROUTER, context)

    async def test_a_location_grant_still_covers_a_router_at_its_own_site(self) -> None:
        """The fix must not lock a network engineer out of their own site."""
        site, org = uuid.uuid4(), uuid.uuid4()
        router_id = uuid.uuid4()
        db = _FakeDb(
            {
                (Router, router_id): _router(
                    router_id, location_id=site, organization_id=org
                )
            }
        )
        request = _make_request(path_params={"router_id": str(router_id)})
        context = await _current_scope_context(request, db)

        grant = GrantScope(
            scope_type=ScopeType.LOCATION,
            organization_id=org,
            location_id=site,
            router_id=None,
        )

        assert ScopeResolver.satisfies(grant, ScopeType.ROUTER, context)

    async def test_a_locations_organization_overrides_the_header(self) -> None:
        org_a, org_b = uuid.uuid4(), uuid.uuid4()
        location_id = uuid.uuid4()
        db = _FakeDb(
            {(Location, location_id): SimpleNamespace(organization_id=org_b)}
        )
        request = _make_request(
            headers={"X-Organization-Id": str(org_a)},
            path_params={"location_id": str(location_id)},
        )

        context = await _current_scope_context(request, db)

        assert context.organization_id == org_b

    async def test_an_unknown_router_leaves_the_headers_alone(self) -> None:
        """An id that resolves to nothing is the handler's 404 to report, not
        an authorization outcome. Turning it into a 403 here would also leak
        whether the id exists."""
        site, org = uuid.uuid4(), uuid.uuid4()
        request = _make_request(
            headers={"X-Location-Id": str(site), "X-Organization-Id": str(org)},
            path_params={"router_id": str(uuid.uuid4())},
        )

        context = await _current_scope_context(request, _FakeDb({}))

        assert context.location_id == site
        assert context.organization_id == org

    async def test_no_db_session_falls_back_to_header_resolution(self) -> None:
        """``_current_scope_context`` is called without a session in a few
        places; it must degrade rather than raise."""
        org = uuid.uuid4()
        request = _make_request(headers={"X-Organization-Id": str(org)})

        context = await _current_scope_context(request, None)

        assert context.organization_id == org

    async def test_only_one_lookup_is_made_for_a_router(self) -> None:
        """The router row carries a denormalized ``organization_id``, so
        containment is one read, not a walk up the hierarchy."""
        site, org = uuid.uuid4(), uuid.uuid4()
        router_id = uuid.uuid4()
        db = _FakeDb(
            {
                (Router, router_id): _router(
                    router_id, location_id=site, organization_id=org
                )
            }
        )
        request = _make_request(path_params={"router_id": str(router_id)})

        await _current_scope_context(request, db)

        assert len(db.gets) == 1

    async def test_a_request_naming_nothing_costs_no_lookup(self) -> None:
        db = _FakeDb({})
        request = _make_request(headers={"X-Organization-Id": str(uuid.uuid4())})

        await _current_scope_context(request, db)

        assert db.gets == []


class TestScopeIdsAreFoundUnderAnyKnownName:
    async def test_customer_id_resolves_as_an_organization(self) -> None:
        """The alias that motivated the table. ``/customers/{customer_id}/
        features`` names an organization without spelling it that way, so the
        old lookup missed it entirely and the check fell back to the caller's
        own header."""
        header_org, path_org = uuid.uuid4(), uuid.uuid4()
        request = _make_request(
            headers={"X-Organization-Id": str(header_org)},
            path_params={"customer_id": str(path_org)},
        )

        context = await _current_scope_context(request, None)

        assert context.organization_id == path_org

    async def test_a_location_named_in_the_query_string_is_found(self) -> None:
        """``GET /guests?location_id=<other site>`` -- the query string was
        entirely invisible to the old lookup, which read path parameters only.
        """
        site_a, site_b = uuid.uuid4(), uuid.uuid4()
        request = _make_request(
            headers={"X-Location-Id": str(site_a)},
            query_string=f"location_id={site_b}".encode(),
        )

        context = await _current_scope_context(request, None)

        assert context.location_id == site_b

    @pytest.mark.parametrize("junk", ["not-a-uuid", "", "123"])
    async def test_an_unparseable_value_contributes_nothing(self, junk: str) -> None:
        """FastAPI's own typed-signature validation already 422s a malformed
        required parameter; this resolver must not raise ahead of it."""
        org = uuid.uuid4()
        request = _make_request(
            headers={"X-Organization-Id": str(org)},
            path_params={"organization_id": junk},
        )

        context = await _current_scope_context(request, None)

        assert context.organization_id == org
