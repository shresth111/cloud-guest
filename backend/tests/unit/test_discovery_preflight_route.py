"""The HTTP surface for Discovery's precondition pre-flight.

``get_discovery_preflight`` has existed as a service method since #146, which
landed it deliberately unrouted and said so:

    "`get_discovery_preflight` is service-only. The HTTP endpoint is NOT
    wired: that needs a route, permissions and its own tests, and inventing a
    public surface inside someone else's half-finished feature is how the next
    person inherits this same problem."

This file is the "its own tests" half of that sentence.

The route was not optional in practice. The fleet wizard has called
``GET /routers/{id}/discover/preflight`` since #127 -- *earlier* than the
service landed -- via ``router-fleet-wizard.service.ts``, rendered through
``useRouterFleetWizard.ts`` and ``RouterFleetSetupWizard.tsx``'s
``preflightLoading``/``preflightError``. Verified against the running
production API on 2026-09-11: its OpenAPI carried 532 paths, none containing
"preflight", and the URL returned 404. So the panel that tells an installer
*why* discovery will fail has been showing its error state on every router, on
every run, while the backend could compute all of it.

These tests therefore pin the two things a future refactor could quietly break
in a way nobody would notice until an installer complained: the exact path
string the frontend calls, and the permission it sits behind.
"""

from __future__ import annotations

import uuid

from app.main import app

#: The literal the frontend builds in
#: ``cloudguest-foundation/src/services/router-fleet-wizard.service.ts``:
#: ``api.get(`/routers/${routerId}/discover/preflight`)``. Kept as a literal
#: rather than reconstructed from the route object, because the whole failure
#: being fixed here was the two sides not agreeing on this string.
FRONTEND_PATH = "/api/v1/routers/{router_id}/discover/preflight"


def _route(path: str = FRONTEND_PATH):
    return next((r for r in app.routes if getattr(r, "path", None) == path), None)


def _permission_keys(route) -> set[str]:
    """The permission strings a route's ``Depends`` chain enforces.

    ``RequirePermission`` is a factory returning a closure, so the key is not
    on the dependency object -- it lives in the closure cell named
    ``permission_key``. Reading it there is what makes these assertions test
    the wiring rather than a ``repr``."""
    keys: set[str] = set()
    for dep in route.dependant.dependencies:
        call = dep.call
        cells = getattr(call, "__closure__", None) or ()
        names = getattr(getattr(call, "__code__", None), "co_freevars", ()) or ()
        #  strict=True: co_freevars and __closure__ are defined to be
        #  parallel, so a length mismatch means the assumption behind
        #  this helper is wrong and should fail loudly, not silently
        #  truncate and report no permissions at all.
        for name, cell in zip(names, cells, strict=True):
            if name == "permission_key":
                keys.add(cell.cell_contents)
    return keys


def test_the_route_the_frontend_calls_exists():
    """The regression this whole PR is about.

    Before it, the production API served 532 paths and none of them was this
    one, so every call from the wizard 404'd."""
    assert _route() is not None, (
        f"{FRONTEND_PATH} is not registered. The fleet wizard calls it on every "
        "router; without it the precondition panel renders its error state."
    )


def test_it_is_a_GET():
    """``api.get`` on the frontend. A POST here would 405 just as invisibly as
    the 404 did."""
    assert "GET" in _route().methods


def test_it_is_readable_by_someone_who_cannot_run_discovery():
    """``routers.read``, not ``routers.manage``.

    This opens no socket, writes no snapshot and changes nothing -- it reports
    on records we already hold. Gating it behind the permission that lets
    someone *run* discovery would hide the explanation from exactly the person
    who needs it: a reader trying to work out why the button is disabled. The
    button itself still requires ``routers.manage``."""
    keys = _permission_keys(_route())
    assert keys == {"routers.read"}, keys


def test_the_discover_action_itself_still_requires_manage():
    """Guards the other half: widening the read permission must not have
    widened the thing that actually dials a device."""
    discover = _route("/api/v1/routers/{router_id}/discover")
    assert _permission_keys(discover) == {"routers.manage"}


def test_the_response_model_is_the_report_the_service_returns():
    """The frontend reads ``can_attempt``, ``summary``, the two counts and
    ``checks``. Pinning the response model keeps the envelope from being
    changed to something that still 200s while carrying none of that."""
    from app.domains.provisioning_engine.planner.schemas import (
        DiscoveryPreflightResponse,
    )

    fields = DiscoveryPreflightResponse.model_fields
    assert set(fields) >= {
        "can_attempt",
        "summary",
        "blocking_count",
        "unverified_count",
        "checks",
    }


def test_the_path_takes_a_uuid_router_id():
    """The wizard interpolates a router UUID. A route typed as ``str`` would
    accept rubbish and fail deeper, where the error names nothing."""
    route = _route()
    router_id_param = next(
        p for p in route.dependant.path_params if p.name == "router_id"
    )
    assert router_id_param.type_ is uuid.UUID
