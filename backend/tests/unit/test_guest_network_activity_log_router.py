"""Router-registration / RBAC-wiring tests for the two Network Activity Log
v1 backend additions (see ``docs/ipdr-logs-syslog-spec.md``'s v1
recommendation):

* ``GET /guest-devices`` -- bulk MAC-address resolution, closing the "no
  bulk device lookup" gap the spec identified.
* ``GET /guest-login-history`` -- the previously-missing ``GuestLoginHistory``
  list endpoint the Login/Access Attempt Log report reads from.

Mirrors ``test_analytics_router_network_guest_auth.py``'s own
``_permission_key_and_scope_for_route`` pattern: boot the real app via
``create_app()`` and inspect the real, wired ``RequirePermission`` closure
on each route, rather than re-deriving what permission *should* be
required. This is a real assertion against the app's actual dependency
graph, not a guess from reading the decorator source.
"""

from __future__ import annotations

import pytest


def _permission_key_and_scope_for_route(route) -> tuple[str | None, str | None]:
    for dependency in route.dependant.dependencies:
        call = dependency.call
        freevars = getattr(call.__code__, "co_freevars", ())
        if "permission_key" in freevars:
            key_index = freevars.index("permission_key")
            permission_key = call.__closure__[key_index].cell_contents
            scope_value = None
            if "scope" in freevars:
                scope_index = freevars.index("scope")
                scope = call.__closure__[scope_index].cell_contents
                scope_value = scope.value if scope is not None else None
            return permission_key, scope_value
    return None, None


@pytest.fixture(scope="module")
def guest_admin_routes_by_path_and_method():
    from app.main import create_app

    app = create_app()
    routes: dict[tuple[str, str], object] = {}
    for route in app.routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None)
        if path in ("/api/v1/guest-devices", "/api/v1/guest-login-history") and methods:
            for method in methods:
                routes[(path, method)] = route
    return routes


def test_guest_devices_route_is_registered_and_gated_by_guest_sessions_read(
    guest_admin_routes_by_path_and_method,
):
    route = guest_admin_routes_by_path_and_method[("/api/v1/guest-devices", "GET")]
    permission_key, _scope = _permission_key_and_scope_for_route(route)
    assert permission_key == "guest_sessions.read"


def test_guest_login_history_route_is_registered_and_gated_by_guest_sessions_read(
    guest_admin_routes_by_path_and_method,
):
    route = guest_admin_routes_by_path_and_method[
        ("/api/v1/guest-login-history", "GET")
    ]
    permission_key, _scope = _permission_key_and_scope_for_route(route)
    assert permission_key == "guest_sessions.read"


def test_guest_devices_route_matches_existing_guest_sessions_route_gating(
    guest_admin_routes_by_path_and_method,
):
    """The bulk device lookup deliberately reuses the same permission key
    ``GET /guest-sessions`` already gates on -- see
    ``app.domains.guest.router``'s module docstring and this feature's own
    "reuse an existing guest-data read permission, don't invent a new
    module" scoping decision."""
    from app.main import create_app

    app = create_app()
    session_route = next(
        r
        for r in app.routes
        if getattr(r, "path", None) == "/api/v1/guest-sessions"
        and "GET" in getattr(r, "methods", set())
    )
    session_key, session_scope = _permission_key_and_scope_for_route(session_route)

    devices_route = guest_admin_routes_by_path_and_method[
        ("/api/v1/guest-devices", "GET")
    ]
    devices_key, devices_scope = _permission_key_and_scope_for_route(devices_route)

    login_history_route = guest_admin_routes_by_path_and_method[
        ("/api/v1/guest-login-history", "GET")
    ]
    login_history_key, login_history_scope = _permission_key_and_scope_for_route(
        login_history_route
    )

    assert (devices_key, devices_scope) == (session_key, session_scope)
    assert (login_history_key, login_history_scope) == (session_key, session_scope)


def test_app_boots_with_new_routes_registered_and_no_route_conflicts():
    """Confirms the app boots with both new routes registered exactly
    once each -- scoped to just these two paths (rather than asserting
    global route-table uniqueness across the whole app, which fails today
    on a pre-existing, unrelated duplicate elsewhere: ``GET``/``POST``
    ``/api/v1/router-templates/variables`` both registered twice,
    confirmed present on ``main`` before this change and out of this
    feature's scope to fix)."""
    from app.main import create_app

    app = create_app()
    counts: dict[tuple[str, frozenset[str]], int] = {}
    for route in app.routes:
        route_path = getattr(route, "path", None)
        methods = getattr(route, "methods", None)
        if route_path not in ("/api/v1/guest-devices", "/api/v1/guest-login-history"):
            continue
        if methods is None:
            continue
        key = (route_path, frozenset(methods))
        counts[key] = counts.get(key, 0) + 1

    assert counts.get(("/api/v1/guest-devices", frozenset({"GET"}))) == 1
    assert counts.get(("/api/v1/guest-login-history", frozenset({"GET"}))) == 1
