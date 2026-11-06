"""Platform-only routes check their permission at GLOBAL scope (security
review 2026-11-06, C1/L6/L7).

Without ``scope=``, ``RequirePermission`` checks at whatever scope the
caller's own headers imply, so a tenant holding the key at ORGANIZATION
scope passes. These routes serve platform data (leads, quotations, partners,
licences, raw device console, unassigned devices, platform health), so a
tenant-scoped grant must never satisfy them. This walks the real route table,
so a new platform-only route added without the pin fails here.
"""

from __future__ import annotations

import pytest
from fastapi.routing import APIRoute

from app.domains.rbac.enums import ScopeType

# Every permission in a GLOBAL-only module, plus the platform-only keys of
# otherwise tenant-facing modules.
PLATFORM_ONLY_MODULES = {
    "channel_partners",
    "demo_requests",
    "device_logs",
    "network_integrations",
    "quotations",
    "system_settings",
    "traffic_flows",
    "device_console",
}
PLATFORM_ONLY_KEYS = {
    "organizations.create",
    "subscriptions.create",
    "subscriptions.update",
}
PLATFORM_ONLY_PATHS = {
    ("GET", "/api/v1/router-enrollment"),
    ("POST", "/api/v1/router-enrollment/{enrollment_id}/approve"),
    ("POST", "/api/v1/router-enrollment/{enrollment_id}/reject"),
    ("GET", "/api/v1/controller-logs/system"),
    ("GET", "/api/v1/controller-logs/system/export"),
}


def _permission_checks(dependant, out):
    call = dependant.call
    if call is not None and getattr(call, "__qualname__", "").startswith(
        "RequirePermission"
    ):
        cells = dict(
            zip(
                call.__code__.co_freevars,
                [c.cell_contents for c in (call.__closure__ or ())],
                strict=True,
            )
        )
        out.append((cells.get("permission_key"), cells.get("scope")))
    for sub in dependant.dependencies:
        _permission_checks(sub, out)


@pytest.fixture(scope="module")
def route_checks() -> list[tuple[str, str, str, ScopeType | None]]:
    from app.main import app

    rows = []
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        checks: list = []
        _permission_checks(route.dependant, checks)
        for method in route.methods:
            for key, scope in checks:
                rows.append((method, route.path, key, scope))
    return rows


def test_platform_only_permissions_are_pinned_global(route_checks) -> None:
    unpinned = sorted(
        f"{method} {path} ({key})"
        for method, path, key, scope in route_checks
        if (key.split(".")[0] in PLATFORM_ONLY_MODULES or key in PLATFORM_ONLY_KEYS)
        and scope is not ScopeType.GLOBAL
    )
    assert unpinned == []


def test_platform_only_paths_are_pinned_global(route_checks) -> None:
    seen = {(m, p) for m, p, _k, _s in route_checks}
    assert PLATFORM_ONLY_PATHS <= seen
    unpinned = sorted(
        f"{method} {path} ({key})"
        for method, path, key, scope in route_checks
        if (method, path) in PLATFORM_ONLY_PATHS and scope is not ScopeType.GLOBAL
    )
    assert unpinned == []
