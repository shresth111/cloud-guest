"""Structural tests over the mounted route table (BE-3, BE-2, BE-10).

Every ISP route (endpoint defined in ``app.domains.isp_partner`` or
``app.domains.tr069``, except the nginx-only ``/internal/tr069`` route) must
carry, in this order: ``RejectLocationRouterHeaders``,
``RequireOrganization``, a ``RequirePermission`` with an explicit
ORGANIZATION ``scope``, and ``RequireIspPartner``. No path or query
parameter may be named like an RBAC scope alias.

Scoped by endpoint module, not by the ``/isp`` path prefix, because the
existing WAN-failover ``isp`` domain also serves ``/isp/links*`` and
``/isp/routers/{router_id}/...``.

"A structural test that cannot fail is decoration": the ``*_detects_*``
tests at the bottom feed the same checker a route with the scope pin
removed and assert it is flagged.
"""

from __future__ import annotations

import uuid
from functools import lru_cache

import pytest
from fastapi import APIRouter, Depends
from fastapi.testclient import TestClient

from app.domains.isp_partner import config as isp_config
from app.domains.isp_partner.dependencies import (
    RejectLocationRouterHeaders,
    RequireIspPartner,
)
from app.domains.rbac.dependencies import RequireOrganization, RequirePermission
from app.domains.rbac.enums import ScopeType

FORBIDDEN_PARAM_NAMES = {"organization_id", "customer_id", "location_id", "router_id"}
_OUR_MODULES = ("app.domains.isp_partner.", "app.domains.tr069.")
_INTERNAL = "/api/v1/internal/tr069/"


@lru_cache(maxsize=1)
def _app():
    from app.main import create_app

    return create_app()


def _isp_routes(app=None):
    app = app or _app()
    out = []
    for route in app.routes:
        endpoint = getattr(route, "endpoint", None)
        if endpoint is None or not getattr(route, "methods", None):
            continue
        if not endpoint.__module__.startswith(_OUR_MODULES):
            continue
        if route.path.startswith(_INTERNAL):
            continue
        out.append(route)
    return out


def _closure_values(call) -> list:
    return [cell.cell_contents for cell in (getattr(call, "__closure__", None) or ())]


def guard_problems(route) -> list[str]:
    """Empty when the route carries the contract's guard stack."""
    calls = [d.dependency for d in route.dependencies]
    problems: list[str] = []
    expected = [RejectLocationRouterHeaders, RequireOrganization]
    positions = {}
    for name, target in (
        ("RejectLocationRouterHeaders", expected[0]),
        ("RequireOrganization", expected[1]),
        ("RequireIspPartner", RequireIspPartner),
    ):
        if target not in calls:
            problems.append(f"missing {name}")
        else:
            positions[name] = calls.index(target)
    perms = [
        c
        for c in calls
        if getattr(c, "__qualname__", "").startswith("RequirePermission")
    ]
    if len(perms) != 1:
        problems.append(f"expected exactly one RequirePermission, found {len(perms)}")
    else:
        values = _closure_values(perms[0])
        if ScopeType.ORGANIZATION not in values:
            problems.append(
                f"RequirePermission scope is not pinned to ORGANIZATION: {values}"
            )
        if None in values:
            problems.append("RequirePermission has scope=None (inferred scope)")
        positions["RequirePermission"] = calls.index(perms[0])
    order = [
        "RejectLocationRouterHeaders",
        "RequireOrganization",
        "RequirePermission",
        "RequireIspPartner",
    ]
    seen = [positions[n] for n in order if n in positions]
    if seen != sorted(seen):
        problems.append(f"guards out of order: {positions}")
    dependant = route.dependant
    names = {p.name for p in list(dependant.path_params) + list(dependant.query_params)}
    for sub in _walk(dependant):
        names |= {p.name for p in list(sub.path_params) + list(sub.query_params)}
    bad = names & FORBIDDEN_PARAM_NAMES
    if bad:
        problems.append(f"scope-alias parameter names: {sorted(bad)}")
    return problems


def _walk(dependant):
    for d in dependant.dependencies:
        yield d
        yield from _walk(d)


def test_the_route_table_has_the_isp_surface() -> None:
    routes = _isp_routes()
    paths = {r.path for r in routes}
    assert len(routes) >= 64
    assert "/api/v1/isp/me" in paths
    assert "/api/v1/isp/tr069/devices/{cpe_id}/reboot" in paths


@pytest.mark.parametrize(
    "route",
    _isp_routes(),
    ids=lambda r: f"{sorted(r.methods)[0]} {r.path}",
)
def test_every_isp_route_carries_the_guard_stack(route) -> None:
    assert guard_problems(route) == []


def test_no_route_creates_a_child_under_a_customer() -> None:
    """BE-T 2: no /isp/customers/{id}/customers (or any org-type route)."""
    for route in _isp_routes():
        assert not route.path.startswith(
            "/api/v1/isp/customers/{isp_customer_id}/customers"
        )
        assert "org_type" not in route.path


# -- the checker bites --------------------------------------------------------


def _probe_route(*deps):
    router = APIRouter()

    @router.get("/isp/probe", dependencies=list(deps))
    async def probe() -> None:  # pragma: no cover
        return None

    probe.__module__ = "app.domains.isp_partner.probe"
    return router.routes[0]


def test_checker_detects_a_removed_scope_pin() -> None:
    route = _probe_route(
        Depends(RejectLocationRouterHeaders),
        Depends(RequireOrganization),
        Depends(RequirePermission("isp_partner.read")),  # scope= deleted
        Depends(RequireIspPartner),
    )
    assert any("scope" in p for p in guard_problems(route))


def test_checker_detects_a_global_pin_and_missing_guards() -> None:
    route = _probe_route(
        Depends(RequireOrganization),
        Depends(RequirePermission("isp_partner.read", scope=ScopeType.GLOBAL)),
    )
    problems = guard_problems(route)
    assert any("RejectLocationRouterHeaders" in p for p in problems)
    assert any("RequireIspPartner" in p for p in problems)
    assert any("ORGANIZATION" in p for p in problems)


def test_checker_detects_a_scope_alias_parameter() -> None:
    router = APIRouter()

    @router.get(
        "/isp/probe/{customer_id}",
        dependencies=[
            Depends(RejectLocationRouterHeaders),
            Depends(RequireOrganization),
            Depends(
                RequirePermission("isp_partner.read", scope=ScopeType.ORGANIZATION)
            ),
            Depends(RequireIspPartner),
        ],
    )
    async def probe(customer_id: uuid.UUID) -> None:  # pragma: no cover
        return None

    assert any("scope-alias" in p for p in guard_problems(router.routes[0]))


def test_the_correct_shape_passes_the_checker() -> None:
    route = _probe_route(
        Depends(RejectLocationRouterHeaders),
        Depends(RequireOrganization),
        Depends(RequirePermission("isp_partner.read", scope=ScopeType.ORGANIZATION)),
        Depends(RequireIspPartner),
    )
    assert guard_problems(route) == []


# -- feature flags --------------------------------------------------------------


def _concrete(path: str) -> str:
    import re

    return re.sub(r"\{[^}]+\}", str(uuid.UUID(int=7)), path)


def _all_new_routes():
    out = []
    for route in _app().routes:
        endpoint = getattr(route, "endpoint", None)
        if endpoint is not None and endpoint.__module__.startswith(_OUR_MODULES):
            for method in sorted(route.methods or []):
                out.append((method, route.path))
    return out


@pytest.fixture
def flags(monkeypatch):
    def set_flags(*, isp: bool, tr069: bool) -> None:
        from app.domains.tr069 import config as tr_config

        monkeypatch.setattr(
            isp_config,
            "get_isp_partner_settings",
            lambda: isp_config.IspPartnerSettings(enabled=isp),
        )
        monkeypatch.setattr(
            tr_config,
            "get_tr069_settings",
            lambda: tr_config.Tr069Settings(enabled=tr069, edge_shared_secret="s3cret"),
        )
        from app.domains.tr069 import internal_router

        monkeypatch.setattr(
            internal_router, "get_tr069_settings", tr_config.get_tr069_settings
        )

    return set_flags


def test_flag_off_every_new_route_is_404_even_for_a_super_admin(flags) -> None:
    """BE-2: with ISP_PARTNER_ENABLED off the surface does not exist. The
    caller is authenticated as a platform Super Admin and sends every header
    -- the flag check runs before any of it."""
    from app.domains.auth.models import AuthUser
    from app.domains.rbac.dependencies import CurrentUser

    flags(isp=False, tr069=True)
    app = _app()
    app.dependency_overrides[CurrentUser] = lambda: AuthUser(
        id=str(uuid.uuid4()), email="root@example.com", is_superuser=True
    )
    try:
        client = TestClient(app, raise_server_exceptions=False)
        routes = _all_new_routes()
        assert len(routes) >= 65
        for method, path in routes:
            response = client.request(
                method,
                _concrete(path),
                headers={
                    "X-Organization-Id": str(uuid.uuid4()),
                    "X-Organization-Scope": "all",
                    "X-Wyfy-Acs-Gate": "s3cret",
                },
            )
            assert response.status_code == 404, (method, path, response.text)
    finally:
        app.dependency_overrides.clear()


def test_tr069_off_is_503_on_isp_tr069_and_404_on_internal(flags) -> None:
    flags(isp=True, tr069=False)
    client = TestClient(_app(), raise_server_exceptions=False)
    response = client.get("/api/v1/isp/tr069/devices")
    assert response.status_code == 503
    assert response.json()["data"]["code"] == "TR069_NOT_ENABLED"
    internal = client.get(
        "/api/v1/internal/tr069/acs-auth", headers={"X-Wyfy-Acs-Gate": "s3cret"}
    )
    assert internal.status_code == 404


def test_flag_on_unauthenticated_is_401_not_404(flags) -> None:
    flags(isp=True, tr069=True)
    client = TestClient(_app(), raise_server_exceptions=False)
    assert client.get("/api/v1/isp/me").status_code == 401


def test_no_isp_schema_name_collides_with_an_existing_one() -> None:
    """A request model named like an existing one (``LocationCreateRequest``)
    makes FastAPI rename BOTH to ``app__domains__...`` in the OpenAPI
    document, which changes existing paths' schemas. BE-Z 3b forbids that."""
    import inspect

    from pydantic import BaseModel

    from app.domains.isp_partner import schemas as isp_schemas
    from app.domains.tr069 import router as tr_router

    ours = {
        name
        for module in (isp_schemas, tr_router)
        for name, obj in vars(module).items()
        if inspect.isclass(obj)
        and issubclass(obj, BaseModel)
        and obj.__module__ == module.__name__
    }
    assert "IspLocationCreateRequest" in ours
    schemas = _app().openapi()["components"]["schemas"]
    clashes = sorted(
        name
        for name in schemas
        if name.startswith("app__") and name.rsplit("__", 1)[-1] in ours
    )
    assert clashes == [], clashes
