"""RAKESH-FS: ``/isp/workflow`` flag + the MB<->GB boundary helpers.

The console enters/shows GB; the database keeps whole MB unchanged
(``data_cap_mb``, ``fup_limit_mb``). Route-table rules (guards, no
scope-alias path names) are walked for every isp_partner route by
``test_isp_partner_guards``.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.domains.isp_partner import workflow_config as wc


async def test_flag_defaults_off() -> None:
    wc.get_workflow_settings.cache_clear()
    assert wc.get_workflow_settings().enabled is False
    assert wc.franchisee_logins_on() is False
    with pytest.raises(HTTPException) as exc:
        await wc.RequireWorkflowEnabled()
    assert exc.value.status_code == 404


def test_flag_on(monkeypatch) -> None:
    monkeypatch.setenv("ISP_WORKFLOW_ENABLED", "true")
    wc.get_workflow_settings.cache_clear()
    try:
        assert wc.get_workflow_settings().enabled is True
    finally:
        monkeypatch.delenv("ISP_WORKFLOW_ENABLED")
        wc.get_workflow_settings.cache_clear()


@pytest.mark.parametrize(
    ("gb", "mb"),
    [
        (3000, 3_000_000),  # DECISIONS-1: decimal GB
        (1.5, 1500),
        (0.5, 500),
        (0.001, 1),  # never rounds a positive limit to 0
        (0.0004, 1),
        (1.0006, 1001),
        (1_000_000, 1_000_000_000),
        (0, 0),
        (None, None),
    ],
)
def test_gb_to_mb(gb, mb) -> None:
    assert wc.gb_to_mb(gb) == mb


def test_gb_to_mb_refuses_negative() -> None:
    with pytest.raises(ValueError):
        wc.gb_to_mb(-1)


@pytest.mark.parametrize(
    ("mb", "gb"),
    [(3_000_000, 3000.0), (1500, 1.5), (500, 0.5), (1024, 1.024), (None, None), (1, 0.001)],
)
def test_mb_to_gb(mb, gb) -> None:
    assert wc.mb_to_gb(mb) == gb


def test_round_trip_whole_gb_is_exact() -> None:
    for g in (1, 10, 999, 3000, 50_000, 1_000_000):
        assert wc.mb_to_gb(wc.gb_to_mb(g)) == g


def test_largest_form_value_fits_existing_int_column() -> None:
    # isp_packages.data_cap_mb is INTEGER (int4); the console caps at 1e6 GB.
    assert wc.gb_to_mb(1_000_000) < 2**31 - 1


# --------------------------------------------------------------------------
# franchisee confinement (pure parts; the end-to-end cross-zone / cross-ISP
# scenario is test_isp_workflow_postgres.py)
# --------------------------------------------------------------------------

import uuid  # noqa: E402
from types import SimpleNamespace  # noqa: E402

from app.domains.isp_partner import workflow_franchisee as wf  # noqa: E402
from app.domains.isp_partner.exceptions import (  # noqa: E402
    IspBadRequestError,
    IspRoleRequiredError,
    IspZoneNotFoundError,
)

ZA, ZB = uuid.uuid4(), uuid.uuid4()
CUST_A, CUST_B = uuid.uuid4(), uuid.uuid4()
SCOPE = wf.FranchiseeScope(
    zone_ids=frozenset({ZA}), profile_customer_ids=frozenset({CUST_A}), package_ids=None
)


def _flags(monkeypatch, on: bool) -> None:
    from app.domains.isp_partner import zones_config

    v = "true" if on else "false"
    monkeypatch.setenv("ISP_WORKFLOW_ENABLED", v)
    monkeypatch.setenv("ISP_ZONES_ENABLED", v)
    wc.get_workflow_settings.cache_clear()
    zones_config.get_zones_settings.cache_clear()


@pytest.fixture
def flags_reset():
    yield
    from app.domains.isp_partner import zones_config

    wc.get_workflow_settings.cache_clear()
    zones_config.get_zones_settings.cache_clear()


async def test_other_roles_are_untouched() -> None:
    ctx = SimpleNamespace(role_slug="isp-technician")
    assert await wf.apply_franchisee_scope(ctx, None) is ctx


async def test_franchisee_refused_while_flags_off(monkeypatch, flags_reset) -> None:
    _flags(monkeypatch, False)
    with pytest.raises(IspRoleRequiredError):
        await wf.apply_franchisee_scope(
            SimpleNamespace(role_slug="isp-franchisee"), None
        )


def test_role_cannot_be_granted_while_off(monkeypatch, flags_reset) -> None:
    _flags(monkeypatch, False)
    with pytest.raises(IspBadRequestError):
        wf.check_role_allowed("isp-franchisee")
    wf.check_role_allowed("isp-viewer")  # others unaffected
    _flags(monkeypatch, True)
    wf.check_role_allowed("isp-franchisee")


def test_role_has_no_hierarchy_keys() -> None:
    from app.domains.isp_partner.rbac_roles import ROLES_BY_SLUG

    keys = set(ROLES_BY_SLUG["isp-franchisee"].permission_keys)
    for forbidden in (
        "isp_partner.create",  # customers, locations (customer logins)
        "isp_partner.manage",
        "isp_partner.assign",  # users / franchisees
        "isp_zones.manage",
        "isp_plans.create",
        "isp_plans.update",
        "isp_logs.read",
        "isp_ipdr.read",
        "isp_audit.read",
        "isp_partner.export",
    ):
        assert forbidden not in keys, forbidden


def _sub(zone, cust):
    from app.domains.isp_partner.plans_models import IspSubscriber

    return IspSubscriber(zone_id=zone, customer_organization_id=cust)


def test_write_guard() -> None:
    from app.domains.isp_partner.models import IspCustomerProfile

    wf.check_write(SCOPE, _sub(ZA, CUST_B))  # own zone on a shared customer
    wf.check_write(SCOPE, _sub(None, CUST_A))  # no zone, customer profile ours
    with pytest.raises(IspZoneNotFoundError):
        wf.check_write(SCOPE, _sub(ZB, CUST_A))  # into another zone
    with pytest.raises(IspZoneNotFoundError):
        wf.check_write(SCOPE, _sub(None, CUST_B))  # would belong to B's zone
    with pytest.raises(IspZoneNotFoundError):
        wf.check_write(SCOPE, IspCustomerProfile(zone_id=ZB))
    with pytest.raises(IspZoneNotFoundError):
        wf.check_write(SCOPE, IspCustomerProfile(zone_id=None))
    wf.check_write(SCOPE, IspCustomerProfile(zone_id=ZA))


def test_ids_in_request_reads_path_and_query() -> None:
    from starlette.datastructures import QueryParams

    req = SimpleNamespace(
        path_params={"zone_ref": str(ZB), "x": "nope"},
        query_params=QueryParams(f"zone_id={ZA}&page=2"),
    )
    assert wf._ids_in_request(req) == {ZA, ZB}


async def test_path_zone_outside_subtree_is_404() -> None:
    class _Db:
        async def execute(self, _stmt):
            return SimpleNamespace(first=lambda: (ZB,))

    req = SimpleNamespace(path_params={"zone_id": str(ZB)}, query_params=None)
    with pytest.raises(IspZoneNotFoundError):
        await wf._guard_request_zone_ids(_Db(), uuid.uuid4(), frozenset({ZA}), req)


async def test_own_zone_in_path_needs_no_query() -> None:
    class _Db:
        async def execute(self, _stmt):  # pragma: no cover - must not run
            raise AssertionError

    req = SimpleNamespace(path_params={"zone_id": str(ZA)}, query_params=None)
    await wf._guard_request_zone_ids(_Db(), uuid.uuid4(), frozenset({ZA}), req)


def test_workflow_path_params_avoid_scope_aliases() -> None:
    from app.domains.isp_partner.workflow_router import workflow_router

    bad = {"organization_id", "customer_id", "location_id", "router_id"}
    for r in workflow_router.routes:
        names = {p for p in r.param_convertors}  # type: ignore[attr-defined]
        assert not (names & bad), r.path
