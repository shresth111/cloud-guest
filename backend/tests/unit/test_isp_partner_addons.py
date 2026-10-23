"""ADDENDUM_04 §2 (B6): Master add-on allowance + ISP per-customer toggle."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from app.domains.isp_partner import isp_addons as mod
from app.domains.isp_partner.exceptions import IspCustomerNotFoundError
from app.domains.isp_partner.policy import get_isp_partner_policy
from tests.unit.isp_partner_fixtures import CUST_A1, CUST_A2, CUST_B1, context, estate


@pytest.fixture(autouse=True)
def _fresh_policy(monkeypatch):
    for var in ("ISP_PARTNER_ADDON_DEFAULT_ALLOWANCE", "ISP_PARTNER_BYO_SENDER_SCOPE"):
        monkeypatch.delenv(var, raising=False)
    get_isp_partner_policy.cache_clear()
    yield
    get_isp_partner_policy.cache_clear()


def _row(key, enabled=True, cap=None):
    return SimpleNamespace(feature_key=key, enabled=enabled, max_customers=cap)


def test_default_allowance_is_none() -> None:
    out = mod.resolve_allowances([])
    assert set(out) == set(mod.ADDON_KEYS)
    assert not any(a["allowed"] for a in out.values())


def test_default_all_flip_but_byo_follows_f3(monkeypatch) -> None:
    monkeypatch.setenv("ISP_PARTNER_ADDON_DEFAULT_ALLOWANCE", "all")
    get_isp_partner_policy.cache_clear()
    out = mod.resolve_allowances([])
    assert out["guest_marketing"]["allowed"] and out["traffic_flow"]["allowed"]
    assert not out["guest_marketing_byo"]["allowed"]  # F3 default: ISP-level sender
    monkeypatch.setenv("ISP_PARTNER_BYO_SENDER_SCOPE", "customer")
    get_isp_partner_policy.cache_clear()
    assert mod.resolve_allowances([])["guest_marketing_byo"]["allowed"]


def test_master_rows_win_and_missing_keys_are_not_allowed(monkeypatch) -> None:
    monkeypatch.setenv("ISP_PARTNER_ADDON_DEFAULT_ALLOWANCE", "all")
    get_isp_partner_policy.cache_clear()
    out = mod.resolve_allowances([_row("traffic_flow", cap=2)])
    assert out["traffic_flow"] == {
        "allowed": True,
        "max_customers": 2,
        "source": "master",
    }
    assert not out["guest_marketing"]["allowed"]


class _Service:
    def __init__(self) -> None:
        self.calls: list = []

    async def set_addon(self, org_id, key, *, enabled, reason, actor_user_id):
        self.calls.append((org_id, key, enabled))
        view = SimpleNamespace(
            key=key,
            name=key,
            description="",
            enabled=enabled,
            source="override",
            blocked_by=None,
        )
        return view, 0


def _patch(monkeypatch, rows, enabled_elsewhere=0):
    async def allowance_rows(db, isp_org_id):
        return rows

    async def enabled_count(db, ids, key):
        return enabled_elsewhere

    monkeypatch.setattr(mod, "_allowance_rows", allowance_rows)
    monkeypatch.setattr(mod, "_enabled_count", enabled_count)


async def _toggle(isp, customer, key, enabled, service):
    return await mod.set_customer_addon(
        SimpleNamespace(headers={}, state=SimpleNamespace(request_id="t")),
        isp_customer_id=customer,
        feature_key=key,
        payload=mod.IspAddonToggleRequest(enabled=enabled),
        isp=isp,
        actor=SimpleNamespace(id=str(uuid.uuid4())),
        db=None,
        service=service,
    )


async def test_switch_on_without_allowance_is_403(monkeypatch) -> None:
    _patch(monkeypatch, [])
    svc = _Service()
    with pytest.raises(mod.IspAddonNotAllowedError):
        await _toggle(context(estate()), CUST_A1, "traffic_flow", True, svc)
    assert svc.calls == []


async def test_switch_off_is_always_allowed(monkeypatch) -> None:
    _patch(monkeypatch, [])
    svc = _Service()
    await _toggle(context(estate()), CUST_A1, "guest_marketing", False, svc)
    assert svc.calls == [(CUST_A1, "guest_marketing", False)]


async def test_cap_is_409(monkeypatch) -> None:
    _patch(monkeypatch, [_row("traffic_flow", cap=1)], enabled_elsewhere=1)
    svc = _Service()
    with pytest.raises(mod.IspAddonLimitError):
        await _toggle(context(estate()), CUST_A2, "traffic_flow", True, svc)
    assert svc.calls == []


async def test_allowed_switch_on_calls_the_existing_addon_service(monkeypatch) -> None:
    _patch(monkeypatch, [_row("traffic_flow", cap=5)], enabled_elsewhere=1)
    svc = _Service()
    out = await _toggle(context(estate()), CUST_A1, "traffic_flow", True, svc)
    assert svc.calls == [(CUST_A1, "traffic_flow", True)]
    assert out["data"]["addon"]["enabled"] is True


async def test_another_isps_customer_is_404(monkeypatch) -> None:
    _patch(monkeypatch, [_row("traffic_flow")])
    svc = _Service()
    with pytest.raises(IspCustomerNotFoundError):
        await _toggle(context(estate()), CUST_B1, "traffic_flow", True, svc)
    assert svc.calls == []


async def test_unknown_key_is_refused(monkeypatch) -> None:
    _patch(monkeypatch, [])
    with pytest.raises(mod.IspAddonUnknownError):
        await _toggle(context(estate()), CUST_A1, "white_label", True, _Service())


def test_routes_are_mounted_with_their_pins() -> None:
    from app.domains.rbac.enums import ScopeType
    from app.main import create_app

    want = {
        ("GET", "/api/v1/isp/addons"),
        ("GET", "/api/v1/isp/customers/{isp_customer_id}/addons"),
        ("PUT", "/api/v1/isp/customers/{isp_customer_id}/addons/{feature_key}"),
        ("GET", "/api/v1/platform/isp-partners/{isp_partner_id}/addon-allowances"),
        ("PUT", "/api/v1/platform/isp-partners/{isp_partner_id}/addon-allowances"),
    }
    found = {}
    for r in create_app().routes:
        for m in getattr(r, "methods", None) or ():
            if (m, getattr(r, "path", "")) in want:
                found[(m, r.path)] = r
    assert set(found) == want
    for (_m, path), route in found.items():
        scopes = [
            c.cell_contents
            for d in route.dependant.dependencies
            for c in (getattr(d.call, "__closure__", None) or ())
            if isinstance(c.cell_contents, ScopeType)
        ]
        expected = ScopeType.GLOBAL if "/platform/" in path else ScopeType.ORGANIZATION
        assert expected in scopes and all(s == expected for s in scopes), (path, scopes)


def test_traffic_lens_twins_declare_traffic_flow_and_take_no_path_location() -> None:
    from app.domains.billing.constants import PlanFeatureKey
    from app.domains.isp_partner.twins_addons import ADDON_TWINS
    from app.domains.isp_partner.twins_all import ALL_TWINS

    assert len(ADDON_TWINS) == 6
    for spec in ADDON_TWINS:
        assert any(spec is t for t in ALL_TWINS)
        assert spec.requires_features == (PlanFeatureKey.TRAFFIC_FLOW,)
        assert "{" not in spec.path, spec.path
        assert spec.inject["location_id"] == ("location",)
        assert spec.inject["header_location_id"] == ("location",)


def test_flow_records_are_not_twinned_until_f2() -> None:
    from app.domains.isp_partner.twins_all import ALL_TWINS
    from app.domains.traffic_flow import flow_records_customer_router as records

    record_handlers = {
        records.search_venue_flow_records,
        records.export_venue_flow_records,
    }
    assert not [s for s in ALL_TWINS if s.handler in record_handlers]
