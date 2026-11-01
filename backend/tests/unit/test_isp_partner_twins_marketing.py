"""ADDENDUM_04 F1-F3 (coordinator defaults): marketing twins, the ISP wallet,
the ISP-level sender and per-ISP PII unmasking.

Pinned here (the generic structural tests walk the rows through ALL_TWINS):

1. ``isp_marketing_scope`` builds the original's CallerScope from the HEADER
   location's customer; another ISP's location is a 404.
2. F1: ``fund_customer`` moves only the shortfall, refuses with 402
   ``ISP_WALLET_EMPTY`` when the pool cannot cover it, and moves nothing when
   the customer already holds enough. Schedule / test-send use it.
3. F3: venue provider writes need the customer's own-sender override.
4. F2: unmasking only for owner/admin of an ISP Master enabled; unmasked PII
   views are audited; ``build_twin`` honours it.
5. Routes are mounted with their pins.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from app.domains.isp_partner import parity_settings as ps
from app.domains.isp_partner import twins_marketing as tm
from app.domains.isp_partner.exceptions import IspLocationNotFoundError
from app.domains.isp_partner.twins_all import ALL_TWINS
from tests.unit.isp_partner_fixtures import (
    CUST_A1,
    ISP_A,
    LOC_A1,
    LOC_B1,
    context,
    estate,
)


def _req(location=None, path="/x", path_params=None, body=None):
    from starlette.datastructures import Headers

    headers = Headers({"x-isp-location-id": str(location)} if location else {})

    class R:
        def __init__(self):
            self.headers = headers
            self.path_params = path_params or {}
            self.url = SimpleNamespace(path=path)

        async def json(self):
            if body is None:
                raise ValueError("no body")
            return body

    return R()


async def test_scope_is_the_header_locations_customer() -> None:
    scope = await tm.isp_marketing_scope(
        _req(LOC_A1), isp=context(estate()), user=SimpleNamespace(id=str(uuid.uuid4()))
    )
    assert scope.organization_id == CUST_A1 and scope.location_id == LOC_A1
    assert scope.organization_id != ISP_A


async def test_scope_refuses_another_isps_location() -> None:
    with pytest.raises(IspLocationNotFoundError):
        await tm.isp_marketing_scope(
            _req(LOC_B1),
            isp=context(estate()),
            user=SimpleNamespace(id=str(uuid.uuid4())),
        )


class _Wallets:
    def __init__(self, balances):
        self.balances = dict(balances)
        self.moves = []

    async def adjust(self, org, amount, *, idempotency_key, **_k):
        self.balances[org] = self.balances.get(org, 0) + amount
        self.moves.append((org, amount, idempotency_key))


def _patch_wallets(monkeypatch, balances):
    w = _Wallets(balances)

    async def available(db, org):
        return w.balances.get(org, 0)

    monkeypatch.setattr(ps, "_available", available)
    monkeypatch.setattr(ps, "_wallets", lambda db: w)
    return w


async def test_fund_moves_only_the_shortfall(monkeypatch) -> None:
    w = _patch_wallets(monkeypatch, {ISP_A: 1000, CUST_A1: 300})
    moved = await ps.fund_customer(
        None,
        isp_org_id=ISP_A,
        customer_org_id=CUST_A1,
        needed_minor=500,
        idempotency_key="k1",
        actor_user_id=None,
    )
    assert moved == 200
    assert w.balances == {ISP_A: 800, CUST_A1: 500}
    assert {m[2] for m in w.moves} == {"k1:out", "k1:in"}


async def test_fund_nothing_when_customer_holds_enough(monkeypatch) -> None:
    w = _patch_wallets(monkeypatch, {ISP_A: 0, CUST_A1: 900})
    assert (
        await ps.fund_customer(
            None,
            isp_org_id=ISP_A,
            customer_org_id=CUST_A1,
            needed_minor=500,
            idempotency_key="k",
            actor_user_id=None,
        )
        == 0
    )
    assert w.moves == []


async def test_empty_pool_is_402(monkeypatch) -> None:
    w = _patch_wallets(monkeypatch, {ISP_A: 50, CUST_A1: 0})
    with pytest.raises(ps.IspWalletEmptyError) as exc:
        await ps.fund_customer(
            None,
            isp_org_id=ISP_A,
            customer_org_id=CUST_A1,
            needed_minor=500,
            idempotency_key="k",
            actor_user_id=None,
        )
    assert exc.value.status_code == 402
    assert w.moves == []


async def test_schedule_funds_from_the_estimate(monkeypatch) -> None:
    seen = {}

    async def fake_fund(db, **kw):
        seen.update(kw)
        return kw["needed_minor"]

    monkeypatch.setattr(ps, "fund_customer", fake_fund)

    class Svc:
        async def estimate(self, scope, campaign_id):
            return {
                "estimated_max_minor": 1234,
                "unit_price_minor": 10,
                "units_per_recipient_max": 1,
            }

    cid = uuid.uuid4()
    scope = SimpleNamespace(
        organization_id=CUST_A1, location_id=LOC_A1, actor_user_id=None
    )
    svc = Svc()
    out = await tm.funded_marketing_service(
        _req(
            LOC_A1,
            path=f"/x/{cid}/schedule",
            path_params={"campaign_id": str(cid)},
            body={"idempotency_key": "abc"},
        ),
        isp=context(estate()),
        scope=scope,
        service=svc,
        db=None,
    )
    assert out is svc
    assert seen["needed_minor"] == 1234 and seen["customer_org_id"] == CUST_A1
    assert seen["isp_org_id"] == ISP_A


async def test_test_send_funds_per_recipient(monkeypatch) -> None:
    seen = {}

    async def fake_fund(db, **kw):
        seen.update(kw)
        return 0

    monkeypatch.setattr(ps, "fund_customer", fake_fund)

    class Svc:
        async def estimate(self, scope, campaign_id):
            return {
                "estimated_max_minor": 99999,
                "unit_price_minor": 25,
                "units_per_recipient_max": 2,
            }

    cid = uuid.uuid4()
    await tm.funded_marketing_service(
        _req(
            LOC_A1,
            path=f"/x/{cid}/test-send",
            path_params={"campaign_id": str(cid)},
            body={"to": ["a@example.com", "b@example.com", "c@example.com"]},
        ),
        isp=context(estate()),
        scope=SimpleNamespace(
            organization_id=CUST_A1, location_id=LOC_A1, actor_user_id=None
        ),
        service=Svc(),
        db=None,
    )
    assert seen["needed_minor"] == 25 * 2 * 3


def test_schedule_and_test_send_rows_use_the_funded_service() -> None:
    rows = {s.path: s for s in tm.MARKETING_TWINS if s.method == "POST"}
    for path in ("/schedule", "/test-send"):
        spec = rows[f"/venue/marketing/campaigns/{{campaign_id}}{path}"]
        assert spec.deps["service"] is tm.funded_marketing_service


async def test_venue_provider_writes_need_own_sender(monkeypatch) -> None:
    async def not_own(db, org):
        return False

    monkeypatch.setattr(ps, "own_sender", not_own)
    with pytest.raises(tm.IspSenderIsIspLevelError):
        await tm.isp_marketing_scope_own_sender(
            _req(LOC_A1), scope=SimpleNamespace(organization_id=CUST_A1), db=None
        )
    writes = [
        s
        for s in tm.MARKETING_TWINS
        if "/providers/{channel}" in s.path and s.method in ("PUT", "DELETE", "POST")
    ]
    assert len(writes) == 3
    assert all(s.deps["scope"] is tm.isp_marketing_scope_own_sender for s in writes)


def test_marketing_rows_declare_the_addon_and_are_mounted() -> None:
    from app.domains.billing.constants import PlanFeatureKey

    for spec in tm.MARKETING_TWINS:
        if spec.path == "/venue/me/entitlements":
            # ungated like the original; answers the CUSTOMER's entitlements
            assert spec.inject["organization_id"] == ("org",)
            continue
        assert PlanFeatureKey.GUEST_MARKETING in spec.requires_features, spec.path
        if "/providers" in spec.path:
            assert PlanFeatureKey.GUEST_MARKETING_BYO in spec.requires_features
        assert any(spec is t for t in ALL_TWINS)


async def test_unmask_only_owner_admin_of_an_enabled_isp(monkeypatch) -> None:
    async def setting(db, isp_org_id):
        return {"pii_unmask_enabled": True, "byo_customer_override_enabled": False}

    monkeypatch.setattr(ps, "get_parity_setting", setting)
    repo = estate()
    assert await ps.pii_unmasked_for(None, context(repo, role="isp-owner"))
    assert await ps.pii_unmasked_for(None, context(repo, role="isp-admin"))
    assert not await ps.pii_unmasked_for(None, context(repo, role="isp-noc"))
    assert not await ps.pii_unmasked_for(None, context(repo, role="isp-technician"))

    async def off(db, isp_org_id):
        return {"pii_unmask_enabled": False, "byo_customer_override_enabled": False}

    monkeypatch.setattr(ps, "get_parity_setting", off)
    assert not await ps.pii_unmasked_for(None, context(repo, role="isp-owner"))


async def test_build_twin_audits_an_unmasked_pii_view(monkeypatch) -> None:
    from app.domains.isp_partner import pii_policy
    from app.domains.isp_partner.twins import TwinSpec, build_twin

    audits = []

    async def unmasked(isp):
        return True

    async def record(db, isp, **kw):
        audits.append(kw)

    monkeypatch.setattr("app.domains.isp_partner.twins.apply_pii_policy", unmasked)
    monkeypatch.setattr(ps, "record_unmasked_view", record)

    async def handler(request=None, requesting_organization_id=None):
        return {"items": [{"guest_identifier": "+919999999999"}]}

    repo = estate()
    isp = context(repo)
    isp.repository.session = object()
    spec = TwinSpec(
        method="GET",
        path="/venue/guests",
        permission_key="isp_access.read",
        handler=handler,
        target="header_location",
        inject={"requesting_organization_id": ("org",)},
        redact_fields=("guest_identifier",),
    )
    out = await build_twin(spec)(request=_req(LOC_A1), isp=isp)
    assert out["items"][0]["guest_identifier"] == "+919999999999"  # unmasked
    assert audits and audits[0]["customer_org_id"] == CUST_A1
    assert pii_policy.is_pii_spec(spec)


_EXPECTED = {
    ("GET", "/api/v1/isp/wallet"): "isp_engage.read",
    ("GET", "/api/v1/isp/messaging/settings"): "isp_engage.read",
    ("PUT", "/api/v1/isp/messaging/settings"): "isp_engage.manage",
    ("PUT", "/api/v1/isp/customers/{isp_customer_id}/messaging"): "isp_engage.manage",
    ("GET", "/api/v1/isp/messaging/providers"): "isp_engage.read",
    ("PUT", "/api/v1/isp/messaging/providers/{channel}"): "isp_engage.manage",
    ("POST", "/api/v1/isp/messaging/providers/sync"): "isp_engage.manage",
    ("GET", "/api/v1/isp/venue/marketing/credits"): "isp_engage.read",
    (
        "GET",
        "/api/v1/platform/isp-partners/{isp_partner_id}/parity-settings",
    ): "organizations.read",
    (
        "PUT",
        "/api/v1/platform/isp-partners/{isp_partner_id}/parity-settings",
    ): "organizations.manage",
    (
        "GET",
        "/api/v1/platform/isp-partners/{isp_partner_id}/wallet",
    ): "organizations.read",
    (
        "POST",
        "/api/v1/platform/isp-partners/{isp_partner_id}/wallet/topups",
    ): "organizations.manage",
}


def test_f1_f3_routes_are_mounted_with_their_keys() -> None:
    from app.domains.rbac.enums import ScopeType
    from app.main import create_app

    found = {}
    for r in create_app().routes:
        for m in getattr(r, "methods", None) or ():
            if (m, getattr(r, "path", "")) in _EXPECTED:
                vals = [
                    c.cell_contents
                    for d in r.dependant.dependencies
                    for c in (getattr(d.call, "__closure__", None) or ())
                ]
                found[(m, r.path)] = vals
    assert set(found) == set(_EXPECTED)
    for route, key in _EXPECTED.items():
        assert key in found[route], route
        want = ScopeType.GLOBAL if "/platform/" in route[1] else ScopeType.ORGANIZATION
        assert want in found[route], route


async def test_marketing_scope_refuses_a_mismatched_header_pair() -> None:
    from starlette.datastructures import Headers

    from tests.unit.isp_partner_fixtures import CUST_A2

    req = SimpleNamespace(
        headers=Headers(
            {"x-isp-location-id": str(LOC_A1), "x-isp-customer-id": str(CUST_A2)}
        )
    )
    with pytest.raises(IspLocationNotFoundError):
        await tm.isp_marketing_scope(
            req, isp=context(estate()), user=SimpleNamespace(id=str(uuid.uuid4()))
        )
