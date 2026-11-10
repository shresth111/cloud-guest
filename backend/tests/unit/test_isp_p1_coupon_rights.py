"""P1-3: per-zone coupon right for franchisees, inherited down the zone tree.

The gate in ``create_coupon_batch`` must be identity (no query) with the flag
off and for every role but ``isp-franchisee``.
"""

from __future__ import annotations

import inspect
import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.domains.isp_partner import p1_coupon_rights as cr
from app.domains.isp_partner.p1_config import get_p1_settings

ROOT, MID, LEAF, OTHER = (uuid.uuid4() for _ in range(4))
PARENTS = {ROOT: None, MID: ROOT, LEAF: MID, OTHER: None}


class _NoDb:
    async def execute(self, *_a, **_k):  # pragma: no cover - must not happen
        raise AssertionError("queried")


@pytest.fixture
def flag_on(monkeypatch):
    monkeypatch.setenv("ISP_ZONE_COUPON_RIGHTS_ENABLED", "true")
    get_p1_settings.cache_clear()
    yield
    get_p1_settings.cache_clear()


def test_default_is_allowed() -> None:
    assert cr.effective_right(PARENTS, {}, LEAF) == (True, None)


def test_nearest_explicit_row_wins() -> None:
    assert cr.effective_right(PARENTS, {ROOT: False}, LEAF) == (False, ROOT)
    assert cr.effective_right(PARENTS, {ROOT: False, MID: True}, LEAF) == (True, MID)
    assert cr.effective_right(PARENTS, {ROOT: True, LEAF: False}, LEAF) == (False, LEAF)
    # a sibling tree is not affected
    assert cr.effective_right(PARENTS, {ROOT: False}, OTHER) == (True, None)


def test_cycle_safe() -> None:
    a, b = uuid.uuid4(), uuid.uuid4()
    assert cr.effective_right({a: b, b: a}, {}, a) == (True, None)


async def test_gate_identity_with_flag_off(monkeypatch) -> None:
    monkeypatch.delenv("ISP_ZONE_COUPON_RIGHTS_ENABLED", raising=False)
    get_p1_settings.cache_clear()
    isp = SimpleNamespace(role_slug="isp-franchisee", isp_org_id=uuid.uuid4())
    await cr.coupon_gate(_NoDb(), isp, uuid.uuid4())


@pytest.mark.parametrize(
    "slug", ["isp-owner", "isp-admin", "isp-billing", "isp-technician", "isp-noc"]
)
async def test_gate_never_applies_to_other_roles(flag_on, slug) -> None:
    isp = SimpleNamespace(role_slug=slug, isp_org_id=uuid.uuid4())
    await cr.coupon_gate(_NoDb(), isp, uuid.uuid4())


async def test_gate_refuses_franchisee_where_zone_says_no(flag_on, monkeypatch) -> None:
    from app.domains.isp_partner import scoping

    async def _visible(_isp, _cid):
        return SimpleNamespace(id=_cid)

    monkeypatch.setattr(scoping.IspScope, "assert_customer", staticmethod(_visible))

    class _Db:
        def __init__(self, zone):
            self.zone = zone

        async def execute(self, *_a, **_k):
            return SimpleNamespace(scalar_one_or_none=lambda: self.zone)

    async def _tree(_s, _isp):
        return PARENTS

    async def _explicit_no(_s, _isp):
        return {MID: False}

    monkeypatch.setattr(cr, "_tree", _tree)
    monkeypatch.setattr(cr, "_explicit", _explicit_no)
    isp = SimpleNamespace(role_slug=cr.FRANCHISEE_SLUG, isp_org_id=uuid.uuid4())
    with pytest.raises(cr.IspCouponsNotPermittedError) as exc:
        await cr.coupon_gate(_Db(LEAF), isp, uuid.uuid4())
    assert exc.value.status_code_default == 403
    # sibling zone: allowed; customer without a zone: allowed
    await cr.coupon_gate(_Db(OTHER), isp, uuid.uuid4())
    await cr.coupon_gate(_Db(None), isp, uuid.uuid4())


async def test_router_flag_off_is_404(monkeypatch) -> None:
    monkeypatch.delenv("ISP_ZONE_COUPON_RIGHTS_ENABLED", raising=False)
    get_p1_settings.cache_clear()
    with pytest.raises(HTTPException) as exc:
        await cr.RequireZoneCouponRightsEnabled()
    assert exc.value.status_code == 404


def test_slug_matches_rakesh_fs_role() -> None:
    try:
        from app.domains.isp_partner.workflow_franchisee import FRANCHISEE_SLUG
    except ImportError:  # RAKESH-FS role not merged yet in this tree
        pytest.skip("workflow_franchisee not present")
    assert cr.FRANCHISEE_SLUG == FRANCHISEE_SLUG


def test_create_coupon_batch_calls_the_gate_first() -> None:
    from app.domains.isp_partner import plans_router

    src = inspect.getsource(plans_router.create_coupon_batch)
    body = src.split(") -> dict:", 1)[1].lstrip()
    assert body.startswith("await p1_coupon_gate(db, isp, payload.isp_customer_id)")
    assert plans_router.p1_coupon_gate is cr.coupon_gate
