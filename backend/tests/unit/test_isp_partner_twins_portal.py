"""Portal page twins: the venue /me/organizations answer and the F4 flip."""

from __future__ import annotations

import pytest
from starlette.requests import Request

from app.domains.billing.constants import PlanFeatureKey
from app.domains.billing.exceptions import FeatureNotEntitledError
from app.domains.isp_partner import policy
from app.domains.isp_partner.exceptions import (
    IspBadRequestError,
    IspCustomerNotFoundError,
)
from app.domains.isp_partner.twin_gates import enforce_customer_gates
from app.domains.isp_partner.twin_headers import HEADER_CUSTOMER
from app.domains.isp_partner.twins_portal import PORTAL_TWINS
from app.domains.isp_partner.venue_session import venue_me_organizations
from tests.unit.isp_partner_fixtures import CUST_A1, CUST_B1, ISP_A, context, estate
from tests.unit.isp_partner_gate_fakes import FakeChecker, FakeSnapshot


def _request(customer=None) -> Request:
    headers = {"X-Organization-Id": str(ISP_A)}
    if customer:
        headers[HEADER_CUSTOMER] = str(customer)
    raw = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    return Request({"type": "http", "method": "GET", "headers": raw, "path": "/"})


async def test_me_organizations_names_the_pinned_customer() -> None:
    out = await venue_me_organizations(_request(CUST_A1), isp=context(estate()))
    assert [r["organization_id"] for r in out["data"]] == [str(CUST_A1)]
    assert out["data"][0]["status"] == "active"


async def test_me_organizations_refuses_another_isps_customer() -> None:
    with pytest.raises(IspCustomerNotFoundError):
        await venue_me_organizations(_request(CUST_B1), isp=context(estate()))


async def test_me_organizations_needs_the_header() -> None:
    with pytest.raises(IspBadRequestError):
        await venue_me_organizations(_request(), isp=context(estate()))


def test_every_branding_twin_is_white_label_gated() -> None:
    branding = [s for s in PORTAL_TWINS if s.path.startswith("/venue/branding")]
    assert len(branding) == 8
    for spec in branding:
        assert PlanFeatureKey.WHITE_LABEL in spec.requires_features, spec.path


async def test_f4_off_refuses_white_label_even_when_the_plan_has_it(
    monkeypatch,
) -> None:
    checker = FakeChecker(
        snapshots={CUST_A1: FakeSnapshot(enabled_features=frozenset({"white_label"}))}
    )
    await enforce_customer_gates(
        checker,
        CUST_A1,
        method="POST",
        paid_write=True,
        features=(PlanFeatureKey.WHITE_LABEL,),
    )
    monkeypatch.setenv("ISP_PARTNER_WHITE_LABEL", "off")
    policy.get_isp_partner_policy.cache_clear()
    try:
        with pytest.raises(FeatureNotEntitledError):
            await enforce_customer_gates(
                checker,
                CUST_A1,
                method="POST",
                paid_write=True,
                features=(PlanFeatureKey.WHITE_LABEL,),
            )
    finally:
        policy.get_isp_partner_policy.cache_clear()
