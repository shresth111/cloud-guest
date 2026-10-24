"""QA pass 2: QA-026 (other locations of the same customer), QA-016 (engage
read keys), and the /venue/me/organizations header pair."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from starlette.requests import Request

from app.domains.isp_partner.constants import ISP_ENGAGE_READ
from app.domains.isp_partner.exceptions import (
    IspCustomerNotFoundError,
    IspLocationNotFoundError,
)
from app.domains.isp_partner.twin_headers import HEADER_CUSTOMER, HEADER_LOCATION
from app.domains.isp_partner.twins import Param, TwinSpec, build_twin
from app.domains.isp_partner.twins_all import ALL_TWINS
from app.domains.isp_partner.twins_keys import ENGAGE_READ_PATHS
from app.domains.isp_partner.venue_session import venue_me_organizations
from tests.unit.isp_partner_fixtures import (
    CUST_A1,
    ISP_A,
    LOC_A1,
    LOC_A2,
    LOC_B1,
    context,
    estate,
)

LOC_A1_OTHER = uuid.UUID("00000000-0000-0000-0000-00000000a103")


def _estate():
    repo = estate()
    repo.locations[LOC_A1_OTHER] = SimpleNamespace(
        id=LOC_A1_OTHER, organization_id=CUST_A1, name="A1 second", is_deleted=False
    )
    return repo


def _request(customer=CUST_A1, location=LOC_A1) -> Request:
    headers = {"X-Organization-Id": str(ISP_A)}
    if customer:
        headers[HEADER_CUSTOMER] = str(customer)
    if location:
        headers[HEADER_LOCATION] = str(location)
    raw = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    return Request({"type": "http", "method": "GET", "headers": raw, "path": "/"})


class _Rec:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def __call__(self, *a, **kw):
        self.calls.append(kw)
        return {"data": {}}


def _location_row():
    rec = _Rec()
    spec = TwinSpec(
        method="GET",
        path="/venue/locations/{isp_location_id}/routers",
        permission_key="isp_partner.read",
        handler=rec,
        target="location",
        resolve_param="isp_location_id",
        params=(Param("isp_location_id", "path", uuid.UUID, forward="location_id"),),
        inject={"requesting_organization_id": ("org",)},
    )
    return build_twin(spec), rec


async def test_another_location_of_the_same_customer_by_path_works() -> None:
    """QA-026: the Business Unit / location pickers read the customer's
    OTHER locations while the workspace pins one."""
    twin, rec = _location_row()
    await twin(request=_request(), isp=context(_estate()), isp_location_id=LOC_A1_OTHER)
    assert rec.calls[0]["location_id"] == LOC_A1_OTHER
    assert rec.calls[0]["requesting_organization_id"] == CUST_A1


@pytest.mark.parametrize("loc", [LOC_A2, LOC_B1], ids=["other-customer", "other-isp"])
async def test_a_location_of_another_customer_by_path_is_404(loc) -> None:
    twin, rec = _location_row()
    with pytest.raises((IspLocationNotFoundError, IspCustomerNotFoundError)):
        await twin(request=_request(), isp=context(_estate()), isp_location_id=loc)
    assert rec.calls == []


async def test_the_pinned_location_must_still_be_the_customers() -> None:
    twin, rec = _location_row()
    with pytest.raises(IspLocationNotFoundError):
        await twin(
            request=_request(location=LOC_A2),
            isp=context(_estate()),
            isp_location_id=LOC_A1_OTHER,
        )
    assert rec.calls == []


async def test_me_organizations_refuses_a_mismatched_pair() -> None:
    with pytest.raises(IspLocationNotFoundError):
        await venue_me_organizations(_request(location=LOC_A2), isp=context(estate()))
    out = await venue_me_organizations(_request(), isp=context(estate()))
    assert out["data"][0]["organization_id"] == str(CUST_A1)


def test_engage_reads_use_isp_engage_read() -> None:
    """QA-016: isp-billing holds isp_engage.read but not isp_access.read."""
    rows = {(s.method, s.path): s for s in ALL_TWINS}
    for key in ENGAGE_READ_PATHS:
        assert rows[key].permission_key == ISP_ENGAGE_READ, key
