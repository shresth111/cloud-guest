"""QA pass 1 regressions (QA_REPORT.md): QA-001, QA-002, QA-003, QA-014, QA-025."""

from __future__ import annotations

import uuid
from dataclasses import replace

import pytest
from pydantic import BaseModel
from starlette.requests import Request

from app.domains.isp_partner.exceptions import (
    IspCustomerNotFoundError,
    IspLocationNotFoundError,
)
from app.domains.isp_partner.subscriber_identity import subscriber_identifier
from app.domains.isp_partner.twin_body import BodyId, apply_body_ids
from app.domains.isp_partner.twin_headers import HEADER_CUSTOMER, HEADER_LOCATION
from app.domains.isp_partner.twins import TwinSpec, build_twin
from app.domains.isp_partner.twins_all import ALL_TWINS
from tests.unit.isp_partner_fixtures import (
    CFG_A1,
    CUST_A1,
    CUST_A2,
    CUST_B1,
    ISP_A,
    LOC_A1,
    LOC_A2,
    LOC_B1,
    context,
    estate,
)


class _Rec:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def __call__(self, *args, **kwargs):
        self.calls.append(kwargs)
        return {"data": {}}


def _request(customer=None, location=None) -> Request:
    headers = {"X-Organization-Id": str(ISP_A)}
    if customer:
        headers[HEADER_CUSTOMER] = str(customer)
    if location:
        headers[HEADER_LOCATION] = str(location)
    raw = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    return Request({"type": "http", "method": "GET", "headers": raw, "path": "/"})


def _probe(target, inject=None):
    rec = _Rec()
    spec = TwinSpec(
        method="GET",
        path="/venue/_qa",
        permission_key="isp_access.read",
        handler=rec,
        target=target,
        inject={"requesting_organization_id": ("org",)} if inject is None else inject,
    )
    return build_twin(spec), rec


# -- QA-002 --------------------------------------------------------------------
async def test_customer_header_with_another_customers_location_is_404() -> None:
    twin, rec = _probe("header_location")
    with pytest.raises(IspCustomerNotFoundError):
        await twin(request=_request(CUST_A1, LOC_A2), isp=context(estate()))
    assert rec.calls == []


async def test_matching_pair_still_works() -> None:
    twin, rec = _probe("header_location")
    await twin(request=_request(CUST_A1, LOC_A1), isp=context(estate()))
    assert rec.calls[0]["requesting_organization_id"] == CUST_A1


@pytest.mark.parametrize("loc", [LOC_A2, LOC_B1], ids=["same-isp", "other-isp"])
async def test_customer_rows_check_the_location_header(loc) -> None:
    """e.g. GET /venue/captive-portal-configs used to ignore it entirely."""
    twin, rec = _probe("header_customer")
    with pytest.raises(IspLocationNotFoundError):
        await twin(request=_request(CUST_A1, loc), isp=context(estate()))
    assert rec.calls == []


async def test_a_path_resolved_row_must_belong_to_the_header_customer() -> None:
    rec = _Rec()
    spec = TwinSpec(
        method="GET",
        path="/venue/_qa/{config_id}",
        permission_key="isp_partner.read",
        handler=rec,
        target="portal_config",
        resolve_param="config_id",
        params=(),
        inject={"requesting_organization_id": ("org",)},
    )
    from app.domains.isp_partner.twins import Param

    spec = replace(spec, params=(Param("config_id", "path", uuid.UUID),))
    twin = build_twin(spec)
    with pytest.raises(IspCustomerNotFoundError):
        await twin(
            request=_request(CUST_A2), isp=context(estate()), config_id=CFG_A1
        )
    assert rec.calls == []


def test_the_real_portal_list_row_is_header_customer() -> None:
    row = next(
        s
        for s in ALL_TWINS
        if s.method == "GET" and s.path == "/venue/captive-portal-configs"
    )
    assert row.target == "header_customer"


# -- QA-003 --------------------------------------------------------------------
async def test_a_target_less_row_refuses_a_foreign_customer_header() -> None:
    twin, rec = _probe("none", inject={})
    with pytest.raises(IspCustomerNotFoundError):
        await twin(request=_request(CUST_B1), isp=context(estate()))
    assert rec.calls == []


# -- QA-001 --------------------------------------------------------------------
class _StrLoc(BaseModel):
    location_id: str | None = None
    mac_address: str = "02:AA:BB:CC:DD:04"


class _UuidLoc(BaseModel):
    location_id: uuid.UUID | None = None


@pytest.mark.parametrize(
    "sent", [None, "", "ignored"], ids=["omitted", "empty", "other"]
)
async def test_forced_location_takes_the_declared_str_type(sent) -> None:
    kwargs = {"payload": _StrLoc(location_id=sent) if sent is not None else _StrLoc()}
    await apply_body_ids(
        (BodyId("location_id", "force_location"),),
        kwargs,
        context(estate()),
        CUST_A1,
        LOC_A1,
    )
    value = kwargs["payload"].location_id
    assert isinstance(value, str) and uuid.UUID(value) == LOC_A1


async def test_forced_location_on_a_uuid_field_stays_a_uuid() -> None:
    kwargs = {"payload": _UuidLoc()}
    await apply_body_ids(
        (BodyId("location_id", "force_location"),),
        kwargs,
        context(estate()),
        CUST_A1,
        LOC_A1,
    )
    assert kwargs["payload"].location_id == LOC_A1


# -- QA-014 --------------------------------------------------------------------
@pytest.mark.parametrize(
    ("identifier", "source", "want"),
    [
        ("rahul.sharma.9288", "manual", "rahul.sharma.9288"),
        ("user9288", "manual", "user9288"),
        ("+919999900000", "manual", "+919999900000"),
        ("user9288", "coupon", "user9288"),
    ],
)
def test_usernames_are_shown_as_entered(identifier, source, want) -> None:
    assert subscriber_identifier(identifier, source) == want


@pytest.mark.parametrize("identifier", ["guest@example.com", "+91 98765 47512"])
def test_coupon_guest_contacts_stay_masked(identifier) -> None:
    out = subscriber_identifier(identifier, "coupon")
    assert out != identifier
    assert "98765" not in out or "@" in identifier


def test_two_usernames_never_collapse_to_the_same_label() -> None:
    a = subscriber_identifier("rahul.sharma.9288", "manual")
    b = subscriber_identifier("user9288", "manual")
    assert a != b


# -- QA-025 --------------------------------------------------------------------
@pytest.mark.parametrize("path", ["/venue/voucher-batches", "/venue/guest-teams"])
def test_business_unit_is_checked_on_the_two_remaining_reports(path) -> None:
    row = next(s for s in ALL_TWINS if s.method == "GET" and s.path == path)
    assert "isp_location_id" in {e.name for e in row.extras}
