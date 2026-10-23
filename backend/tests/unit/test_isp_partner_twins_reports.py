"""Reports page: the Business Unit picker selects a location OF THE SAME
customer; omitted, the report stays on the workspace location."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from starlette.requests import Request

from app.domains.isp_partner.exceptions import (
    IspLocationNotFoundError,
)
from app.domains.isp_partner.twin_headers import HEADER_CUSTOMER, HEADER_LOCATION
from app.domains.isp_partner.twins import build_twin
from app.domains.isp_partner.twins_all import ALL_TWINS
from app.domains.isp_partner.twins_reports import REPORT_PATHS
from tests.unit.isp_partner_fixtures import (
    CUST_A1,
    ISP_A,
    LOC_A1,
    LOC_A2,
    LOC_B1,
    context,
    estate,
)

LOC_A1_SECOND = uuid.UUID("00000000-0000-0000-0000-00000000a102")


def _estate():
    repo = estate()
    repo.locations[LOC_A1_SECOND] = SimpleNamespace(
        id=LOC_A1_SECOND, organization_id=CUST_A1, name="Loc 2", is_deleted=False
    )
    return repo


def _request() -> Request:
    headers = {
        "X-Organization-Id": str(ISP_A),
        HEADER_CUSTOMER: str(CUST_A1),
        HEADER_LOCATION: str(LOC_A1),
    }
    raw = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    return Request({"type": "http", "method": "GET", "headers": raw, "path": "/"})


class _Rec:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def __call__(self, *args, **kwargs):
        self.calls.append(kwargs)
        return {"data": {}}


def _rows():
    return [s for s in ALL_TWINS if (s.method, s.path) in REPORT_PATHS]


def _kwargs(spec, **over):
    out = {"request": _request(), "isp": context(_estate())}
    for p in spec.params:
        out[p.name] = p.default if not p.required else None
    for e in spec.extras:
        out[e.name] = None
    for dep in spec.deps:
        out[dep] = None
    out.update(over)
    return out


def test_every_report_path_has_the_business_unit_extra() -> None:
    rows = _rows()
    assert {(s.method, s.path) for s in rows} == set(REPORT_PATHS)
    for spec in rows:
        assert "isp_location_id" in {e.name for e in spec.extras}, spec.path


@pytest.mark.parametrize("spec", _rows(), ids=lambda s: s.path)
async def test_omitted_business_unit_stays_on_the_workspace(spec) -> None:
    from dataclasses import replace

    rec = _Rec()
    twin = build_twin(replace(spec, handler=rec))
    await twin(**_kwargs(spec))
    assert rec.calls[0]["location_id"] == LOC_A1


@pytest.mark.parametrize("spec", _rows(), ids=lambda s: s.path)
async def test_another_location_of_the_same_customer_is_used_everywhere(spec) -> None:
    from dataclasses import replace

    rec = _Rec()
    twin = build_twin(replace(spec, handler=rec))
    await twin(**_kwargs(spec, isp_location_id=LOC_A1_SECOND))
    call = rec.calls[0]
    assert call["location_id"] == LOC_A1_SECOND
    for key, src in spec.inject.items():
        if src == ("location",):
            assert call[key] == LOC_A1_SECOND, key


@pytest.mark.parametrize("other", [LOC_A2, LOC_B1], ids=["other-customer", "other-isp"])
@pytest.mark.parametrize("spec", _rows(), ids=lambda s: s.path)
async def test_a_location_outside_the_customer_is_404(spec, other) -> None:
    from dataclasses import replace

    from app.domains.isp_partner.exceptions import IspCustomerNotFoundError

    rec = _Rec()
    twin = build_twin(replace(spec, handler=rec))
    with pytest.raises((IspLocationNotFoundError, IspCustomerNotFoundError)):
        await twin(**_kwargs(spec, isp_location_id=other))
    assert rec.calls == []
