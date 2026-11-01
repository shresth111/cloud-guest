"""JAZE-4 thermal slips: ``?width=58`` must be accepted. It used to be
declared ``Literal[58, 80]``, which FastAPI does not coerce from the query
string, so ``width=58`` (and ``width=80`` sent explicitly) answered 422."""

from __future__ import annotations

import httpx
import pytest
from fastapi import Depends, FastAPI

from app.domains.isp_partner.finance_router import finance_router, thermal_width


def _app() -> FastAPI:
    from app.common.exceptions import register_exception_handlers

    app = FastAPI()
    register_exception_handlers(app)

    @app.get("/w")
    async def w(width: int = Depends(thermal_width)) -> dict:
        return {"width": width}

    return app


@pytest.mark.parametrize(
    ("query", "status", "width"),
    [("", 200, 80), ("?width=58", 200, 58), ("?width=80", 200, 80)],
)
async def test_widths_from_the_query_string(
    query: str, status: int, width: int
) -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app()), base_url="http://t"
    ) as c:
        r = await c.get(f"/w{query}")
    assert r.status_code == status, r.text
    assert r.json()["width"] == width


@pytest.mark.parametrize("bad", ["57", "100", "abc"])
async def test_other_widths_are_refused(bad: str) -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app()), base_url="http://t"
    ) as c:
        r = await c.get(f"/w?width={bad}")
    assert r.status_code == 422


def test_both_thermal_routes_use_the_checked_width() -> None:
    paths = {
        "/finance/invoices/{invoice_id}/thermal.pdf",
        "/finance/payments/{payment_id}/thermal.pdf",
    }
    seen = set()
    for r in finance_router.routes:
        if r.path in paths:
            calls = {d.call for d in r.dependant.dependencies}
            assert thermal_width in calls, r.path
            seen.add(r.path)
    assert seen == paths
