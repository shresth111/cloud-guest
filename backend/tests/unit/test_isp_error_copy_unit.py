"""ERROR-COPY: stable error codes on the ISP partner API.

* the code inventory snapshot (``scripts/isp_error_codes.json``) matches the
  source, so the console's copy test (FE) sees every code;
* flag-off 404s and the old bare ``HTTPException`` 422s now carry
  ``data.code`` (and are still ``HTTPException`` for existing callers);
* ``data.reason`` sub-codes ride along without changing ``data.code``;
* every error envelope built in ``isp_partner`` carries ``request_id``.
"""

from __future__ import annotations

import ast
import json
from datetime import UTC, date, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

from app.common.exceptions import register_exception_handlers
from app.domains.isp_partner import exceptions as ex

BACKEND = Path(__file__).resolve().parents[2]
ISP = BACKEND / "app" / "domains" / "isp_partner"


# -- inventory -----------------------------------------------------------------


def test_inventory_snapshot_is_fresh() -> None:
    from scripts import isp_error_inventory as inv

    assert inv.stale_codes() == [], "run: python -m scripts.isp_error_inventory --write"


def test_inventory_has_the_new_codes_and_reasons() -> None:
    from scripts import isp_error_inventory as inv

    rows = {r["code"]: r for r in inv.inventory()}
    assert rows["ISP_FEATURE_DISABLED"]["status"] == 404
    assert rows["RATE_LIMITED"]["status"] == 429
    assert rows["TR069_NOT_ENABLED"]["status"] == 503
    for reason in (
        "ISP_DATE_RANGE_ORDER",
        "ISP_DATE_RANGE_TOO_LONG",
        "ISP_QUERY_INVALID",
        "ISP_MONTH_FORMAT",
        "ISP_BULK_FILTER_TOO_BROAD",
        "ISP_STATUS_CHANGED",
    ):
        assert rows[reason]["kind"] == "reason", reason
        assert rows[reason]["parents"], reason
    # every code has a status, so the console can pick a fallback
    assert all(r["status"] for r in rows.values())


# -- envelope shape ------------------------------------------------------------


def _app(exc: Exception) -> TestClient:
    app = FastAPI()
    register_exception_handlers(app)

    @app.middleware("http")
    async def rid(request, call_next):  # noqa: ANN001
        request.state.request_id = "rid-123"
        return await call_next(request)

    @app.get("/boom")
    async def boom() -> None:
        raise exc

    return TestClient(app, raise_server_exceptions=False)


def test_feature_disabled_is_still_an_http_exception_with_a_code() -> None:
    e = ex.IspFeatureDisabledError()
    assert isinstance(e, HTTPException) and isinstance(e, ex.IspError)
    assert (e.status_code, e.detail) == (404, "Not Found")
    r = _app(e).get("/boom")
    assert r.status_code == 404
    body = r.json()
    assert body["message"] == "Not Found"
    assert body["data"] == {"code": "ISP_FEATURE_DISABLED"}
    assert body["request_id"] == "rid-123"


def test_reason_is_additive() -> None:
    e = ex.IspBadRequestError("x", reason="ISP_QUERY_INVALID", field="month")
    assert e.status_code == 422
    assert e.data == {
        "code": "ISP_BAD_REQUEST",
        "reason": "ISP_QUERY_INVALID",
        "field": "month",
    }


@pytest.mark.parametrize(
    "module,dep",
    [
        ("apps_common", "RequireIspAppsEnabled"),
        ("bill2_config", "RequireBill2Enabled"),
        ("fiber_service", "RequireIspFiberEnabled"),
        ("caf_service", "RequireIspCafEnabled"),
        ("directory_bulk_router", "RequireDir2Enabled"),
        ("staticip_router", "RequireStaticIp2Enabled"),
        ("package_meta_router", "RequirePackageMetaEnabled"),
        ("discount_wire_router", "RequireDiscountApplyEnabled"),
    ],
)
async def test_flag_off_dependencies_raise_the_coded_404(
    monkeypatch, module: str, dep: str
) -> None:
    import importlib

    mod = importlib.import_module(f"app.domains.isp_partner.{module}")
    off = SimpleNamespace(enabled=False, discount_apply_enabled=False)
    for name in dir(mod):
        if name.startswith("get_") and name.endswith("_settings"):
            monkeypatch.setattr(mod, name, lambda: off)
    with pytest.raises(HTTPException) as info:
        await getattr(mod, dep)()
    assert isinstance(info.value, ex.IspFeatureDisabledError)
    assert info.value.status_code == 404


def test_finance_flag_off_factory() -> None:
    from app.domains.isp_partner import finance_config

    e = finance_config._off()
    assert isinstance(e, ex.IspFeatureDisabledError)
    assert e.data["code"] == "ISP_FEATURE_DISABLED"


def test_gst_month_is_coded_and_still_http() -> None:
    from app.domains.isp_partner import billing_gst

    with pytest.raises(HTTPException) as info:
        billing_gst.month_bounds("2026/10")
    e = info.value
    assert e.status_code == 422
    assert e.data == {
        "code": "ISP_BAD_REQUEST",
        "field": "month",
        "reason": "ISP_MONTH_FORMAT",
    }
    body = _app(e).get("/boom").json()
    assert body["data"]["reason"] == "ISP_MONTH_FORMAT"
    assert body["request_id"] == "rid-123"


async def test_zone_revenue_bad_range_has_request_id_not_a_500() -> None:
    """Before ERROR-COPY this reply omitted request_id, so build_response
    raised TypeError and the caller got a 500 with no code."""
    from app.domains.isp_partner import finance_router

    req = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"x-request-id", b"rid-9")],
            "query_string": b"",
        }
    )
    r = await finance_router.zone_revenue(
        req,
        date_from=date(2026, 10, 2),
        date_to=date(2026, 10, 1),
        isp=SimpleNamespace(),
        svc=SimpleNamespace(),
    )
    assert r.status_code == 422
    body = json.loads(r.body)
    assert body["request_id"] == "rid-9"
    assert body["data"]["code"] == "ISP_FINANCE_INVALID"
    assert body["data"]["reason"] == "ISP_DATE_RANGE_INVALID"


def test_dashboard_period_reasons() -> None:
    from app.domains.isp_partner import dashboard_service as ds

    now = datetime(2026, 11, 1, tzinfo=UTC)
    with pytest.raises(ex.IspBadRequestError) as info:
        ds.period_bounds(ds.Filters(period="custom"), now=now, tz="Asia/Kolkata")
    assert info.value.data["reason"] == "ISP_DATE_RANGE_INCOMPLETE"
    with pytest.raises(ex.IspBadRequestError) as info:
        ds.period_bounds(
            ds.Filters(
                period="custom", date_from=date(2025, 1, 1), date_to=date(2026, 10, 1)
            ),
            now=now,
            tz="Asia/Kolkata",
        )
    assert info.value.data["reason"] == "ISP_DATE_RANGE_INVALID"
    assert info.value.data["max_days"] == 401
    assert info.value.data["code"] == "ISP_BAD_REQUEST"


# -- source guards -------------------------------------------------------------

# Bare HTTPException stays only where the 404 must look like a missing route
# before any auth runs (whole console off; PPPoE flag and FreeRADIUS secret).
BARE_HTTP_ALLOWED = {"config.py", "pppoe_router.py", "pppoe_config.py"}


def _trees():
    for p in sorted(ISP.rglob("*.py")):
        yield p, ast.parse(p.read_text())


def _name(call: ast.Call) -> str:
    f = call.func
    return f.id if isinstance(f, ast.Name) else getattr(f, "attr", "")


def test_every_error_envelope_carries_request_id() -> None:
    missing = [
        f"{p.name}:{n.lineno}"
        for p, t in _trees()
        for n in ast.walk(t)
        if isinstance(n, ast.Call)
        and _name(n) == "build_response"
        and not any(k.arg == "request_id" for k in n.keywords)
    ]
    assert missing == []


def test_no_new_bare_http_exceptions() -> None:
    bare = [
        f"{p.name}:{n.lineno}"
        for p, t in _trees()
        for n in ast.walk(t)
        if isinstance(n, ast.Raise)
        and isinstance(n.exc, ast.Call)
        and _name(n.exc) == "HTTPException"
        and p.name not in BARE_HTTP_ALLOWED
    ]
    assert bare == [], "raise an IspError subclass (it carries data.code)"
