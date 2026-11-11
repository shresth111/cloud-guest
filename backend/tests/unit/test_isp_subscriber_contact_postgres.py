# ruff: noqa: E501, PLR0915 -- scenario test
"""First name + mobile required on the console's subscriber writes, on real
PostgreSQL (skipped unless ``ISP_TEST_PG_DSN``). Run with
``scripts/run_isp_pg_tests.py``. ISP_SUBSCRIBER_CONTACT_REQUIRED=true

The test switches ISP_WORKFLOW_ENABLED / ISP_ZONES_ENABLED itself, and the
contact flag off once to make a row without a name.

Covers:
* ``POST /subscribers``, ``POST /subscribers/onboard`` and ``POST /onboarding``
  refuse a missing first name (422 ``ISP_SUBSCRIBER_FIRST_NAME_REQUIRED``) and
  a missing / malformed mobile (422 ``ISP_SUBSCRIBER_MOBILE_REQUIRED``), write
  nothing, and accept a complete body;
* ``PATCH`` refuses clearing the first name or a bad mobile, and accepts an
  unrelated update on an old row that has no name or mobile;
* a coupon redemption still becomes a subscriber (no name, no mobile);
* ISP B still gets 404 on A's customer with a complete body;
* franchisee FA: same 422 inside its zone, 201 with a full body, and 404 on
  FB's zone customer.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("ISP_TEST_PG_DSN"), reason="set ISP_TEST_PG_DSN to run"
)


def _clear() -> None:
    from app.domains.isp_partner.subscriber_contact import (
        get_subscriber_contact_settings,
    )
    from app.domains.isp_partner.workflow_config import get_workflow_settings
    from app.domains.isp_partner.zones_config import get_zones_settings

    get_workflow_settings.cache_clear()
    get_zones_settings.cache_clear()
    get_subscriber_contact_settings.cache_clear()


async def test_subscriber_contact_required(monkeypatch) -> None:  # noqa: ANN001, C901
    import httpx
    from sqlalchemy import func, select

    from app.database.session import SessionLocal
    from app.domains.isp_partner.plans_models import IspSubscriber
    from app.domains.voucher.models import Voucher

    from .isp_small_pg_helpers import Api, customer, dispose, make_world, package

    monkeypatch.setenv("ISP_SUBSCRIBER_CONTACT_REQUIRED", "true")
    monkeypatch.setenv("ISP_WORKFLOW_ENABLED", "true")
    monkeypatch.setenv("ISP_ZONES_ENABLED", "true")
    _clear()
    try:
        w = await make_world(
            extra_users_on_a={"FA": "isp-franchisee", "FB": "isp-franchisee"}
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=w.app), base_url="http://t"
        ) as c:
            api = Api(c, w)
            za = (await api.post("/zones/tree", {"name": f"SZA{w.tag}"}))["id"]
            zb = (await api.post("/zones/tree", {"name": f"SZB{w.tag}"}))["id"]
            ca = await customer(api, "A", "SCa")
            cb = await customer(api, "A", "SCb")
            cx = await customer(api, "B", "SCx")
            await api.patch(f"/customers/{ca}", {"zone_id": za})
            await api.patch(f"/customers/{cb}", {"zone_id": zb})
            p1 = await package(api, "A", price=50000, name="SC")
            px = await package(api, "B", price=50000, name="SCx")
            fa, fb = str(w.users["FA"]), str(w.users["FB"])
            await api.put(f"/workflow/franchisees/{fa}/zones", {"zone_ids": [za]})
            await api.put(f"/workflow/franchisees/{fb}/zones", {"zone_ids": [zb]})

            async def count(cust: str) -> int:
                async with SessionLocal() as s:
                    return (
                        await s.execute(
                            select(func.count())
                            .select_from(IspSubscriber)
                            .where(
                                IspSubscriber.customer_organization_id
                                == uuid.UUID(cust)
                            )
                        )
                    ).scalar_one()

            def body(ident: str, cust: str = ca, pkg: str = p1, **kw):  # noqa: ANN003, ANN202
                return {
                    "isp_customer_id": cust,
                    "identifier": f"{ident}{w.tag}",
                    "package_id": pkg,
                    "state_code": "07",
                    **kw,
                }

            def code(resp) -> str:  # noqa: ANN001
                return str(resp)

            full = {"first_name": "Asha", "last_name": "Rao", "phone": "9876543210"}

            # ---- the three create routes, owner ------------------------------
            for path, wrap in (
                ("/subscribers", lambda b: b),
                ("/subscribers/onboard", lambda b: b),
                ("/onboarding", lambda b: {"subscriber": b}),
            ):
                r = await api.post(
                    path, wrap(body(f"n{len(path)}", phone="9876543210")), code=422
                )
                assert "ISP_SUBSCRIBER_FIRST_NAME_REQUIRED" in code(r), (path, r)
                r = await api.post(
                    path, wrap(body(f"m{len(path)}", first_name="Asha")), code=422
                )
                assert "ISP_SUBSCRIBER_MOBILE_REQUIRED" in code(r), (path, r)
                r = await api.post(
                    path,
                    wrap(body(f"b{len(path)}", first_name="Asha", phone="12345")),
                    code=422,
                )
                assert "ISP_SUBSCRIBER_MOBILE_REQUIRED" in code(r), (path, r)
                r = await api.post(
                    path,
                    wrap(body(f"w{len(path)}", first_name="  ", phone="9876543210")),
                    code=422,
                )
                assert "ISP_SUBSCRIBER_FIRST_NAME_REQUIRED" in code(r), (path, r)
            assert await count(ca) == 0  # nothing written by any refusal
            ok1 = await api.post("/subscribers", body("ok1", **full), code=201)
            ok2 = await api.post("/subscribers/onboard", body("ok2", **full), code=201)
            ok3 = await api.post(
                "/onboarding", {"subscriber": body("ok3", **full)}, code=201
            )
            assert ok1["id"] and ok2["id"] and ok3
            assert await count(ca) == 3

            # ---- PATCH: only the keys sent ------------------------------------
            sid = ok1["id"]
            r = await api.patch(f"/subscribers/{sid}", {"first_name": ""}, code=422)
            assert "ISP_SUBSCRIBER_FIRST_NAME_REQUIRED" in code(r)
            r = await api.patch(f"/subscribers/{sid}", {"first_name": None}, code=422)
            assert "ISP_SUBSCRIBER_FIRST_NAME_REQUIRED" in code(r)
            r = await api.patch(f"/subscribers/{sid}", {"phone": "abc"}, code=422)
            assert "ISP_SUBSCRIBER_MOBILE_REQUIRED" in code(r)
            await api.patch(f"/subscribers/{sid}", {"last_name": None})  # optional
            await api.patch(
                f"/subscribers/{sid}",
                {"first_name": "Asha", "phone": "+91 98765-43210"},
            )

            # an old row (made while the flag was off) stays editable elsewhere
            monkeypatch.setenv("ISP_SUBSCRIBER_CONTACT_REQUIRED", "false")
            _clear()
            old = await api.post("/subscribers", body("old"), code=201)
            monkeypatch.setenv("ISP_SUBSCRIBER_CONTACT_REQUIRED", "true")
            _clear()
            await api.get(f"/subscribers/{old['id']}")
            await api.patch(f"/subscribers/{old['id']}", {"zone_id": za})
            await api.patch(f"/subscribers/{old['id']}", {"display_name": "Old row"})

            # ---- coupon redemption still makes a subscriber -------------------
            await api.post(
                "/coupon-batches",
                {"package_id": p1, "isp_customer_id": cb, "quantity": 1},
            )
            async with SessionLocal() as s:
                v = (
                    (
                        await s.execute(
                            select(Voucher).where(
                                Voucher.organization_id == uuid.UUID(cb)
                            )
                        )
                    )
                    .scalars()
                    .first()
                )
                v.redeemed_identifier = f"cpn{w.tag}"
                v.redeemed_at = datetime.now(UTC) - timedelta(minutes=2)
                v.expires_at = datetime.now(UTC) + timedelta(days=30)
                await s.commit()
            assert (await api.post("/subscribers/sync"))["applied"] == 1
            async with SessionLocal() as s:
                cs = (
                    await s.execute(
                        select(IspSubscriber).where(
                            IspSubscriber.identifier == f"cpn{w.tag}"
                        )
                    )
                ).scalar_one()
                assert (
                    cs.source == "coupon" and cs.first_name is None and cs.phone is None
                )

            # ---- cross-ISP: B on A's customer is 404 even with a full body ----
            await api.post("/subscribers", body("x1", **full), who="B", code=404)
            await api.post(
                "/subscribers/onboard", body("x2", **full), who="B", code=404
            )
            await api.post(
                "/onboarding", {"subscriber": body("x3", **full)}, who="B", code=404
            )
            await api.patch(
                f"/subscribers/{sid}", {"first_name": "B"}, who="B", code=404
            )
            # ...and B's own create follows the same rule
            r = await api.post(
                "/subscribers", body("bx", cust=cx, pkg=px), who="B", code=422
            )
            assert "ISP_SUBSCRIBER_FIRST_NAME_REQUIRED" in code(r)

            # ---- franchisees ---------------------------------------------------
            r = await api.post(
                "/subscribers/onboard", body("fa1", zone_id=za), who="FA", code=422
            )
            assert "ISP_SUBSCRIBER_FIRST_NAME_REQUIRED" in code(r)
            await api.post(
                "/subscribers/onboard",
                body("fa2", zone_id=za, **full),
                who="FA",
                code=201,
            )
            await api.post(
                "/subscribers/onboard",
                body("fa3", cust=cb, zone_id=zb, **full),
                who="FA",
                code=404,
            )
            await api.patch(
                f"/subscribers/{sid}", {"first_name": ""}, who="FB", code=404
            )
    finally:
        _clear()
        await dispose()
