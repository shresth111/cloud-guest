# ruff: noqa: E501, PLR0915 -- scenario test
"""RAKESH-P1 on real PostgreSQL + Redis (skipped unless ``ISP_TEST_PG_DSN``).
Run with ``scripts/run_isp_pg_tests.py``. The test switches its own flags
(env + cache_clear): ISP_TEMPLATE_RULES_ENABLED, ISP_CYCLE_BASIS_ENABLED,
ISP_ZONE_COUPON_RIGHTS_ENABLED, ISP_ZONES_ENABLED.

Covers:
* flags off -> every P1 route 404, and a renewal is the old ``validity`` end;
* P1-1: template device rules saved; dry run changes nothing; apply writes
  the package's max_devices and only the 3 policy fields (other policy fields
  keep their values); a second apply changes nothing;
* P1-2: ``subscriber`` basis snaps a renewal to the anchor day (DECISIONS-1:
  the first snapped period is pro-rated, the next one on the anchor is full
  price); the same
  renewal on a ``package`` basis package (or a subscriber with no anchor) is
  exactly validity days;
* P1-3: zone right inherits from the parent zone, explicit child wins, null
  goes back to inherit;
* scope: ISP B gets 404 on A's template / package / zone; confined (zone-
  restricted) staff read templates but cannot write template rules, cycle
  basis, packages or coupon rights (403), and see / create coupon batches only
  for their own customer (another customer's batch is a 404 on read and on
  create).
"""

from __future__ import annotations

import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("ISP_TEST_PG_DSN"), reason="set ISP_TEST_PG_DSN to run"
)

_FLAGS = (
    "ISP_TEMPLATE_RULES_ENABLED",
    "ISP_CYCLE_BASIS_ENABLED",
    "ISP_ZONE_COUPON_RIGHTS_ENABLED",
    "ISP_ZONES_ENABLED",
)


def _clear() -> None:
    from app.domains.isp_partner.p1_config import get_p1_settings
    from app.domains.isp_partner.zones_config import get_zones_settings

    get_p1_settings.cache_clear()
    get_zones_settings.cache_clear()


async def test_rakesh_p1(monkeypatch) -> None:  # noqa: ANN001, C901
    from datetime import datetime, timedelta
    from zoneinfo import ZoneInfo

    import httpx
    from sqlalchemy import select

    from app.database.session import SessionLocal
    from app.domains.isp_partner.enforcement_models import IspPackagePolicy
    from app.domains.isp_partner.plans_models import IspPackage, IspSubscriber
    from app.domains.isp_partner.subscriber360_models import IspSubscriberProfile

    from .isp_small_pg_helpers import (
        Api,
        billing_setup,
        confine,
        customer,
        dispose,
        make_world,
        package,
        subscriber,
    )

    for f in _FLAGS:
        monkeypatch.setenv(f, "false")
    _clear()
    ist = ZoneInfo("Asia/Kolkata")
    try:
        w = await make_world({"bill": "isp-billing", "tech": "isp-technician"})
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=w.app), base_url="http://t"
        ) as c:
            api = Api(c, w)
            await billing_setup(api, "A")
            c1 = await customer(api, "A", "P1c1")
            c2 = await customer(api, "A", "P1c2")
            await confine(w, "bill", [c1])
            await confine(w, "tech", [c1])
            pkg = await package(api, "A", price=49900, name="P1 30d")
            pkg_row = await api.get(f"/packages/{pkg}")
            grp = pkg_row["speed_group"]["id"]
            # a second package on the same template keeps its own boost rule
            pkg2 = (
                await api.post(
                    "/packages",
                    {
                        "speed_group_id": grp,
                        "type": "prepaid",
                        "validity_days": 90,
                        "price_paise": 129900,
                        "name": "P1 90d",
                    },
                )
            )["id"]
            slow = (
                await api.post(
                    "/speed-groups",
                    {
                        "name": f"Slow {w.tag}",
                        "download_kbps": 2048,
                        "upload_kbps": 2048,
                    },
                )
            )["id"]
            await api.put(
                f"/packages/{pkg2}/policy",
                {
                    "fup_limit_mb": 102400,
                    "fup_reset": "month",
                    "fup_fallback_speed_group_id": slow,
                    "queue_priority": 3,
                },
            )

            # -- flags off: 404 everywhere, renewal is the old end -----------
            for path in (
                "/speed-group-device-rules",
                f"/speed-groups/{grp}/device-rules",
                "/package-cycle-basis",
                f"/packages/{pkg}/cycle-basis",
                "/zone-coupon-rights",
            ):
                await api.get(path, code=404)
            sub = await subscriber(api, "A", c1, pkg, "p1s")
            async with SessionLocal() as s:
                s.add(
                    IspSubscriberProfile(
                        isp_organization_id=w.isps["A"],
                        subscriber_id=uuid.UUID(sub),
                        billing_anchor_day=1,
                    )
                )
                await s.commit()

            async def valid_until(sid: str) -> datetime:
                async with SessionLocal() as s:
                    return (await s.get(IspSubscriber, uuid.UUID(sid))).valid_until

            before = await valid_until(sub)
            await api.post(
                f"/subscribers/{sub}/recharge",
                {"package_id": pkg, "idempotency_key": f"p1off{w.tag}"},
            )
            after = await valid_until(sub)
            assert after - before == timedelta(
                days=30
            ), "flag off: validity days exactly"

            for f in _FLAGS:
                monkeypatch.setenv(f, "true")
            _clear()

            # -- P1-1 template device rules ---------------------------------
            assert (await api.get(f"/speed-groups/{grp}/device-rules"))[
                "configured"
            ] is False
            await api.put(
                f"/speed-groups/{grp}/device-rules",
                {"max_devices": 2, "mac_bind_count": 0, "mac_restriction": True},
                code=422,
            )
            saved = await api.put(
                f"/speed-groups/{grp}/device-rules",
                {
                    "max_devices": 3,
                    "mac_bind_count": 2,
                    "mac_restriction": True,
                    "max_simultaneous": 2,
                },
            )
            assert saved["configured"] is True
            listed = await api.get("/speed-group-device-rules")
            assert [i["speed_group_id"] for i in listed["items"]] == [grp]
            dry = await api.post(
                f"/speed-groups/{grp}/device-rules/apply", {"dry_run": True}
            )
            assert dry["would_change"] == 2 and dry["dry_run"] is True
            async with SessionLocal() as s:
                p = await s.get(IspPackage, uuid.UUID(pkg))
                assert p.max_devices == 1, "dry run wrote nothing"
                assert (
                    await s.execute(
                        select(IspPackagePolicy).where(
                            IspPackagePolicy.package_id == uuid.UUID(pkg)
                        )
                    )
                ).scalar_one_or_none() is None
            done = await api.post(
                f"/speed-groups/{grp}/device-rules/apply", {"dry_run": False}
            )
            assert done["would_change"] == 2
            for pid in (pkg, pkg2):
                pol = await api.get(f"/packages/{pid}/policy")
                assert (
                    pol["mac_bind_count"],
                    pol["mac_restriction"],
                    pol["max_simultaneous"],
                ) == (2, True, 2)
                assert (await api.get(f"/packages/{pid}"))["max_devices"] == 3
            pol2 = await api.get(f"/packages/{pkg2}/policy")
            assert (
                pol2["fup_limit_mb"] == 102400
                and pol2["fup_fallback_speed_group_id"] == slow
            )
            assert pol2["queue_priority"] == 3, "other policy fields untouched"
            pol1 = await api.get(f"/packages/{pkg}/policy")
            assert (
                pol1["fup_limit_mb"] is None and pol1["validity_starts"] == "activation"
            )
            again = await api.post(
                f"/speed-groups/{grp}/device-rules/apply", {"dry_run": False}
            )
            assert again["would_change"] == 0 and again["unchanged"] == 2

            # -- P1-2 billing cycle basis -----------------------------------
            assert (await api.get(f"/packages/{pkg}/cycle-basis"))["basis"] == "package"
            await api.put(
                f"/packages/{pkg}/cycle-basis", {"basis": "monthly"}, code=422
            )
            # package basis + flag on: still exactly 30 days
            before = await valid_until(sub)
            await api.post(
                f"/subscribers/{sub}/recharge",
                {"package_id": pkg, "idempotency_key": f"p1pk{w.tag}"},
            )
            assert await valid_until(sub) - before == timedelta(days=30)
            await api.put(f"/packages/{pkg}/cycle-basis", {"basis": "subscriber"})
            before = await valid_until(sub)
            res = await api.post(
                f"/subscribers/{sub}/recharge",
                {"package_id": pkg, "idempotency_key": f"p1sb{w.tag}"},
            )
            snapped = await valid_until(sub)
            assert snapped.astimezone(ist).day == 1, snapped
            assert abs((snapped - before) - timedelta(days=30)) <= timedelta(days=16)
            # DECISIONS-1: the first snapped period is pro-rated to whole rupees
            from app.domains.isp_partner.p1_cycle_hook import prorated_paise

            days = (snapped.astimezone(ist).date() - before.astimezone(ist).date()).days
            inv = await api.get(f"/billing/invoices/{res['invoice']['id']}")
            [li] = inv["lines"]
            if before.astimezone(ist).day == 1:  # test ran on an anchor-aligned day
                assert li["taxable_paise"] == 49900
            else:
                assert li["taxable_paise"] == prorated_paise(49900, days, 30), (
                    li,
                    days,
                )
                assert li["description"] == f"P1 30d (pro-rated {days} days)", li
                assert li["quantity"] == 1
            # the next renewal starts on the anchor: full price, not pro-rated
            res = await api.post(
                f"/subscribers/{sub}/recharge",
                {"package_id": pkg, "idempotency_key": f"p1sc{w.tag}"},
            )
            assert (await valid_until(sub)).astimezone(ist).day == 1
            inv = await api.get(f"/billing/invoices/{res['invoice']['id']}")
            [li] = inv["lines"]
            assert li["taxable_paise"] == 49900 and "pro-rated" not in li["description"]
            # a subscriber with no anchor day renews by validity
            sub2 = await subscriber(api, "A", c1, pkg, "p1s2")
            before = await valid_until(sub2)
            await api.post(
                f"/subscribers/{sub2}/recharge",
                {"package_id": pkg, "idempotency_key": f"p1na{w.tag}"},
            )
            assert await valid_until(sub2) - before == timedelta(days=30)
            assert (await api.get("/package-cycle-basis"))["items"] == [
                {"package_id": pkg, "basis": "subscriber"}
            ]

            # -- P1-3 zone coupon rights ------------------------------------
            north = (await api.post("/zones/tree", {"name": f"North {w.tag}"}))["id"]
            leaf = (
                await api.post(
                    "/zones/tree", {"name": f"Leaf {w.tag}", "parent_id": north}
                )
            )["id"]
            r = await api.get(f"/zones/{leaf}/coupon-right")
            assert (r["allow_generate"], r["explicit"], r["decided_by_zone_id"]) == (
                True,
                None,
                None,
            )
            await api.put(f"/zones/{north}/coupon-right", {"allow_generate": False})
            r = await api.get(f"/zones/{leaf}/coupon-right")
            assert (r["allow_generate"], r["decided_by_zone_id"]) == (False, north)
            await api.put(f"/zones/{leaf}/coupon-right", {"allow_generate": True})
            assert (await api.get(f"/zones/{leaf}/coupon-right"))[
                "allow_generate"
            ] is True
            await api.put(f"/zones/{leaf}/coupon-right", {"allow_generate": None})
            r = await api.get(f"/zones/{leaf}/coupon-right")
            assert (r["explicit"], r["allow_generate"]) == (None, False)

            # -- scope: other ISP -------------------------------------------
            await api.get(f"/speed-groups/{grp}/device-rules", who="B", code=404)
            await api.put(
                f"/speed-groups/{grp}/device-rules",
                {"max_devices": 1},
                who="B",
                code=404,
            )
            await api.post(
                f"/speed-groups/{grp}/device-rules/apply",
                {"dry_run": False},
                who="B",
                code=404,
            )
            await api.get(f"/packages/{pkg}/cycle-basis", who="B", code=404)
            await api.put(
                f"/packages/{pkg}/cycle-basis", {"basis": "package"}, who="B", code=404
            )
            await api.get(f"/zones/{north}/coupon-right", who="B", code=404)
            await api.put(
                f"/zones/{north}/coupon-right",
                {"allow_generate": True},
                who="B",
                code=404,
            )
            assert (await api.get("/speed-group-device-rules", who="B"))["items"] == []
            assert (await api.get("/package-cycle-basis", who="B"))["items"] == []

            # -- scope: confined (zone-restricted) staff --------------------
            for who in ("bill", "tech"):
                assert (await api.get(f"/speed-groups/{grp}/device-rules", who=who))[
                    "configured"
                ]
                await api.put(
                    f"/speed-groups/{grp}/device-rules",
                    {"max_devices": 1},
                    who=who,
                    code=403,
                )
                await api.post(
                    f"/speed-groups/{grp}/device-rules/apply",
                    {"dry_run": False},
                    who=who,
                    code=403,
                )
                await api.put(
                    f"/packages/{pkg}/cycle-basis",
                    {"basis": "package"},
                    who=who,
                    code=403,
                )
                await api.put(
                    f"/zones/{north}/coupon-right",
                    {"allow_generate": True},
                    who=who,
                    code=403,
                )
                await api.post(
                    "/speed-groups",
                    {"name": f"X{who}", "download_kbps": 1024, "upload_kbps": 1024},
                    who=who,
                    code=403,
                )
                await api.patch(
                    f"/packages/{pkg}", {"price_paise": 1}, who=who, code=403
                )
            assert (await api.get(f"/packages/{pkg}"))["price_paise"] == 49900

            b1 = (
                await api.post(
                    "/coupon-batches",
                    {"package_id": pkg, "isp_customer_id": c1, "quantity": 1},
                )
            )["id"]
            b2 = (
                await api.post(
                    "/coupon-batches",
                    {"package_id": pkg, "isp_customer_id": c2, "quantity": 1},
                )
            )["id"]
            seen = {
                b["id"] for b in (await api.get("/coupon-batches", who="bill"))["items"]
            }
            assert b1 in seen and b2 not in seen
            await api.get(f"/coupon-batches/{b2}", who="bill", code=404)
            await api.get(f"/coupon-batches/{b2}/coupons", who="bill", code=404)
            await api.post(
                "/coupon-batches",
                {"package_id": pkg, "isp_customer_id": c2, "quantity": 1},
                who="bill",
                code=404,
            )
            # a confined billing user (not a franchisee) is never gated by the zone right
            await api.post(
                "/coupon-batches",
                {"package_id": pkg, "isp_customer_id": c1, "quantity": 1},
                who="bill",
                code=(200, 201),
            )
            await api.post(
                "/coupon-batches",
                {"package_id": pkg, "isp_customer_id": c1, "quantity": 1},
                who="tech",
                code=403,
            )
    finally:
        for f in _FLAGS:
            os.environ.pop(f, None)
        _clear()
        await dispose()
