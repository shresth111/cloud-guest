# ruff: noqa: E501, PLR0915 -- scenario tests
"""BE-REVIEW regressions on real PostgreSQL + Redis (skipped unless
``ISP_TEST_PG_DSN`` is set; CI has neither). Run::

    CLOUDGUEST_DATABASE_URL=postgresql+asyncpg://postgres@127.0.0.1:55491/berev \\
    CLOUDGUEST_REDIS_URL=redis://127.0.0.1:56391/0 \\
    ISP_TEST_PG_DSN=1 ISP_PARTNER_ENABLED=true \\
    python -m pytest tests/unit/test_isp_be_review_postgres.py

One test per fix (BE_E2E_REVIEW.md):
* R1  two payments against one invoice at the same time: the second one used
  to read a stale balance, allocate it again and overwrite ``paid_paise``
  (allocations 2x the bill, invoice showing one payment);
* R2  a referral reward that covers a whole unpaid bill left it CANCELLED;
* R3  a zone-scoped list (``scope_zone_id``) ran the coupon subscriber sync
  through the zone filter, missed the existing subscribers outside the zone,
  tried to create them again and 500'd on the unique index;
* R4  one static IP lease that cannot be billed (archived customer) rolled
  back every other lease of the ISP, every day;
* R5  the coupon CSV wrote guest-entered identifiers without the formula guard.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("ISP_TEST_PG_DSN"), reason="set ISP_TEST_PG_DSN to run"
)

API = "/api/v1/isp"


@pytest.fixture(autouse=True)
async def _fresh_pool():  # noqa: ANN202
    """Each test runs on its own event loop: never reuse a pooled asyncpg
    connection from another loop."""
    from app.database.redis import redis_client
    from app.database.session import engine

    await engine.dispose()
    redis_client.connection_pool.reset()
    yield
    await engine.dispose()
    await redis_client.connection_pool.disconnect()


async def _world(tag: str, *, customers: int = 1) -> dict:
    """ISP A (owner), billing set up, ``customers`` customers, a 10M package
    at Rs 500. Returns ids + an ASGI app logged in as the owner."""
    from sqlalchemy import select

    from app.database.session import SessionLocal
    from app.domains.auth.models import AuthUser, User
    from app.domains.billing.models import Plan
    from app.domains.isp_partner.models import IspPartnerProfile
    from app.domains.isp_partner.seed import seed_isp_partner_rbac
    from app.domains.organization.models import Organization, OrganizationMember
    from app.domains.rbac.dependencies import CurrentUser
    from app.domains.rbac.models import Role, UserRole
    from app.domains.rbac.repository import RBACRepository
    from app.domains.rbac.seed import seed_rbac
    from app.main import create_app

    async with SessionLocal() as s:
        await seed_rbac(s)
        await seed_isp_partner_rbac(RBACRepository(s))
        await s.commit()
    async with SessionLocal() as s:
        plan = Plan(
            name=f"P {tag}",
            slug=f"br-{tag}",
            plan_type="standard",
            billing_cycle="monthly",
            base_price=Decimal("0"),
            currency="INR",
            is_active=True,
            is_public=False,
        )
        s.add(plan)
        role = (
            await s.execute(select(Role).where(Role.slug == "isp-owner"))
        ).scalar_one()
        org = Organization(
            name=f"Br {tag}",
            slug=f"brnet{tag}",
            org_type="msp",
            status="active",
            contact_email=f"br{tag}@example.com",
            timezone="Asia/Kolkata",
            settings={},
        )
        user = User(
            first_name="O",
            last_name="R",
            email=f"bro{tag}@example.com",
            username=f"bro{tag}",
            password_hash="x",
            is_active=True,
            is_verified=True,
        )
        s.add_all([org, user])
        await s.flush()
        s.add(
            IspPartnerProfile(organization_id=org.id, default_customer_plan_id=plan.id)
        )
        s.add_all(
            [
                OrganizationMember(
                    organization_id=org.id, user_id=user.id, status="active"
                ),
                UserRole(
                    user_id=user.id,
                    role_id=role.id,
                    scope_type="organization",
                    organization_id=org.id,
                    granted_at=datetime.now(UTC),
                    is_active=True,
                ),
            ]
        )
        await s.commit()
        isp_id, user_id = org.id, user.id

    app = create_app()
    app.dependency_overrides[CurrentUser] = lambda: AuthUser(
        id=str(user_id), email="o@example.com"
    )
    return {
        "app": app,
        "isp": isp_id,
        "user": user_id,
        "h": {"X-Organization-Id": str(isp_id)},
    }


async def _ctx(session, isp_id: uuid.UUID, user_id: uuid.UUID):  # noqa: ANN001, ANN202
    from app.domains.isp_partner.dependencies import IspContext
    from app.domains.isp_partner.repository import IspRepository

    repo = IspRepository(session)
    return IspContext(
        isp_org_id=isp_id,
        user_id=user_id,
        role_slug="isp-owner",
        role_id=uuid.uuid4(),
        confined_customer_ids=None,
        organization=await repo.get_organization(isp_id),
        profile=await repo.get_profile(isp_id),
        repository=repo,
    )


async def _basics(c, w: dict, tag: str, n_customers: int = 1) -> dict:  # noqa: ANN001
    async def call(method: str, path: str, body=None, ok=(200, 201)):  # noqa: ANN001, ANN202
        r = await c.request(method, f"{API}{path}", json=body, headers=w["h"])
        assert r.status_code in ok, (method, path, r.status_code, r.text)
        return r.json().get("data")

    await call(
        "PUT",
        "/billing/settings",
        {"legal_name": "Net", "state_code": "07", "invoice_prefix": "BR"},
    )
    cust = [
        (
            await call(
                "POST",
                "/customers",
                {"name": f"c{i} {tag}", "contact_email": f"c{i}{tag}@e.com"},
            )
        )["id"]
        for i in range(n_customers)
    ]
    g = (
        await call(
            "POST",
            "/speed-groups",
            {"name": "10M", "download_kbps": 10240, "upload_kbps": 10240},
        )
    )["id"]
    pkg = (
        await call(
            "POST",
            "/packages",
            {"speed_group_id": g, "type": "prepaid", "price_paise": 50000},
        )
    )["id"]
    return {"call": call, "cust": cust, "pkg": pkg}


# ---------------------------------------------------------------------------
# R1: concurrent payments on one invoice
# ---------------------------------------------------------------------------


async def test_r1_concurrent_payments_never_overpay_one_invoice() -> None:
    import httpx
    from sqlalchemy import func, select

    from app.database.session import SessionLocal
    from app.domains.isp_partner.billing_models import IspInvoice, IspPaymentAllocation
    from app.domains.isp_partner.billing_service import IspBillingService
    from app.domains.isp_partner.exceptions import IspInvoicePaidError

    tag = uuid.uuid4().hex[:8]
    w = await _world(tag)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=w["app"]), base_url="http://t"
    ) as c:
        b = await _basics(c, w, tag)
        sid = (
            await b["call"](
                "POST",
                "/subscribers",
                {
                    "isp_customer_id": b["cust"][0],
                    "identifier": f"p{tag}",
                    "package_id": b["pkg"],
                },
            )
        )["id"]
        inv = (
            await b["call"](
                "POST", f"/subscribers/{sid}/renew", {"idempotency_key": f"r1-{tag}"}
            )
        )["invoice"]
    inv_id = uuid.UUID(inv["id"])
    total = inv["total_paise"]

    first_done, release = asyncio.Event(), asyncio.Event()

    async def pay(hold: bool) -> str:
        async with SessionLocal() as s:
            ctx = await _ctx(s, w["isp"], w["user"])
            try:
                await IspBillingService(session=s).record_payment(
                    ctx,
                    amount_paise=total,
                    mode="cash",
                    subscriber_id=uuid.UUID(sid),
                    invoice_id=inv_id,
                )
            except IspInvoicePaidError:
                await s.rollback()
                return "already_paid"
            if hold:
                first_done.set()
                await release.wait()
            await s.commit()
            return "paid"

    t1 = asyncio.create_task(pay(True))
    await first_done.wait()
    t2 = asyncio.create_task(pay(False))
    await asyncio.sleep(0.5)  # t2 is now waiting on a lock (fixed) or done (bug)
    release.set()
    results = sorted(await asyncio.gather(t1, t2))

    async with SessionLocal() as s:
        row = await s.get(IspInvoice, inv_id)
        allocated = (
            await s.execute(
                select(
                    func.coalesce(func.sum(IspPaymentAllocation.amount_paise), 0)
                ).where(
                    IspPaymentAllocation.invoice_id == inv_id,
                    IspPaymentAllocation.is_deleted.is_(False),
                )
            )
        ).scalar_one()
    assert allocated == row.paid_paise == total, (allocated, row.paid_paise, total)
    assert results == ["already_paid", "paid"]
    assert row.status == "paid"


# ---------------------------------------------------------------------------
# R2: a referral reward that covers the whole bill settles it
# ---------------------------------------------------------------------------


async def test_r2_full_referral_credit_settles_not_cancels() -> None:
    import httpx
    from sqlalchemy import select, update

    from app.database.session import SessionLocal
    from app.domains.isp_partner.billing_models import IspInvoice
    from app.domains.isp_partner.plans_models import IspSubscriber
    from app.domains.isp_partner.referrals_config import get_referrals_settings
    from app.domains.isp_partner.referrals_service import run_referrals

    tag = uuid.uuid4().hex[:8]
    w = await _world(tag)
    os.environ["ISP_REFERRALS_ENABLED"] = "true"
    get_referrals_settings.cache_clear()
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=w["app"]), base_url="http://t"
        ) as c:
            b = await _basics(c, w, tag)
            call = b["call"]

            async def sub(ident: str, age: int) -> str:
                sid = (
                    await call(
                        "POST",
                        "/subscribers",
                        {
                            "isp_customer_id": b["cust"][0],
                            "identifier": ident,
                            "package_id": b["pkg"],
                        },
                    )
                )["id"]
                async with SessionLocal() as s:
                    await s.execute(
                        update(IspSubscriber)
                        .where(IspSubscriber.id == uuid.UUID(sid))
                        .values(created_at=datetime.now(UTC) - timedelta(days=age))
                    )
                    await s.commit()
                return sid

            ra, rb = await sub(f"ra{tag}", 200), await sub(f"rb{tag}", 1)
            first = (
                await call(
                    "POST", f"/subscribers/{rb}/renew", {"idempotency_key": f"rb-{tag}"}
                )
            )["invoice"]
            await call(
                "PUT",
                "/referrals/settings",
                {"enabled": True, "reward_paise": 500000, "max_rewards_per_year": 5},
            )
            r = await call(
                "POST",
                "/referrals",
                {"referrer_subscriber_id": ra, "referred_subscriber_id": rb},
            )
            await call(
                "POST",
                "/billing/payments",
                {
                    "subscriber_id": rb,
                    "invoice_id": first["id"],
                    "amount_paise": first["total_paise"],
                    "mode": "cash",
                },
            )

            async def tick() -> None:
                async with SessionLocal() as s:
                    await run_referrals(s)
                    await s.commit()

            await tick()
            assert (await call("GET", f"/referrals/{r['id']}"))["status"] == "earned"
            bill = (
                await call(
                    "POST", f"/subscribers/{ra}/renew", {"idempotency_key": f"ra-{tag}"}
                )
            )["invoice"]
            await tick()
            got = await call("GET", f"/referrals/{r['id']}")
            assert (
                got["status"] == "applied"
                and got["applied_paise"] == bill["total_paise"]
            )
        async with SessionLocal() as s:
            inv = (
                await s.execute(
                    select(IspInvoice).where(IspInvoice.id == uuid.UUID(bill["id"]))
                )
            ).scalar_one()
        assert inv.credit_noted_paise == inv.total_paise and inv.paid_paise == 0
        # settled by the reward, not a cancelled renewal
        assert inv.status == "paid", inv.status
    finally:
        os.environ.pop("ISP_REFERRALS_ENABLED", None)
        get_referrals_settings.cache_clear()


# ---------------------------------------------------------------------------
# R3: zone-scoped list + coupon sync
# ---------------------------------------------------------------------------


async def test_r3_zone_scoped_list_does_not_duplicate_hidden_coupon_subscribers() -> (
    None
):
    import httpx
    from sqlalchemy import func, select, update

    from app.database.session import SessionLocal
    from app.domains.isp_partner import plans_service
    from app.domains.isp_partner.billing_models import IspZone
    from app.domains.isp_partner.models import IspCustomerProfile
    from app.domains.isp_partner.plans_models import IspSubscriber
    from app.domains.isp_partner.zones_config import get_zones_settings
    from app.domains.voucher.models import Voucher

    tag = uuid.uuid4().hex[:8]
    w = await _world(tag)
    os.environ["ISP_ZONES_ENABLED"] = "true"
    get_zones_settings.cache_clear()
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=w["app"], raise_app_exceptions=False),
            base_url="http://t",
        ) as c:
            b = await _basics(c, w, tag, n_customers=2)
            c1, c2 = (uuid.UUID(x) for x in b["cust"])
            async with SessionLocal() as s:
                za = IspZone(isp_organization_id=w["isp"], name=f"A {tag}")
                zb = IspZone(isp_organization_id=w["isp"], name=f"B {tag}")
                s.add_all([za, zb])
                await s.flush()
                for cid, z in ((c1, za), (c2, zb)):
                    await s.execute(
                        update(IspCustomerProfile)
                        .where(IspCustomerProfile.customer_organization_id == cid)
                        .values(zone_id=z.id)
                    )
                await s.commit()
                zone_a = za.id
            await b["call"](
                "POST",
                "/coupon-batches",
                {"package_id": b["pkg"], "isp_customer_id": str(c2), "quantity": 1},
            )
            async with SessionLocal() as s:
                v = (
                    await s.execute(
                        select(Voucher).where(Voucher.organization_id == c2)
                    )
                ).scalar_one()
                v.redeemed_identifier = f"cp{tag}"
                v.redeemed_at = datetime.now(UTC) - timedelta(minutes=5)
                v.expires_at = datetime.now(UTC) + timedelta(days=30)
                await s.commit()
            plans_service._last_sync.clear()
            await b["call"](
                "GET", "/subscribers"
            )  # unscoped: creates the c2 subscriber
            plans_service._last_sync.clear()
            r = await c.get(
                f"{API}/subscribers",
                params={"scope_zone_id": str(zone_a)},
                headers=w["h"],
            )
            assert r.status_code == 200, r.text
            async with SessionLocal() as s:
                n = (
                    await s.execute(
                        select(func.count())
                        .select_from(IspSubscriber)
                        .where(
                            IspSubscriber.customer_organization_id == c2,
                            IspSubscriber.is_deleted.is_(False),
                        )
                    )
                ).scalar_one()
            assert n == 1
    finally:
        os.environ.pop("ISP_ZONES_ENABLED", None)
        get_zones_settings.cache_clear()


# ---------------------------------------------------------------------------
# R4: one bad lease never blocks the others
# ---------------------------------------------------------------------------


async def test_r4_one_unbillable_lease_does_not_block_the_rest() -> None:
    import httpx
    from sqlalchemy import select, update

    from app.database.session import SessionLocal
    from app.domains.isp_partner.billing_models import IspInvoice
    from app.domains.isp_partner.finance_config import get_finance_settings
    from app.domains.isp_partner.finance_models import IspStaticIpLease
    from app.domains.isp_partner.finance_tasks import run_finance_daily
    from app.domains.organization.models import Organization

    tag = uuid.uuid4().hex[:8]
    w = await _world(tag)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=w["app"]), base_url="http://t"
    ) as c:
        b = await _basics(c, w, tag, n_customers=2)
    c1, c2 = (uuid.UUID(x) for x in b["cust"])
    today = date.today()
    async with SessionLocal() as s:
        good = IspStaticIpLease(
            isp_organization_id=w["isp"],
            customer_organization_id=c1,
            ip_address="203.0.113.10",
            monthly_amount_paise=30000,
            price_includes_gst=False,
            active_since=today,
            status="active",
        )
        bad = IspStaticIpLease(
            isp_organization_id=w["isp"],
            customer_organization_id=c2,
            ip_address="203.0.113.11",
            monthly_amount_paise=30000,
            price_includes_gst=False,
            active_since=today,
            status="active",
        )
        s.add_all([good, bad])
        await s.execute(
            update(Organization).where(Organization.id == c2).values(status="archived")
        )
        await s.commit()
        good_id, bad_id = good.id, bad.id
    os.environ["ISP_FINANCE_EXTRAS_ENABLED"] = "true"
    get_finance_settings.cache_clear()
    try:
        async with SessionLocal() as s:
            ctx = await _ctx(s, w["isp"], None)
            out = await run_finance_daily(s, ctx, today)
            await s.commit()
    finally:
        os.environ.pop("ISP_FINANCE_EXTRAS_ENABLED", None)
        get_finance_settings.cache_clear()
    assert out["lease_invoices"] == 1, out
    async with SessionLocal() as s:
        keys = set(
            (
                await s.execute(
                    select(IspInvoice.source_key).where(
                        IspInvoice.isp_organization_id == w["isp"]
                    )
                )
            ).scalars()
        )
        assert f"sip:{good_id}:{today.isoformat()}" in keys
        assert f"sip:{bad_id}:{today.isoformat()}" not in keys
        assert (await s.get(IspStaticIpLease, good_id)).billed_through is not None


# ---------------------------------------------------------------------------
# R5: coupon CSV formula guard
# ---------------------------------------------------------------------------


async def test_r5_coupon_csv_guards_formula_cells() -> None:
    import httpx
    from sqlalchemy import select

    from app.database.session import SessionLocal
    from app.domains.isp_partner.plans_models import IspCouponBatch
    from app.domains.voucher.models import Voucher

    tag = uuid.uuid4().hex[:8]
    w = await _world(tag)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=w["app"]), base_url="http://t"
    ) as c:
        b = await _basics(c, w, tag)
        cust = uuid.UUID(b["cust"][0])
        await b["call"](
            "POST",
            "/coupon-batches",
            {"package_id": b["pkg"], "isp_customer_id": str(cust), "quantity": 1},
        )
        async with SessionLocal() as s:
            v = (
                await s.execute(select(Voucher).where(Voucher.organization_id == cust))
            ).scalar_one()
            v.redeemed_identifier = '=HYPERLINK("http://x.example","y")'
            v.redeemed_at = datetime.now(UTC)
            batch = (
                await s.execute(
                    select(IspCouponBatch).where(
                        IspCouponBatch.customer_organization_id == cust
                    )
                )
            ).scalar_one()
            await s.commit()
        r = await c.get(f"{API}/coupon-batches/{batch.id}/export.csv", headers=w["h"])
        assert r.status_code == 200, r.text
        body = r.text
    assert "=HYPERLINK" in body
    assert ",=HYPERLINK" not in body and '"=HYPERLINK' not in body, body
