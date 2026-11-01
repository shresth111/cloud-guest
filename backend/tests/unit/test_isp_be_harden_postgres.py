# ruff: noqa: E501, PLR0915 -- scenario tests
"""BE-HARDEN on real PostgreSQL + Redis (skipped unless ``ISP_TEST_PG_DSN``;
CI has neither). Same env as ``test_isp_be_review_postgres.py``.

* H1 daily billing: one transaction per ISP; while the next ISP runs, the
  previous ISP's invoice-number row is already free;
* H2 120 s pass: overlap guard (Redis lock with TTL), lock released after,
  and a failing hook does not stop the next one;
* H3 coupon sync: no GET runs it; "sync now" + the background pass apply new
  redemptions incrementally from the watermark; a lapsed row reads
  ``expired`` before the background flip; single-flight per ISP;
* H4 referrals: keyset pages, so stale pending rows never starve a newer
  actionable one;
* H5 concurrent renewals: reverting the second one restores the first one's
  validity, not the pre-both value;
* H6 static IP: anniversary periods from the start day, pro-rata last month;
* H7 zone share on void (founder 2026-11-01): back only the share of the
  unpaid part; credit notes in proportion; a retry never refunds twice.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from datetime import UTC, date, datetime, timedelta

import pytest

from tests.unit.test_isp_be_review_postgres import (  # noqa: F401 (fixture)
    API,
    _basics,
    _ctx,
    _fresh_pool,
    _world,
)

pytestmark = pytest.mark.skipif(
    not os.environ.get("ISP_TEST_PG_DSN"), reason="set ISP_TEST_PG_DSN to run"
)


def _client(app):  # noqa: ANN001, ANN202
    import httpx

    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://t",
    )


# ---------------------------------------------------------------------------
# H1
# ---------------------------------------------------------------------------


async def test_h1_daily_billing_commits_per_isp(monkeypatch) -> None:  # noqa: ANN001
    from sqlalchemy import select, text

    from app.database.session import SessionLocal
    from app.domains.isp_partner import tasks
    from app.domains.isp_partner.billing_models import IspInvoiceSequence
    from app.domains.isp_partner.billing_service import IspBillingService
    from app.domains.isp_partner.gst import fiscal_year

    worlds = []
    for _ in range(2):
        tag = uuid.uuid4().hex[:8]
        w = await _world(tag)
        async with _client(w["app"]) as c:
            await _basics(c, w, tag)
        worlds.append(w)
    mine = {w["isp"] for w in worlds}
    # the series rows must already exist (committed), as they do on any ISP
    # that has billed once; a row created inside the run is invisible to the
    # probe and would prove nothing
    async with SessionLocal() as s:
        for w in worlds:
            ctx = await _ctx(s, w["isp"], w["user"])
            svc = IspBillingService(session=s)
            await svc._allocate(w["isp"], "invoice", fiscal_year(svc.today(ctx)))
        await s.commit()
    seen: list[uuid.UUID] = []
    probes: list[str] = []
    real = IspBillingService.generate_due

    async def spy(self, isp):  # noqa: ANN001, ANN202
        out = await real(self, isp)
        if isp.isp_org_id in mine:
            if seen:  # the other one of mine already ran: is its row free?
                async with SessionLocal() as probe:
                    await probe.execute(text("SET LOCAL lock_timeout = '500ms'"))
                    try:
                        await probe.execute(
                            select(IspInvoiceSequence.id)
                            .where(IspInvoiceSequence.isp_organization_id == seen[0])
                            .with_for_update()
                        )
                        probes.append("free")
                    except Exception:  # noqa: BLE001
                        probes.append("locked")
                    await probe.rollback()
            else:
                # what a real cycle invoice does: take the series row lock
                await self._allocate(
                    isp.isp_org_id, "invoice", fiscal_year(self.today(isp))
                )
            seen.append(isp.isp_org_id)
        return out

    monkeypatch.setattr(IspBillingService, "generate_due", spy)
    summary = await tasks._billing_daily_async()
    assert len(seen) == 2, (seen, summary)
    assert probes == ["free"], probes


# ---------------------------------------------------------------------------
# H2
# ---------------------------------------------------------------------------


async def test_h2_retry_pass_overlap_guard_and_hook_isolation(monkeypatch) -> None:  # noqa: ANN001
    from app.database.redis import create_redis_client
    from app.domains.isp_partner import queued_renewal_service, referrals_service, tasks

    r = create_redis_client()
    try:
        await r.set(tasks.RETRY_LOCK_KEY, "someone-else", ex=60)
        out = await tasks._retry_async()
        assert out.get("skipped_overlap") == 1
        assert await r.get(tasks.RETRY_LOCK_KEY) in (b"someone-else", "someone-else")
        await r.delete(tasks.RETRY_LOCK_KEY)

        ran = []

        async def boom(session, **kw):  # noqa: ANN001, ANN202, ARG001
            raise RuntimeError("queued renewals down")

        async def refs(session, **kw):  # noqa: ANN001, ANN202, ARG001
            ran.append("referrals")
            return {}

        monkeypatch.setattr(queued_renewal_service, "run_queued_renewals", boom)
        monkeypatch.setattr(referrals_service, "run_referrals", refs)
        out = await tasks._retry_async()
        assert "skipped_overlap" not in out
        assert out["errors"] >= 1 and ran == ["referrals"]
        assert await r.get(tasks.RETRY_LOCK_KEY) is None  # released
    finally:
        await r.aclose()


# ---------------------------------------------------------------------------
# H3
# ---------------------------------------------------------------------------


async def test_h3_coupon_sync_is_background_incremental_single_flight() -> None:
    from sqlalchemy import func, select, text

    from app.database.session import SessionLocal
    from app.domains.isp_partner.coupon_sync import IspCouponSyncState
    from app.domains.isp_partner.plans_models import IspSubscriber
    from app.domains.voucher.models import Voucher

    tag = uuid.uuid4().hex[:8]
    w = await _world(tag)
    async with _client(w["app"]) as c:
        b = await _basics(c, w, tag)
        cust = uuid.UUID(b["cust"][0])
        await b["call"](
            "POST",
            "/coupon-batches",
            {"package_id": b["pkg"], "isp_customer_id": str(cust), "quantity": 2},
        )
        now = datetime.now(UTC)
        async with SessionLocal() as s:
            vs = list(
                (
                    await s.execute(
                        select(Voucher)
                        .where(Voucher.organization_id == cust)
                        .order_by(Voucher.id)
                    )
                ).scalars()
            )
            vs[0].redeemed_identifier, vs[0].redeemed_at = (
                f"v1{tag}",
                now - timedelta(minutes=3),
            )
            vs[0].expires_at = now + timedelta(days=30)
            await s.commit()

        async def count() -> int:
            async with SessionLocal() as s:
                return (
                    await s.execute(
                        select(func.count())
                        .select_from(IspSubscriber)
                        .where(IspSubscriber.customer_organization_id == cust)
                    )
                ).scalar_one()

        # no GET syncs any more
        assert (await b["call"]("GET", "/subscribers"))["total"] == 0
        assert await count() == 0
        assert (await b["call"]("POST", "/subscribers/sync"))["applied"] == 1
        assert await count() == 1
        async with SessionLocal() as s:
            st = (
                await s.execute(
                    select(IspCouponSyncState).where(
                        IspCouponSyncState.isp_organization_id == w["isp"]
                    )
                )
            ).scalar_one()
            assert st.watermark_at is not None and st.last_applied == 1
        # a second redemption: only it is applied (the first is a no-op)
        async with SessionLocal() as s:
            v2 = await s.get(Voucher, vs[1].id)
            v2.redeemed_identifier, v2.redeemed_at = f"v2{tag}", datetime.now(UTC)
            v2.expires_at = datetime.now(UTC) + timedelta(days=30)
            await s.commit()
        assert (await b["call"]("POST", "/subscribers/sync"))["applied"] == 1
        assert await count() == 2
        assert (await b["call"]("POST", "/subscribers/sync"))["applied"] == 0
        # lapsed but not yet flipped: reads expired, filters as expired
        async with SessionLocal() as s:
            sub = (
                await s.execute(
                    select(IspSubscriber).where(IspSubscriber.identifier == f"v1{tag}")
                )
            ).scalar_one()
            sub.valid_until, sub.status = (
                datetime.now(UTC) - timedelta(hours=1),
                "active",
            )
            await s.commit()
        items = (await b["call"]("GET", "/subscribers"))["items"]
        assert {i["identifier"][-11:]: i["status"] for i in items}[
            f"v1{tag}"[-11:]
        ] == "expired"
        assert (await b["call"]("GET", "/subscribers?status=expired"))["total"] == 1
        assert (await b["call"]("GET", "/subscribers?status=active"))["total"] == 1
        # single flight: while another session holds the ISP, sync returns 0
        async with SessionLocal() as holder:
            await holder.execute(
                text("SELECT pg_advisory_xact_lock(hashtext(:k))"),
                {"k": f"isp_coupon_sync:{w['isp']}"},
            )
            assert (await b["call"]("POST", "/subscribers/sync"))["applied"] == 0
            await holder.rollback()


# ---------------------------------------------------------------------------
# H4
# ---------------------------------------------------------------------------


async def test_h4_referral_keyset_never_starves(monkeypatch) -> None:  # noqa: ANN001
    from sqlalchemy import select

    from app.database.session import SessionLocal
    from app.domains.isp_partner import referrals_service
    from app.domains.isp_partner.referrals_config import get_referrals_settings
    from app.domains.isp_partner.referrals_models import IspReferral

    tag = uuid.uuid4().hex[:8]
    w = await _world(tag)
    os.environ["ISP_REFERRALS_ENABLED"] = "true"
    get_referrals_settings.cache_clear()
    monkeypatch.setattr(referrals_service, "REFERRAL_PAGE", 2)
    try:
        async with _client(w["app"]) as c:
            b = await _basics(c, w, tag)
            call, cust = b["call"], b["cust"][0]
            subs = [
                (
                    await call(
                        "POST",
                        "/subscribers",
                        {
                            "isp_customer_id": cust,
                            "identifier": f"k{i}{tag}",
                            "package_id": b["pkg"],
                        },
                    )
                )["id"]
                for i in range(6)
            ]
            await call(
                "PUT",
                "/referrals/settings",
                {"enabled": True, "reward_paise": 1000, "max_rewards_per_year": 5},
            )
            base = datetime.now(UTC) - timedelta(days=1)
            async with SessionLocal() as s:
                for i, referred in enumerate(subs[1:]):
                    s.add(
                        IspReferral(
                            isp_organization_id=w["isp"],
                            referrer_subscriber_id=uuid.UUID(subs[0]),
                            referred_subscriber_id=uuid.UUID(referred),
                            referrer_customer_id=uuid.UUID(cust),
                            referred_customer_id=uuid.UUID(cust),
                            status="pending",
                            history=[],
                            created_at=base + timedelta(minutes=i),
                        )
                    )
                await s.commit()
            # only the NEWEST referred subscriber pays its first bill
            inv = (
                await call(
                    "POST",
                    f"/subscribers/{subs[5]}/renew",
                    {"idempotency_key": f"h4-{tag}"},
                )
            )["invoice"]
            await call(
                "POST",
                "/billing/payments",
                {
                    "subscriber_id": subs[5],
                    "invoice_id": inv["id"],
                    "amount_paise": inv["total_paise"],
                    "mode": "cash",
                },
            )
        async with SessionLocal() as s:
            out = await referrals_service.run_referrals(s, commit_each=True)
            await s.commit()
        assert out["referrals"] == 1, out  # stale pending rows are not even read
        async with SessionLocal() as s:
            rows = {
                str(r.referred_subscriber_id): r.status
                for r in (
                    await s.execute(
                        select(IspReferral).where(
                            IspReferral.isp_organization_id == w["isp"]
                        )
                    )
                ).scalars()
            }
        assert rows[subs[5]] == "earned"
        assert [rows[x] for x in subs[1:5]] == ["pending"] * 4
    finally:
        os.environ.pop("ISP_REFERRALS_ENABLED", None)
        get_referrals_settings.cache_clear()


# ---------------------------------------------------------------------------
# H5
# ---------------------------------------------------------------------------


async def test_h5_concurrent_renewals_then_revert_keeps_the_first() -> None:
    from app.database.session import SessionLocal
    from app.domains.isp_partner.plans_models import IspSubscriber
    from app.domains.isp_partner.plans_service import IspPlansService
    from app.domains.isp_partner.subscriber360_service import IspSubscriber360Service

    tag = uuid.uuid4().hex[:8]
    w = await _world(tag)
    async with _client(w["app"]) as c:
        b = await _basics(c, w, tag)
        sid = uuid.UUID(
            (
                await b["call"](
                    "POST",
                    "/subscribers",
                    {
                        "isp_customer_id": b["cust"][0],
                        "identifier": f"h5{tag}",
                        "package_id": b["pkg"],
                    },
                )
            )["id"]
        )
    async with SessionLocal() as s:
        t0 = (await s.get(IspSubscriber, sid)).valid_until

    first_done, release = asyncio.Event(), asyncio.Event()

    async def renew(key: str, hold: bool) -> datetime:
        async with SessionLocal() as s:
            ctx = await _ctx(s, w["isp"], w["user"])
            svc = IspSubscriber360Service(
                plans=IspPlansService(session=s), guest_service=None
            )
            out = await svc.renew(ctx, sid, {"idempotency_key": key})
            if hold:
                first_done.set()
                await release.wait()
            await s.commit()
            return datetime.fromisoformat(out["subscriber"]["valid_until"])

    t1_task = asyncio.create_task(renew(f"h5a-{tag}", True))
    await first_done.wait()
    t2_task = asyncio.create_task(renew(f"h5b-{tag}", False))
    await asyncio.sleep(0.5)
    release.set()
    t1, t2 = await asyncio.gather(t1_task, t2_task)
    assert t0 < t1 < t2
    async with SessionLocal() as s:
        ctx = await _ctx(s, w["isp"], w["user"])
        svc = IspSubscriber360Service(
            plans=IspPlansService(session=s), guest_service=None
        )
        out = await svc.revert(ctx, sid, reason="test")
        await s.commit()
    assert datetime.fromisoformat(out["valid_until"]) == t1, (out, t0, t1)


# ---------------------------------------------------------------------------
# H6
# ---------------------------------------------------------------------------


def test_h6_lease_period_maths() -> None:
    from app.domains.isp_partner.finance_service import lease_period as lp

    jan31 = date(2026, 1, 31)
    assert lp(jan31, jan31, 30000) == (date(2026, 2, 27), 30000)
    assert lp(jan31, date(2026, 2, 28), 30000) == (date(2026, 3, 30), 30000)
    assert lp(jan31, date(2026, 3, 31), 30000) == (
        date(2026, 4, 29),
        30000,
    )  # back on the 31st
    # final partial: 10 Mar - 24 Mar of a 10 Mar - 9 Apr (31-day) period
    assert lp(
        date(2026, 1, 10), date(2026, 3, 10), 31000, active_until=date(2026, 3, 24)
    ) == (date(2026, 3, 24), 15000)
    # off-anniversary start (old drifted row): to the next anniversary, pro rata
    end, amt = lp(jan31, date(2026, 3, 28), 30000)
    assert end == date(2026, 3, 30) and amt == round(30000 * 3 / 31)


async def test_h6_lease_billing_anniversary_and_prorated_end() -> None:
    from sqlalchemy import select

    from app.database.session import SessionLocal
    from app.domains.isp_partner.billing_models import IspInvoice, IspInvoiceLine
    from app.domains.isp_partner.finance_models import IspStaticIpLease
    from app.domains.isp_partner.finance_service import IspFinanceService

    tag = uuid.uuid4().hex[:8]
    w = await _world(tag)
    async with _client(w["app"]) as c:
        b = await _basics(c, w, tag)
    async with SessionLocal() as s:
        lease = IspStaticIpLease(
            isp_organization_id=w["isp"],
            customer_organization_id=uuid.UUID(b["cust"][0]),
            ip_address="198.51.100.7",
            monthly_amount_paise=31000,
            price_includes_gst=False,
            active_since=date(2026, 1, 10),
            active_until=date(2026, 3, 24),
            status="ended",
        )
        s.add(lease)
        await s.commit()
        lid = lease.id
    async with SessionLocal() as s:
        ctx = await _ctx(s, w["isp"], w["user"])
        out = await IspFinanceService(session=s).bill_leases(
            ctx, as_of=date(2026, 11, 1)
        )
        await s.commit()
    assert out["invoices_issued"] == 3
    async with SessionLocal() as s:
        lines = (
            await s.execute(
                select(
                    IspInvoiceLine.period_from,
                    IspInvoiceLine.period_to,
                    IspInvoiceLine.unit_amount_paise,
                )
                .join(IspInvoice, IspInvoice.id == IspInvoiceLine.invoice_id)
                .where(IspInvoice.source_key.like(f"sip:{lid}:%"))
                .order_by(IspInvoiceLine.period_from)
            )
        ).all()
    assert [tuple(x) for x in lines] == [
        (date(2026, 1, 10), date(2026, 2, 9), 31000),
        (date(2026, 2, 10), date(2026, 3, 9), 31000),
        (date(2026, 3, 10), date(2026, 3, 24), 15000),
    ]


# ---------------------------------------------------------------------------
# H7
# ---------------------------------------------------------------------------


async def test_h7_zone_share_on_void_is_the_unpaid_part_only() -> None:
    from sqlalchemy import func, select

    from app.database.session import SessionLocal
    from app.domains.isp_partner.billing_models import IspInvoice
    from app.domains.isp_partner.finance_config import get_finance_settings
    from app.domains.isp_partner.franchise_models import IspZoneAutoDebit
    from app.domains.isp_partner.franchise_service import get_franchise_settings

    flags = (
        "ISP_FRANCHISE_ENABLED",
        "ISP_ZONE_AUTODEBIT_ENABLED",
        "ISP_ZONE_LEDGER_ENABLED",
    )
    for k in flags:
        os.environ[k] = "true"
    get_franchise_settings.cache_clear()
    get_finance_settings.cache_clear()
    tag = uuid.uuid4().hex[:8]
    w = await _world(tag)
    try:
        async with _client(w["app"]) as c:
            b = await _basics(c, w, tag)
            call = b["call"]
            z = (
                await call("POST", "/zones", {"name": f"Z {tag}", "state_code": "07"})
            )["id"]
            # zone keeps 70 % -> ISP share 30 %
            await call("PUT", f"/finance/zones/{z}/profile", {"revenue_share_bp": 7000})
            await call("PUT", f"/franchise/zones/{z}/share", {"mode": "percent"})

            async def bill(ident: str) -> dict:
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
                await call("PATCH", f"/subscribers/{sid}", {"zone_id": z})
                inv = (
                    await call(
                        "POST",
                        f"/subscribers/{sid}/renew",
                        {"idempotency_key": f"{ident}-r"},
                    )
                )["invoice"]
                return {"sid": sid, **inv}

            async def moves(inv_id: str) -> tuple[int, int]:
                async with SessionLocal() as s:
                    q = (
                        select(
                            IspZoneAutoDebit.kind,
                            func.coalesce(func.sum(IspZoneAutoDebit.amount_paise), 0),
                        )
                        .where(IspZoneAutoDebit.invoice_id == uuid.UUID(inv_id))
                        .group_by(IspZoneAutoDebit.kind)
                    )
                    got = dict((await s.execute(q)).all())
                return int(got.get("debit", 0)), int(got.get("reversal", 0))

            async def pay(inv: dict, amount: int) -> None:
                await call(
                    "POST",
                    "/billing/payments",
                    {
                        "subscriber_id": inv["sid"],
                        "invoice_id": inv["id"],
                        "amount_paise": amount,
                        "mode": "cash",
                    },
                )

            # (a) unpaid, voided: the whole share back
            a = await bill(f"za{tag}")
            debit, _ = await moves(a["id"])
            assert debit == a["total_paise"] * 3000 // 10000 > 0
            await call("POST", f"/billing/invoices/{a['id']}/void", {"reason": "t"})
            assert await moves(a["id"]) == (debit, debit)

            # (b) 40 % paid, voided: share of the unpaid 60 % only
            bb = await bill(f"zb{tag}")
            total = bb["total_paise"]
            paid = total * 4 // 10
            await pay(bb, paid)
            await call("POST", f"/billing/invoices/{bb['id']}/void", {"reason": "t"})
            d, rev = await moves(bb["id"])
            assert rev == d * (total - paid) // total, (d, rev)
            assert d - rev > 0  # the paid part's share stays debited
            # retry: a second void is refused and refunds nothing more
            r = await c.post(
                f"{API}/billing/invoices/{bb['id']}/void",
                json={"reason": "t"},
                headers=w["h"],
            )
            assert r.status_code >= 400
            assert await moves(bb["id"]) == (d, rev)
            # retry of the cancellation hook itself (status re-set in a flush)
            async with SessionLocal() as s:
                inv = await s.get(IspInvoice, uuid.UUID(bb["id"]))
                inv.status = "partially_paid"
                await s.flush()
                inv.status = "cancelled"
                await s.commit()
            assert await moves(bb["id"]) == (d, rev)

            # (c) part-paid then a partial credit note: share of the note
            cc = await bill(f"zc{tag}")
            await pay(cc, cc["total_paise"] // 2)
            note = cc["total_paise"] // 5
            await call(
                "POST",
                f"/invoices/{cc['id']}/credit-note",
                {"amount_paise": note, "reason": "goodwill"},
            )
            d, rev = await moves(cc["id"])
            assert rev == d * note // cc["total_paise"]

            # (d) fully paid: a credit note is refused (no balance), nothing moves
            dd = await bill(f"zd{tag}")
            await pay(dd, dd["total_paise"])
            r = await c.post(
                f"{API}/invoices/{dd['id']}/credit-note",
                json={"amount_paise": 100, "reason": "x"},
                headers=w["h"],
            )
            assert r.status_code == 422, r.text  # ISP_CREDIT_EXCEEDS_BALANCE
            d, rev = await moves(dd["id"])
            assert d > 0 and rev == 0
    finally:
        for k in flags:
            os.environ.pop(k, None)
        get_franchise_settings.cache_clear()
        get_finance_settings.cache_clear()
