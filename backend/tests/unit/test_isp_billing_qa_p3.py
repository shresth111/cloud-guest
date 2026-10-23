"""QA pass 1 billing P3s: QA-004 (seller GSTIN error code), QA-007 (SMS
reminder must not "succeed"), QA-008 (a voided, partly paid invoice must not
read "paid")."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from app.domains.isp_partner import billing_router
from app.domains.isp_partner.billing_service import IspBillingService, status_for
from app.domains.isp_partner.exceptions import (
    IspSellerGstinInvalidError,
    IspSmsRemindersUnavailableError,
)


async def test_invalid_seller_gstin_uses_the_seller_code() -> None:
    svc = IspBillingService.__new__(IspBillingService)
    with pytest.raises(IspSellerGstinInvalidError) as exc:
        await svc.put_settings(SimpleNamespace(), {"gstin": "NOT-A-GSTIN"})
    assert exc.value.code == "ISP_SELLER_GSTIN_INVALID"


async def test_sms_reminder_is_refused_not_reported_as_sent(monkeypatch) -> None:
    called = []

    async def remind(*a, **kw):
        called.append(a)
        return True

    monkeypatch.setattr(billing_router, "_remind", remind)
    with pytest.raises(IspSmsRemindersUnavailableError):
        await billing_router.remind(
            SimpleNamespace(),
            uuid.uuid4(),
            billing_router.RemindRequest(channel="sms"),
            isp=SimpleNamespace(),
            svc=SimpleNamespace(),
        )
    assert called == []


def _inv(**kw):
    base = dict(
        status="partially_paid",
        total_paise=139240,
        paid_paise=118100,
        credit_noted_paise=0,
    )
    base.update(kw)
    return SimpleNamespace(**base)


async def test_void_of_a_partly_paid_invoice_cancels_it() -> None:
    inv = _inv()

    class Session:
        async def flush(self):
            return None

    svc = IspBillingService.__new__(IspBillingService)
    svc.session = Session()

    async def credit_note(isp, invoice_id, *, amount_paise, reason):
        assert amount_paise is None  # the whole remaining balance
        inv.credit_noted_paise = inv.total_paise - inv.paid_paise
        inv.status = status_for(inv)
        return SimpleNamespace(id=uuid.uuid4())

    async def _invoice(isp, invoice_id):
        return inv

    svc.credit_note = credit_note
    svc._invoice = _invoice
    await svc.void_invoice(SimpleNamespace(), uuid.uuid4(), reason="qa")
    assert inv.status == "cancelled"
    # and it stays cancelled if a payment is later voided (status_for is sticky)
    inv.paid_paise = 0
    assert status_for(inv) == "cancelled"


def test_partial_credit_plus_payment_without_void_is_still_paid() -> None:
    """Only an explicit void cancels; a normal credit note that settles the
    balance together with payments keeps the invoice "paid"."""
    assert status_for(_inv(credit_noted_paise=139240 - 118100)) == "paid"
