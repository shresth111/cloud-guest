"""QA-005: every ISP invoice kind renders a PDF.

Views are built with the real ``IspBillingService.invoice_row`` (the shape
``invoice_detail`` returns and both ``GET /isp/invoices/{id}/pdf`` and the
bulk ``download_pdfs`` action pass to the renderer). Subscriber-billed
invoices (manual, recharge, coupon) carry ``customer: None``. Before the fix
the "Bill to" line read ``view['customer']['name']`` and raised TypeError,
which was a 500 for every subscriber invoice and for any bulk selection that
included one.
"""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime
from types import SimpleNamespace

import pytest

from app.domains.isp_partner.billing_pdf import (
    bill_to_text,
    render_invoice_pdf,
    render_receipt_pdf,
)
from app.domains.isp_partner.billing_service import IspBillingService

SELLER = {
    "legal_name": "QA Net & Co <Pvt> Ltd",
    "address": "Test Rd, Noida",
    "gstin": "09ABCDE1234F1Z5",
    "state_code": "09",
    "upi_vpa": "qa@upi",
    "invoice_footer": "Thanks & regards",
}


def _invoice(bill_to_kind: str, invoice_kind: str, **kw) -> SimpleNamespace:
    base = dict(
        id=uuid.uuid4(),
        display_id="INV-1",
        number="QAA/26-27/2",
        doc_type="invoice",
        created_at=datetime(2026, 10, 23, tzinfo=UTC),
        issue_date=date(2026, 10, 23),
        due_date=date(2026, 11, 7),
        bill_to_kind=bill_to_kind,
        subscriber_id=uuid.uuid4() if bill_to_kind == "subscriber" else None,
        bill_to_username="rahul.sharma.9288" if bill_to_kind == "subscriber" else None,
        circuit_id_snapshot="QA-000017" if bill_to_kind == "subscriber" else None,
        customer_organization_id=uuid.uuid4(),
        bill_to_name="Cafe A & B",
        invoice_kind=invoice_kind,
        po_number=None,
        bill_to_gstin=None,
        taxable_paise=15678,
        cgst_paise=1411,
        sgst_paise=1411,
        igst_paise=0,
        total_paise=18500,
        paid_paise=0,
        credit_noted_paise=0,
        status="issued",
        credit_note_for_invoice_id=None,
    )
    base.update(kw)
    return SimpleNamespace(**base)


def _view(inv, *, subscriber=None) -> dict:
    view = IspBillingService.invoice_row(inv, "Cafe A & B", subscriber=subscriber)
    view["lines"] = [
        {
            "description": f"{inv.invoice_kind} line: 10 Mbps <30 days> & more",
            "sac_code": "998422",
            "period_from": "2026-10-23",
            "period_to": "2026-11-22",
            "taxable_paise": inv.taxable_paise,
            "cgst_paise": inv.cgst_paise,
            "sgst_paise": inv.sgst_paise,
            "igst_paise": inv.igst_paise,
            "total_paise": inv.total_paise,
        }
    ]
    view["payments"] = []
    return view


CASES = [
    ("customer", "manual", None),
    ("customer", "cycle", None),
    ("subscriber", "manual", None),  # invoice_row's fallback subscriber block
    (
        "subscriber",
        "recharge",
        {
            "id": "s1",
            "username": "rahul.sharma.9288",
            "first_name": "Rahul",
            "last_name": "Sharma",
            "circuit_id": "QA-000017",
        },
    ),
    (
        "subscriber",
        "coupon",
        {
            "id": "s2",
            "username": "q****3@example.com",
            "first_name": None,
            "last_name": None,
            "circuit_id": None,
        },
    ),
]


@pytest.mark.parametrize(
    ("bill_to", "kind", "subscriber"),
    CASES,
    ids=[f"{b}-{k}" for b, k, _ in CASES],
)
def test_every_invoice_kind_renders_a_pdf(bill_to, kind, subscriber) -> None:
    view = _view(_invoice(bill_to, kind), subscriber=subscriber)
    pdf = render_invoice_pdf(view, seller=SELLER, isp_name="QA ISP & Sons")
    assert pdf[:4] == b"%PDF" and len(pdf) > 1000


def test_credit_note_against_a_subscriber_invoice_renders() -> None:
    inv = _invoice(
        "subscriber", "recharge", doc_type="credit_note", number="QCA/26-27/1"
    )
    pdf = render_invoice_pdf(
        _view(inv), seller=SELLER, isp_name="QA ISP", against="QAA/26-27/3"
    )
    assert pdf[:4] == b"%PDF"


def test_subscriber_bill_to_names_the_subscriber_and_the_venue() -> None:
    view = _view(_invoice("subscriber", "recharge"), subscriber=CASES[3][2])
    text = bill_to_text(view)
    assert "Rahul Sharma" in text
    assert "Username: rahul.sharma.9288" in text
    assert "Circuit ID: QA-000017" in text
    assert "At: Cafe A &amp; B" in text


def test_subscriber_without_a_name_falls_back_to_the_username() -> None:
    view = _view(_invoice("subscriber", "manual"))
    assert bill_to_text(view).startswith("rahul.sharma.9288")


def test_customer_bill_to_is_escaped() -> None:
    view = _view(_invoice("customer", "manual"))
    assert bill_to_text(view) == "Cafe A &amp; B"


def test_receipt_with_markup_characters_renders() -> None:
    pdf = render_receipt_pdf(
        {
            "receipt_number": "TRC/26-27/1",
            "received_at": "2026-10-23T10:00:00+00:00",
            "mode": "cash",
            "reference": "cash & carry",
            "amount_paise": 18500,
            "status": "voided",
            "voided_reason": "typed <wrong> amount & date",
        },
        isp_name="QA ISP & Sons",
        seller=SELLER,
        recorded_by="Owner",
        customer_name="Cafe A & B",
    )
    assert pdf[:4] == b"%PDF"
