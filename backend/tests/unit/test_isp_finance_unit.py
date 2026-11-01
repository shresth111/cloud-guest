"""JAZE-4 pure-function tests (run on CI, no database)."""

from __future__ import annotations

import json

import httpx
import pytest

from app.domains.isp_partner import automation as auto
from app.domains.isp_partner.billing_pdf import render_invoice_pdf
from app.domains.isp_partner.finance_service import IFSC_RE, pan_valid
from app.domains.isp_partner.thermal_pdf import (
    render_thermal_invoice,
    render_thermal_receipt,
)


def _block_text(seller: dict, *, is_note: bool = False) -> str:
    from reportlab.lib.styles import getSampleStyleSheet

    from app.domains.isp_partner.billing_pdf import _extras_block

    flow = _extras_block(seller, getSampleStyleSheet(), is_note=is_note)
    return " ".join(getattr(f, "text", "") for f in flow)


VIEW = {
    "doc_type": "invoice",
    "number": "JZA/26-27/7",
    "invoice_date": "2026-11-01",
    "due_date": "2026-11-08",
    "place_of_supply_state_code": "08",
    "customer": {"name": "Cafe One"},
    "subscriber": None,
    "taxable_paise": 100000,
    "cgst_paise": 9000,
    "sgst_paise": 9000,
    "igst_paise": 0,
    "total_paise": 118000,
    "paid_paise": 0,
    "credit_noted_paise": 0,
    "balance_paise": 118000,
    "lines": [
        {
            "description": "Bandwidth",
            "sac_code": "998422",
            "period_from": None,
            "period_to": None,
            "taxable_paise": 100000,
            "cgst_paise": 9000,
            "sgst_paise": 9000,
            "igst_paise": 0,
            "total_paise": 118000,
        }
    ],
    "payments": [],
}


def test_pan_and_ifsc_shapes() -> None:
    assert pan_valid("abcde1234f")
    assert not pan_valid("ABCD1234F")
    assert IFSC_RE.match("TEST0001234")
    assert not IFSC_RE.match("TEST1001234")  # fifth char must be 0


def test_invoice_pdf_extras_only_when_configured() -> None:
    assert _block_text({"legal_name": "Net A", "gstin": "x"}) == ""
    seller = {
        "legal_name": "Net A",
        "bank": {
            "name": "Test Bank",
            "account_number": "123456789012",
            "ifsc": "TEST0001234",
        },
        "operator": {"name": "LCO One", "phone": "9111111111"},
        "care_phone": "9000000001",
        "licence_number": "UL-TEST-1",
        "terms": "Pay within 7 days & keep the receipt",
    }
    rich = _block_text(seller)
    for needle in (
        "Pay by bank transfer",
        "TEST0001234",
        "123456789012",
        "LCO One",
        "UL-TEST-1",
        "&amp;",
    ):  # noqa: E501
        assert needle in rich, needle
    # A credit note never shows the bank block.
    assert "Pay by bank transfer" not in _block_text(seller, is_note=True)
    # And the whole PDF still renders with and without extras.
    assert render_invoice_pdf(VIEW, seller=seller, isp_name="Net A")[:4] == b"%PDF"
    assert render_invoice_pdf(VIEW, seller={}, isp_name="Net A")[:4] == b"%PDF"


@pytest.mark.parametrize("width", [80, 58])
def test_thermal_slips_render(width: int) -> None:
    from app.domains.isp_partner.thermal_pdf import (
        WIDTHS_MM,
        _lines_for_invoice,
        _lines_for_receipt,
    )

    cols = WIDTHS_MM[width][1]
    lines = _lines_for_invoice(VIEW, {"gstin": "08ABCDE1234F1Z5"}, "Net A", cols)
    text = "\n".join(lines)
    assert (
        "JZA/26-27/7" in text
        and "TOTAL" in text
        and "CGST" in text
        and "Cafe One" in text
    )
    assert max(len(x) for x in lines) <= cols
    receipt = {
        "receipt_number": "R/26-27/1",
        "received_at": "2026-11-01T10:00:00+00:00",
        "mode": "cash",
        "reference": None,
        "amount_paise": 50000,
        "status": "voided",
    }
    assert "VOIDED" in "\n".join(
        _lines_for_receipt(receipt, {}, "Net A", "Cafe One", cols)
    )
    assert (
        render_thermal_invoice(VIEW, seller={}, isp_name="Net A", width_mm=width)[:4]
        == b"%PDF"
    )  # noqa: E501
    assert (
        render_thermal_receipt(
            receipt, seller={}, isp_name="Net A", customer_name="C", width_mm=width
        )[:4]
        == b"%PDF"
    )  # noqa: E501


def test_masking_and_e164() -> None:
    assert auto.mask_phone("+91 98765 43210") == "••••••3210"
    assert auto.mask_email("accounts@example.com") == "a•••@example.com"
    assert auto.e164_in("098765 43210") == "+919876543210"
    assert auto.e164_in("919876543210") == "+919876543210"
    assert auto.e164_in("12345") is None
    assert auto.e164_in("5876543210") is None  # Indian mobiles start 6-9


async def test_telegram_send_never_leaks_token() -> None:
    seen: list[dict] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(json.loads(req.content))
        return httpx.Response(401, json={"ok": False, "description": "Unauthorized"})

    token = "123456:SECRETSECRETSECRETSECRETSECRETSEC"
    err = await auto.telegram_send(
        token, "-100", "hi", transport=httpx.MockTransport(handler)
    )
    assert err and "401" in err and "SECRET" not in err
    assert seen == [{"chat_id": "-100", "text": "hi", "disable_web_page_preview": True}]


def test_finance_flags_default_off() -> None:
    from app.domains.isp_partner.finance_config import IspFinanceSettings

    s = IspFinanceSettings(_env_file=None)
    assert not (
        s.finance_extras_enabled
        or s.zone_ledger_enabled
        or s.whatsapp_automation_enabled
        or s.telegram_alerts_enabled
    )
