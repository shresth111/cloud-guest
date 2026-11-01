"""BILL-2 (ADDENDUM_06): GSTR-1 export rules, multi-cycle guard, PDF extras
block and zone branding validation. Real-DB coverage (recharge for N cycles,
the export over real rows, previous balance) is in
``test_isp_bill2_postgres.py``."""

from __future__ import annotations

import uuid
from datetime import date
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.domains.isp_partner import bill2_config
from app.domains.isp_partner.bill2_router import IspZoneBrandingRequest
from app.domains.isp_partner.billing_gst import (
    B2CL_THRESHOLD_PAISE,
    HEADERS,
    SECTIONS,
    build_gstr1,
    line_rate,
    state_label,
)
from app.domains.isp_partner.billing_pdf import _account_block


def _doc(**kw):
    taxable = kw.pop("taxable", 10_000)
    inter = kw.pop("inter", False)
    tax = taxable * 18 // 100
    base = {
        "id": uuid.uuid4(),
        "doc_type": "invoice",
        "number": "INV/26-27/0001",
        "issue_date": date(2026, 11, 5),
        "gst_applied": True,
        "bill_to_gstin": None,
        "bill_to_name": "Asha",
        "seller_state_code": "09",
        "place_of_supply_state_code": "27" if inter else "09",
        "taxable_paise": taxable,
        "cgst_paise": 0 if inter else tax // 2,
        "sgst_paise": 0 if inter else tax - tax // 2,
        "igst_paise": tax if inter else 0,
        "total_paise": taxable + tax,
        "credit_note_for_invoice_id": None,
    }
    base.update(kw)
    return SimpleNamespace(**base)


def test_line_rate_snaps_to_slabs() -> None:
    assert line_rate(10_000, 1_800) == 18
    assert line_rate(10_000, 1_799) == 18
    assert line_rate(10_000, 0) == 0
    assert line_rate(0, 100) == 0
    assert line_rate(10_000, 500) == 5


def test_state_label() -> None:
    assert state_label("09") == "09-Uttar Pradesh"
    assert state_label("7") == "07-Delhi"
    assert state_label(None) == ""


def test_b2b_row_for_registered_buyer() -> None:
    d = _doc(bill_to_gstin="09ABCDE1234F1Z5", bill_to_name="Acme")
    out = build_gstr1([d], {}, {})["sections"]
    assert len(out["b2b"]) == 1 and not out["b2cs"]
    row = out["b2b"][0]
    assert set(row) == set(HEADERS["b2b"])
    assert row["Rate"] == 18 and row["Taxable Value"] == 100.0
    assert row["Invoice date"] == "05-Nov-2026"
    assert row["Place Of Supply"] == "09-Uttar Pradesh"


def test_b2cl_only_above_threshold_and_inter_state() -> None:
    big = _doc(inter=True, taxable=B2CL_THRESHOLD_PAISE)  # value > threshold
    small_inter = _doc(inter=True, taxable=50_000)
    big_intra = _doc(inter=False, taxable=B2CL_THRESHOLD_PAISE)
    out = build_gstr1([big, small_inter, big_intra], {}, {})["sections"]
    assert [r["Invoice Number"] for r in out["b2cl"]] == [big.number]
    # the other two are B2CS, one bucket per place of supply
    assert {r["Place Of Supply"] for r in out["b2cs"]} == {
        "27-Maharashtra",
        "09-Uttar Pradesh",
    }


def test_b2cs_sums_by_state_and_nets_small_credit_notes() -> None:
    a, b = _doc(taxable=10_000), _doc(taxable=20_000, number="INV/2")
    note = _doc(
        doc_type="credit_note",
        number="CN/1",
        taxable=5_000,
        credit_note_for_invoice_id=a.id,
    )
    out = build_gstr1([a, b, note], {}, {a.id: a})["sections"]
    assert out["b2cs"] == [
        {
            "Type": "OE",
            "Place Of Supply": "09-Uttar Pradesh",
            "Applicable % of Tax Rate": "",
            "Rate": 18,
            "Taxable Value": 250.0,
            "Cess Amount": 0,
            "E-Commerce GSTIN": "",
        }
    ]
    assert not out["cdnr"] and not out["cdnur"]


def test_credit_notes_go_to_cdnr_or_cdnur() -> None:
    reg = _doc(bill_to_gstin="09ABCDE1234F1Z5")
    big = _doc(inter=True, taxable=B2CL_THRESHOLD_PAISE, number="INV/9")
    n1 = _doc(
        doc_type="credit_note",
        number="CN/1",
        bill_to_gstin=reg.bill_to_gstin,
        credit_note_for_invoice_id=reg.id,
    )
    n2 = _doc(
        doc_type="credit_note",
        number="CN/2",
        inter=True,
        taxable=10_000,
        credit_note_for_invoice_id=big.id,
    )
    # originals may be from an earlier month: only the notes are "docs"
    out = build_gstr1([n1, n2], {}, {reg.id: reg, big.id: big})["sections"]
    assert [r["Note Number"] for r in out["cdnr"]] == ["CN/1"]
    assert out["cdnr"][0]["Note Type"] == "C"
    assert [r["Note Number"] for r in out["cdnur"]] == ["CN/2"]
    assert out["cdnur"][0]["UR Type"] == "B2CL"


def test_bill_of_supply_is_nil_not_taxable() -> None:
    d = _doc(gst_applied=False, cgst_paise=0, sgst_paise=0, total_paise=10_000)
    res = build_gstr1([d], {}, {})
    assert all(not res["sections"][k] for k in SECTIONS)
    assert res["nil_value_paise"] == 10_000


def test_hsn_summary_uses_lines_and_signs_credit_notes() -> None:
    inv = _doc()
    line = SimpleNamespace(
        sac_code="998422",
        quantity=3,
        taxable_paise=inv.taxable_paise,
        cgst_paise=inv.cgst_paise,
        sgst_paise=inv.sgst_paise,
        igst_paise=0,
        total_paise=inv.total_paise,
    )
    note = _doc(
        doc_type="credit_note", taxable=10_000, credit_note_for_invoice_id=inv.id
    )
    out = build_gstr1([inv, note], {inv.id: [line]}, {inv.id: inv})["sections"]
    (h,) = out["hsn"]
    assert h["HSN"] == "998422" and h["Rate"] == 18
    assert h["Total Quantity"] == 3 - 1  # the note counts back one unit
    assert h["Taxable Value"] == 0.0


async def test_flag_defaults_off() -> None:
    bill2_config.get_bill2_settings.cache_clear()
    assert bill2_config.get_bill2_settings().enabled is False
    with pytest.raises(HTTPException) as exc:
        await bill2_config.RequireBill2Enabled()
    assert exc.value.status_code == 404


def test_cycles_field_bounds() -> None:
    from app.domains.isp_partner.plans_router import RechargeRequest
    from app.domains.isp_partner.subscriber360_router import RenewBody

    pid = uuid.uuid4()
    assert RechargeRequest(package_id=pid).cycles == 1
    assert RenewBody().cycles == 1
    RechargeRequest(package_id=pid, cycles=12)
    with pytest.raises(ValidationError):
        RechargeRequest(package_id=pid, cycles=13)
    with pytest.raises(ValidationError):
        RenewBody(cycles=0)


def test_account_block_only_when_present() -> None:
    from reportlab.lib.styles import getSampleStyleSheet

    styles = getSampleStyleSheet()
    assert _account_block({}, styles) == []
    out = _account_block({"customer_id": "ravi01", "static_ip": "No"}, styles)
    assert len(out) == 2
    assert "Customer ID" in out[0].text and "ravi01" in out[0].text


def test_branding_validation() -> None:
    ok = IspZoneBrandingRequest(bank_ifsc="hdfc0001234", upi_vpa="zone@okhdfc")
    assert ok.bank_ifsc == "HDFC0001234"
    with pytest.raises(ValidationError):
        IspZoneBrandingRequest(bank_ifsc="HDFC1234")
    with pytest.raises(ValidationError):
        IspZoneBrandingRequest(upi_vpa="not-a-vpa")
    with pytest.raises(ValidationError):
        IspZoneBrandingRequest(bank_account_number="12-34")
