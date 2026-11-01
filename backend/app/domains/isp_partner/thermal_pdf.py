"""JAZE-4 J7: 80 mm (or 58 mm) thermal-printer slips for an invoice or a
payment receipt. One long page, monospace, no images, so any ESC/POS driver
that prints a PDF lays it out without scaling surprises."""

from __future__ import annotations

import io
import textwrap
from typing import Any

from reportlab.lib.units import mm
from reportlab.pdfgen import canvas

from .billing_pdf import rupees

WIDTHS_MM = {80: (80, 42), 58: (58, 30)}  # paper width, characters per line


def _lines_for_invoice(view: dict, seller: dict, isp_name: str, cols: int) -> list[str]:
    def kv(k: str, v: str) -> str:
        v = str(v)
        return f"{k}{' ' * max(1, cols - len(k) - len(v))}{v}"

    out: list[str] = []
    out += textwrap.wrap(isp_name.upper(), cols) or [""]
    if seller.get("gstin"):
        out.append(f"GSTIN {seller['gstin']}")
    if seller.get("care_phone"):
        out.append(f"Care {seller['care_phone']}")
    out.append("-" * cols)
    gst = view["cgst_paise"] or view["sgst_paise"] or view["igst_paise"]
    out.append("TAX INVOICE" if gst else "BILL OF SUPPLY")
    out.append(kv("No.", view["number"]))
    out.append(kv("Date", view["invoice_date"]))
    out.append(kv("Due", view["due_date"]))
    customer = view.get("customer") or {}
    sub = view.get("subscriber") or {}
    full = " ".join(p for p in (sub.get("first_name"), sub.get("last_name")) if p)
    name = customer.get("name") or full or sub.get("username") or "-"
    out += textwrap.wrap(f"To: {name}", cols)
    if sub.get("username"):
        out.append(kv("User", str(sub["username"])))
    if sub.get("circuit_id"):
        out.append(kv("Circuit", str(sub["circuit_id"])))
    out.append("-" * cols)
    for li in view.get("lines") or []:
        out += textwrap.wrap(str(li.get("description") or ""), cols)
        out.append(kv(f"  SAC {li.get('sac_code', '')}", rupees(li["total_paise"])))
    out.append("-" * cols)
    out.append(kv("Taxable", rupees(view["taxable_paise"])))
    if view["cgst_paise"]:
        out.append(kv("CGST", rupees(view["cgst_paise"])))
        out.append(kv("SGST", rupees(view["sgst_paise"])))
    if view["igst_paise"]:
        out.append(kv("IGST", rupees(view["igst_paise"])))
    out.append(kv("TOTAL", rupees(view["total_paise"])))
    out.append(kv("Paid", rupees(view.get("paid_paise", 0))))
    out.append(kv("BALANCE", rupees(view.get("balance_paise", 0))))
    if seller.get("upi_vpa") and view.get("balance_paise", 0) > 0:
        out.append("-" * cols)
        out += textwrap.wrap(f"Pay by UPI: {seller['upi_vpa']}", cols)
    out.append("-" * cols)
    out.append("Thank you".center(cols))
    return out


def _lines_for_receipt(
    payment: dict, seller: dict, isp_name: str, customer_name: str, cols: int
) -> list[str]:  # noqa: E501
    def kv(k: str, v: str) -> str:
        v = str(v)
        return f"{k}{' ' * max(1, cols - len(k) - len(v))}{v}"

    out = textwrap.wrap(isp_name.upper(), cols) or [""]
    if seller.get("gstin"):
        out.append(f"GSTIN {seller['gstin']}")
    out.append("-" * cols)
    out.append("PAYMENT RECEIPT")
    out.append(kv("No.", payment["receipt_number"]))
    out.append(kv("Date", payment["received_at"][:10]))
    out += textwrap.wrap(f"From: {customer_name or '-'}", cols)
    out.append(kv("Mode", payment["mode"]))
    if payment.get("reference"):
        out.append(kv("Ref", payment["reference"][: cols - 5]))
    out.append("-" * cols)
    out.append(kv("AMOUNT", rupees(payment["amount_paise"])))
    if payment.get("status") == "voided":
        out.append("*** VOIDED ***".center(cols))
    out.append("-" * cols)
    out.append("Thank you".center(cols))
    return out


def _render(lines: list[str], width_mm: int) -> bytes:
    paper, _ = WIDTHS_MM[width_mm]
    line_h = 3.6 * mm
    margin = 3 * mm
    height = margin * 2 + line_h * len(lines)
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(paper * mm, height))
    c.setFont("Courier", 8 if width_mm == 80 else 7)
    y = height - margin - line_h * 0.8
    for line in lines:
        c.drawString(margin, y, line)
        y -= line_h
    c.showPage()
    c.save()
    return buf.getvalue()


def render_thermal_invoice(
    view: dict, *, seller: dict, isp_name: str, width_mm: int = 80
) -> bytes:  # noqa: E501
    return _render(
        _lines_for_invoice(view, seller, isp_name, WIDTHS_MM[width_mm][1]), width_mm
    )  # noqa: E501


def render_thermal_receipt(
    payment: dict,
    *,
    seller: dict,
    isp_name: str,
    customer_name: str,
    width_mm: int = 80,
) -> bytes:
    cols = WIDTHS_MM[width_mm][1]
    return _render(
        _lines_for_receipt(payment, seller, isp_name, customer_name, cols), width_mm
    )


__all__: list[Any] = ["render_thermal_invoice", "render_thermal_receipt"]
