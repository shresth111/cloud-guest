"""ISP invoice / credit-note / receipt PDFs (reportlab). Our own layout, with
ISP branding only; Wyfy's ``billing/invoice_pdf.py`` is not used."""

from __future__ import annotations

import io
from typing import Any
from urllib.parse import quote
from xml.sax.saxutils import escape

from reportlab.graphics.barcode.qr import QrCodeWidget
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .gst import rupees_in_words


def rupees(paise: int) -> str:
    """Indian grouping: 123456789 paise -> "Rs 12,34,567.89"."""
    sign = "-" if paise < 0 else ""
    r, p = divmod(abs(int(paise)), 100)
    digits = str(r)
    if len(digits) > 3:
        head, tail = digits[:-3], digits[-3:]
        groups = []
        while len(head) > 2:
            groups.insert(0, head[-2:])
            head = head[:-2]
        if head:
            groups.insert(0, head)
        digits = ",".join(groups) + "," + tail
    return f"{sign}Rs {digits}.{p:02d}"


def upi_uri(vpa: str, payee: str, amount_paise: int, note: str) -> str:
    return (
        f"upi://pay?pa={quote(vpa)}&pn={quote(payee)}"
        f"&am={amount_paise // 100}.{amount_paise % 100:02d}&tn={quote(note)}&cu=INR"
    )


def _qr(data: str, size: float = 3.2 * cm) -> Drawing:
    widget = QrCodeWidget(data)
    x1, y1, x2, y2 = widget.getBounds()
    drawing = Drawing(
        size, size, transform=[size / (x2 - x1), 0, 0, size / (y2 - y1), 0, 0]
    )
    drawing.add(widget)
    return drawing


def _table(rows: list[list[Any]], widths: list[float] | None = None) -> Table:
    t = Table(rows, colWidths=widths, hAlign="LEFT")
    t.setStyle(
        TableStyle(
            [
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EEEEEE")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    return t


def _e(value: Any) -> str:
    """Escape a value for a reportlab Paragraph (its mini-HTML chokes on & < >)."""
    return escape(str(value)) if value is not None else ""


def bill_to_text(view: dict) -> str:
    """The "Bill to" line, already escaped for a reportlab Paragraph.

    Customer-billed invoices name the customer. Subscriber invoices (manual,
    recharge, coupon activation: ADDENDUM_03 Part B) carry ``customer: None``
    and a ``subscriber`` block instead: name (or username), username, circuit
    id, and the venue (the ISP customer) they are at."""
    customer = view.get("customer")
    if customer:
        return escape(str(customer.get("name") or "-"))
    sub = view.get("subscriber") or {}
    full = " ".join(p for p in (sub.get("first_name"), sub.get("last_name")) if p)
    username = sub.get("username")
    parts = [escape(full or str(username or "Subscriber"))]
    if username and full:
        parts.append(f"Username: {escape(str(username))}")
    if sub.get("circuit_id"):
        parts.append(f"Circuit ID: {escape(str(sub['circuit_id']))}")
    if view.get("customer_name"):
        parts.append(f"At: {escape(str(view['customer_name']))}")
    return " &nbsp; ".join(parts)


def render_invoice_pdf(
    view: dict, *, seller: dict, isp_name: str, against: str | None = None
) -> bytes:
    """``view`` is ``IspBillingService.invoice_detail``'s output."""
    styles = getSampleStyleSheet()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=1.5 * cm, rightMargin=1.5 * cm)
    is_note = view["doc_type"] == "credit_note"
    gst = view["cgst_paise"] or view["sgst_paise"] or view["igst_paise"]
    title = "Credit Note" if is_note else ("Tax Invoice" if gst else "Bill of Supply")
    story: list[Any] = [
        Paragraph(f"<b>{escape(isp_name)}</b>", styles["Title"]),
        Paragraph(
            f"{_e(seller.get('legal_name') or isp_name)}<br/>{_e(seller.get('address'))}<br/>"  # noqa: E501
            f"GSTIN: {_e(seller.get('gstin') or '-')} &nbsp; State code: {_e(seller.get('state_code') or '-')}",  # noqa: E501
            styles["Normal"],
        ),
        Spacer(1, 0.4 * cm),
        Paragraph(f"<b>{title}</b>", styles["Heading2"]),
        _table(
            [
                ["Number", "Date", "Due", "Place of supply"],
                [
                    view["number"],
                    view["invoice_date"],
                    view["due_date"],
                    view.get("place_of_supply_state_code") or "-",
                ],
            ]
        ),
    ]
    if against:
        story.append(Paragraph(f"Against invoice {against}", styles["Normal"]))
    story += [
        Spacer(1, 0.3 * cm),
        Paragraph(
            f"<b>Bill to:</b> {bill_to_text(view)}"
            + (
                f" &nbsp; GSTIN: {escape(str(view['buyer_gstin']))}"
                if view.get("buyer_gstin")
                else ""
            )
            + (
                f" &nbsp; PO: {escape(str(view['po_number']))}"
                if view.get("po_number")
                else ""
            ),
            styles["Normal"],
        ),
        Spacer(1, 0.3 * cm),
    ]
    header = [
        "Description",
        "SAC",
        "Period",
        "Taxable",
        "CGST",
        "SGST",
        "IGST",
        "Total",
    ]
    body = [header]
    for li in view.get("lines") or [
        {
            "description": view.get("description") or title,
            "sac_code": seller.get("sac_code", "998422"),
            "period_from": None,
            "period_to": None,
            "taxable_paise": view["taxable_paise"],
            "cgst_paise": view["cgst_paise"],
            "sgst_paise": view["sgst_paise"],
            "igst_paise": view["igst_paise"],
            "total_paise": view["total_paise"],
        }
    ]:
        period = (
            f"{li['period_from']} - {li['period_to']}" if li.get("period_from") else ""
        )
        body.append(
            [
                Paragraph(escape(str(li["description"] or "")), styles["Normal"]),
                li["sac_code"],
                period,
                rupees(li["taxable_paise"]),
                rupees(li["cgst_paise"]),
                rupees(li["sgst_paise"]),
                rupees(li["igst_paise"]),
                rupees(li["total_paise"]),
            ]
        )
    body.append(
        [
            "",
            "",
            "Total",
            rupees(view["taxable_paise"]),
            rupees(view["cgst_paise"]),
            rupees(view["sgst_paise"]),
            rupees(view["igst_paise"]),
            rupees(view["total_paise"]),
        ]
    )
    story.append(
        _table(
            body,
            [5 * cm, 1.4 * cm, 3 * cm, 2 * cm, 1.6 * cm, 1.6 * cm, 1.6 * cm, 2 * cm],
        )
    )
    story += [
        Spacer(1, 0.2 * cm),
        Paragraph(
            f"Amount in words: {rupees_in_words(view['total_paise'])}", styles["Normal"]
        ),
    ]
    if not is_note:
        story.append(
            Paragraph(
                f"Paid: {rupees(view['paid_paise'])} &nbsp; Credit notes: "
                f"{rupees(view['credit_noted_paise'])} &nbsp; <b>Balance: {rupees(view['balance_paise'])}</b>",  # noqa: E501
                styles["Normal"],
            )
        )
        modes = sorted({p["mode"] for p in view.get("payments", [])})
        if modes:
            story.append(
                Paragraph("Payment mode(s): " + ", ".join(modes), styles["Normal"])
            )
        if view["balance_paise"] > 0 and seller.get("upi_vpa"):
            story += [
                Spacer(1, 0.3 * cm),
                Paragraph("Scan to pay by UPI", styles["Normal"]),
                _qr(
                    upi_uri(
                        seller["upi_vpa"],
                        seller.get("payee_name") or isp_name,
                        view["balance_paise"],
                        view["number"],
                    )
                ),
            ]
    if seller.get("invoice_footer"):
        story.append(Paragraph(_e(seller["invoice_footer"]), styles["Normal"]))
    story += [
        Spacer(1, 0.5 * cm),
        Paragraph("Computer-generated document.", styles["Italic"]),
    ]
    doc.build(story)
    return buf.getvalue()


def render_receipt_pdf(
    payment: dict,
    *,
    isp_name: str,
    seller: dict,
    recorded_by: str | None,
    customer_name: str,
) -> bytes:
    styles = getSampleStyleSheet()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=1.5 * cm, rightMargin=1.5 * cm)
    story = [
        Paragraph(f"<b>{escape(isp_name)}</b>", styles["Title"]),
        Paragraph(
            f"{_e(seller.get('legal_name') or isp_name)}<br/>{_e(seller.get('address'))}<br/>"  # noqa: E501
            f"GSTIN: {_e(seller.get('gstin') or '-')}",
            styles["Normal"],
        ),
        Spacer(1, 0.4 * cm),
        Paragraph("<b>Payment Receipt</b>", styles["Heading2"]),
        _table(
            [
                ["Receipt", "Received", "Mode", "Reference", "Amount"],
                [
                    payment["receipt_number"],
                    payment["received_at"][:10],
                    payment["mode"],
                    payment.get("reference") or "-",
                    rupees(payment["amount_paise"]),
                ],
            ]
        ),
        Spacer(1, 0.3 * cm),
        Paragraph(
            f"Received from: {escape(str(customer_name or '-'))}", styles["Normal"]
        ),
        Paragraph(
            f"Amount in words: {rupees_in_words(payment['amount_paise'])}",
            styles["Normal"],
        ),
        Paragraph(f"Recorded by: {recorded_by or '-'}", styles["Normal"]),
    ]
    if payment["status"] == "voided":
        story.append(
            Paragraph(
                f"<b>VOIDED</b>: {_e(payment.get('voided_reason'))}", styles["Normal"]
            )
        )
    story += [
        Spacer(1, 0.5 * cm),
        Paragraph("Computer-generated receipt.", styles["Italic"]),
    ]
    doc.build(story)
    return buf.getvalue()
