"""Coupon print sheets (ADDENDUM_02 §8), ISP-branded. Layouts: ``a4-24``
(3x8 cards), ``a4-40`` (4x10) and ``thermal-58mm`` (one card per slip).
Our own renderer; the existing voucher PDF (Wyfy venue style) is not used."""

from __future__ import annotations

import io

from reportlab.graphics import renderPDF
from reportlab.graphics.barcode.qr import QrCodeWidget
from reportlab.graphics.shapes import Drawing
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas

LAYOUTS = {"a4-24": (3, 8), "a4-40": (4, 10)}


def _qr(c: canvas.Canvas, data: str, x: float, y: float, size: float) -> None:
    widget = QrCodeWidget(data)
    x1, y1, x2, y2 = widget.getBounds()
    d = Drawing(size, size, transform=[size / (x2 - x1), 0, 0, size / (y2 - y1), 0, 0])
    d.add(widget)
    renderPDF.draw(d, c, x, y)


def _card(c, x, y, w, h, coupon, meta, *, small: bool) -> None:  # noqa: ANN001
    c.roundRect(x + 1 * mm, y + 1 * mm, w - 2 * mm, h - 2 * mm, 2 * mm)
    fs = 6 if small else 8
    c.setFont("Helvetica-Bold", fs + 1)
    c.drawString(x + 3 * mm, y + h - 5 * mm, meta["isp_name"][:30])
    c.setFont("Helvetica", fs)
    c.drawString(x + 3 * mm, y + h - 9 * mm, meta["package_name"][:40])
    c.drawString(
        x + 3 * mm, y + h - 12.5 * mm, f"{meta['speed']} · {meta['validity_days']} days"
    )
    c.setFont("Courier-Bold", fs + 3)
    c.drawString(x + 3 * mm, y + 9 * mm, coupon["code"])
    c.setFont("Helvetica", fs - 1)
    c.drawString(x + 3 * mm, y + 5 * mm, f"Serial {coupon['serial']}")
    if meta.get("valid_until"):
        c.drawString(x + 3 * mm, y + 2.5 * mm, f"Use by {meta['valid_until']}")
    if meta.get("portal_url") and not small:
        _qr(c, meta["portal_url"], x + w - 15 * mm, y + 3 * mm, 12 * mm)


def render_coupon_sheet(coupons: list[dict], meta: dict, *, layout: str) -> bytes:
    buf = io.BytesIO()
    if layout == "thermal-58mm":
        w, h = 58 * mm, 40 * mm
        c = canvas.Canvas(buf, pagesize=(w, h))
        for coupon in coupons:
            _card(c, 0, 0, w, h, coupon, meta, small=False)
            c.showPage()
        if not coupons:
            c.showPage()
        c.save()
        return buf.getvalue()
    cols, rows = LAYOUTS.get(layout, LAYOUTS["a4-24"])
    pw, ph = A4
    margin = 8 * mm
    w = (pw - 2 * margin) / cols
    h = (ph - 2 * margin) / rows
    c = canvas.Canvas(buf, pagesize=A4)
    per_page = cols * rows
    for i, coupon in enumerate(coupons):
        if i and i % per_page == 0:
            c.showPage()
        slot = i % per_page
        col, row = slot % cols, slot // cols
        _card(
            c,
            margin + col * w,
            ph - margin - (row + 1) * h,
            w,
            h,
            coupon,
            meta,
            small=cols > 3,
        )
    if not coupons:
        c.drawString(margin, ph - margin - 10 * mm, "No coupons")
    c.showPage()
    c.save()
    return buf.getvalue()
