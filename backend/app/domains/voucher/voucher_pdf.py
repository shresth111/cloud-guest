"""Printable voucher PDF export (Phase 1 BhaiFi-parity #20) -- real
``reportlab``/``platypus`` rendering, mirroring
``app.domains.billing.invoice_pdf``'s exact composition pattern.

## Why a dedicated renderer, not a reuse of ``invoice_pdf``/``analytics
## .export``

See ``app.domains.billing.invoice_pdf``'s own module docstring for the full
"reuse-vs-dedicated" write-up this mirrors: a voucher card has a fixed,
small, print-and-cut layout (organization name, the voucher code itself in
large monospace type, its post-redemption validity window, its data cap)
with nothing in common with an invoice's line-item/tax-breakdown shape or
``analytics.export``'s generic, variable-shaped report-section walker.
What *is* reused, directly, without modification: the same installed
``reportlab`` package (already a pinned dependency -- see
``requirements.txt``), the same ``platypus`` primitives
(``SimpleDocTemplate``/``Paragraph``/``Table``/``TableStyle``/``Spacer``),
the same ``A4``/``cm`` page-geometry constants, and the same
``getSampleStyleSheet()`` base styles both existing PDF renderers use.

## Layout

One page (or more, as needed) per batch, a fixed two-column grid of voucher
cards -- each card boxed, printable, and meant to be cut out and handed to
a guest individually at a front desk. ``organization_name`` is resolved by
the caller (``router.py``, via ``VoucherService.organization_lookup``) and
passed in, never re-derived here -- this module stays a dependency-free
leaf exactly like ``invoice_pdf.py``'s own ``SellerInfo`` convention.
"""

from __future__ import annotations

import io

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .models import Voucher, VoucherBatch

# Two voucher cards per row -- a fixed, print-and-cut-friendly grid, not a
# dynamically-computed column count (a voucher card's own size is fixed;
# it never needs to shrink to fit more per page).
_VOUCHERS_PER_ROW = 2
_CARD_WIDTH = 8.5 * cm


def _format_validity(minutes: int) -> str:
    """A human-readable rendering of ``VoucherBatch.validity_minutes`` --
    days when it divides evenly, else hours, else raw minutes. Purely
    cosmetic (the real, authoritative value stays the stored integer;
    this never round-trips back into anything the service layer reads)."""
    if minutes >= 1440 and minutes % 1440 == 0:
        days = minutes // 1440
        return f"{days} day{'s' if days != 1 else ''}"
    if minutes >= 60 and minutes % 60 == 0:
        hours = minutes // 60
        return f"{hours} hour{'s' if hours != 1 else ''}"
    return f"{minutes} minute{'s' if minutes != 1 else ''}"


def render_voucher_batch_pdf(
    batch: VoucherBatch, vouchers: list[Voucher], *, organization_name: str
) -> bytes:
    """Renders one real, printable PDF of every voucher code in ``batch``
    (a grid of boxed, cut-out-ready cards) -- validity and data-cap text is
    read from ``batch`` itself (the "copied, not referenced" values every
    voucher under it actually carries -- see ``models.py``'s own module
    docstring), not re-derived per voucher. Returns real PDF bytes."""
    buffer = io.BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        topMargin=1.5 * cm,
        bottomMargin=1.5 * cm,
        leftMargin=1.5 * cm,
        rightMargin=1.5 * cm,
    )
    styles = getSampleStyleSheet()
    code_style = ParagraphStyle(
        "VoucherCode",
        parent=styles["Normal"],
        fontName="Courier-Bold",
        fontSize=16,
        alignment=1,
        spaceAfter=4,
    )
    label_style = ParagraphStyle(
        "VoucherLabel",
        parent=styles["Normal"],
        fontSize=8,
        alignment=1,
        textColor=colors.grey,
    )
    org_style = ParagraphStyle(
        "VoucherOrg",
        parent=styles["Normal"],
        fontSize=9,
        alignment=1,
        fontName="Helvetica-Bold",
    )
    card_style = TableStyle(
        [
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#2C3E50")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ]
    )
    grid_style = TableStyle(
        [
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ]
    )

    validity_text = (
        f"Valid for {_format_validity(batch.validity_minutes)} once redeemed"
    )
    data_text = (
        f"{batch.data_limit_mb} MB data cap"
        if batch.data_limit_mb
        else "Unlimited data"
    )

    story = [
        Paragraph(f"Voucher Batch: {batch.name}", styles["Title"]),
        Paragraph(f"{len(vouchers)} voucher(s)", styles["Normal"]),
        Spacer(1, 0.4 * cm),
    ]

    def _card(voucher: Voucher) -> Table:
        cell = Table(
            [
                [Paragraph(organization_name, org_style)],
                [Paragraph(voucher.code, code_style)],
                [Paragraph(validity_text, label_style)],
                [Paragraph(data_text, label_style)],
            ],
            colWidths=[_CARD_WIDTH - 1 * cm],
        )
        cell.setStyle(card_style)
        return cell

    rows: list[list[object]] = []
    current_row: list[object] = []
    for voucher in vouchers:
        current_row.append(_card(voucher))
        if len(current_row) == _VOUCHERS_PER_ROW:
            rows.append(current_row)
            current_row = []
    if current_row:
        current_row.extend([""] * (_VOUCHERS_PER_ROW - len(current_row)))
        rows.append(current_row)

    if rows:
        grid = Table(rows, colWidths=[_CARD_WIDTH] * _VOUCHERS_PER_ROW)
        grid.setStyle(grid_style)
        story.append(grid)

    document.build(story)
    return buffer.getvalue()


__all__ = ["render_voucher_batch_pdf"]
