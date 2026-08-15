"""Real, properly-formatted quotation PDF rendering -- ``reportlab`` used
directly, reusing the exact same library ``app.domains.billing.invoice_pdf``
and ``app.domains.analytics.export`` already establish for this project (no
second PDF library, per that module's own "reuse-vs-dedicated" write-up).

## Reuse-vs-dedicated decision

Same conclusion ``invoice_pdf.py`` already reaches, for the same reason: a
quotation has a fixed, rigid document shape (branded header, client block,
a line-item table, a totals block, a validity/footer note) -- not the
arbitrary, variable-shaped section tree ``analytics.export._render_pdf``
was built for. What's reused, unmodified: the same installed ``reportlab``
package, the same ``platypus`` primitives (``SimpleDocTemplate``/
``Paragraph``/``Table``/``TableStyle``/``Spacer``), the same ``A4``/``cm``
page-geometry constants, and the same ``getSampleStyleSheet()`` base styles
``invoice_pdf.py`` itself uses -- this module is a third, independent
composition of those same primitives, never a copy-paste of either existing
renderer.

## Embedded logo image

Every *other* PDF renderer in this codebase (``invoice_pdf.py``,
``voucher_pdf.py``, ``analytics.export``) is text-only -- none embeds a
raster/vector logo image, because the frontend's own real logo assets
(``cloudguest-foundation/public/brand/*.svg``) are SVG-only and
``reportlab`` cannot render SVG natively without ``svglib``, a dependency
this codebase has never needed until now. Rather than adding that
dependency (and paying its SVG-parsing cost on every single PDF render),
``assets/wyfy-guest-logo.png`` is a one-time, build-time raster export
(via ``rsvg-convert``) of the exact same current, live brand asset
(``cloudguest-foundation/public/brand/lockup-horizontal.svg`` -- the
purple/indigo shield-and-wifi mark next to the "Wyfy Guest" wordmark,
the same one rendered in the product's own UI) -- never regenerated at
request time, just a static file shipped in this domain's own package
and drawn once per PDF via ``reportlab.platypus.Image``.
"""

from __future__ import annotations

import io
from decimal import Decimal
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    Image,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from .constants import (
    QUOTATION_COMPANY_CIN,
    QUOTATION_COMPANY_LEGAL_NAME,
    QUOTATION_PRODUCT_NAME,
)
from .models import Quotation, QuotationLineItem

# Real pixel dimensions of assets/wyfy-guest-logo.png (1496x238, rendered
# from the live brand SVG at 8x its base 187x29.75 viewBox scale for print-
# quality sharpness) -- LOGO_WIDTH/LOGO_HEIGHT below preserve that exact
# aspect ratio at a print-reasonable on-page size, not an arbitrary guess.
_LOGO_PATH = Path(__file__).parent / "assets" / "wyfy-guest-logo.png"
_LOGO_WIDTH = 6.5 * cm
_LOGO_HEIGHT = _LOGO_WIDTH * (238 / 1496)


def _amount(value: Decimal) -> str:
    return f"{value:,.2f}"


def render_quotation_pdf(
    quotation: Quotation, items: list[QuotationLineItem]
) -> bytes:
    """Renders one real quotation PDF -- branded header, client block, a
    real line-item table, a subtotal/tax/total block, and a validity/
    footer note. Returns real PDF bytes (verify with your own ``%PDF``
    header check, same rigor ``invoice_pdf``'s own tests already
    establish for ``render_invoice_pdf``)."""
    buffer = io.BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        topMargin=1.5 * cm,
        bottomMargin=1.5 * cm,
    )
    styles = getSampleStyleSheet()

    table_style = TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2C3E50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ALIGN", (1, 1), (-1, -1), "RIGHT"),
        ]
    )
    totals_style = TableStyle(
        [
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ALIGN", (1, 0), (1, -1), "RIGHT"),
            ("LINEABOVE", (0, -1), (-1, -1), 0.75, colors.HexColor("#2C3E50")),
            ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
        ]
    )

    story = [
        Image(str(_LOGO_PATH), width=_LOGO_WIDTH, height=_LOGO_HEIGHT, hAlign="LEFT"),
        Spacer(1, 0.2 * cm),
        Paragraph(QUOTATION_COMPANY_LEGAL_NAME, styles["Normal"]),
        Paragraph(f"CIN: {QUOTATION_COMPANY_CIN}", styles["Normal"]),
        Spacer(1, 0.3 * cm),
        Paragraph("QUOTATION", styles["Heading1"]),
        Spacer(1, 0.1 * cm),
        Paragraph(f"Quotation Number: {quotation.quotation_number}", styles["Normal"]),
        Paragraph(
            f"Date: {quotation.created_at.date().isoformat()}", styles["Normal"]
        ),
        Paragraph(
            f"Valid Until: {quotation.valid_until.date().isoformat()}",
            styles["Normal"],
        ),
        Spacer(1, 0.4 * cm),
    ]

    # -- Client block ------------------------------------------------------
    client_lines = [
        "<b>Prepared For</b>",
        quotation.client_name,
        quotation.client_company_name,
        quotation.client_email,
    ]
    story.append(Paragraph("<br/>".join(client_lines), styles["Normal"]))
    story.append(Spacer(1, 0.5 * cm))

    # -- Line items ----------------------------------------------------------
    story.append(Paragraph("Line Items", styles["Heading2"]))
    item_rows = [["Description", "Qty", "Unit Price", "Amount"]] + [
        [
            item.description,
            _amount(item.quantity),
            _amount(item.unit_price),
            _amount(item.amount),
        ]
        for item in items
    ]
    item_col_widths = [8 * cm, 2.5 * cm, 3 * cm, 3 * cm]
    story.append(
        Table(item_rows, style=table_style, hAlign="LEFT", colWidths=item_col_widths)
    )
    story.append(Spacer(1, 0.4 * cm))

    # -- Totals --------------------------------------------------------------
    totals_rows: list[list[str]] = [["Subtotal", _amount(quotation.subtotal)]]
    if quotation.tax_percentage > 0:
        totals_rows.append(
            [f"Tax ({quotation.tax_percentage}%)", _amount(quotation.tax_amount)]
        )
    totals_rows.append(
        [f"Total ({quotation.currency})", _amount(quotation.total_amount)]
    )
    story.append(
        Table(
            totals_rows, style=totals_style, hAlign="RIGHT", colWidths=[6 * cm, 3 * cm]
        )
    )
    story.append(Spacer(1, 0.4 * cm))

    if quotation.notes:
        story.append(Paragraph("Notes", styles["Heading2"]))
        story.append(Paragraph(quotation.notes, styles["Normal"]))
        story.append(Spacer(1, 0.4 * cm))

    story.append(Spacer(1, 0.6 * cm))
    story.append(
        Paragraph(
            f"This quotation is valid until "
            f"{quotation.valid_until.date().isoformat()}. Prices are quoted "
            f"in {quotation.currency} and are subject to change thereafter. "
            f"Thank you for considering {QUOTATION_PRODUCT_NAME}.",
            styles["Normal"],
        )
    )

    document.build(story)
    return buffer.getvalue()


__all__ = ["render_quotation_pdf"]
