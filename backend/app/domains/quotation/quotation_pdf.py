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
page-geometry constants -- this module is a third, independent composition
of those same primitives, never a copy-paste of either existing renderer.

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

## Brand redesign: real Wyfy Guest colors/type instead of reportlab defaults

The original version of this module used ``getSampleStyleSheet()``
untouched -- plain Helvetica, a generic dark-slate (``#2C3E50``) table
header, no relationship at all to the actual product's visual identity.
This version pulls directly from the same brand source the embedded logo
itself comes from:

* **Colors** -- ``_INDIGO``/``_VIOLET`` (``#6366f1``/``#7c3aed``) are the
  exact two stops of the gradient in
  ``cloudguest-foundation/public/brand/lockup-horizontal.svg``; ``_NAVY``
  (``#17364E``) is that same SVG's wordmark/text color. Nothing here is a
  new, invented palette -- every color is read directly off the live
  brand asset already shipped in this file's own ``assets/`` folder.
* **Fonts** -- the product's own ``cloudguest-foundation/src/styles.css``
  sets body copy in Inter and its display/heading face in Space Grotesk
  (the Master Console -- where quotations are actually issued -- leans
  "Inter throughout"). Reportlab ships no fonts of its own beyond the 14
  built-in Type1 faces (Helvetica/Times/Courier), so real Inter/Space
  Grotesk ``.ttf`` files are vendored under ``assets/fonts/`` (both are
  open-license Google Fonts, freely redistributable) and registered with
  ``reportlab.pdfbase.ttfonts.TTFont`` at import time -- only the weights
  actually used (Inter Regular/SemiBold/Bold for body copy and labels,
  Space Grotesk Bold for the single "QUOTATION" display heading), not
  every weight in either family.
* **The one gradient moment** -- ``_GradientRule`` paints one thin
  (~2.6pt) horizontal indigo->violet rule, using ``Canvas.linearGradient``
  clipped to a thin rectangle, directly under the header and again above
  the footer note. Deliberately the *only* two places any gradient
  appears -- every other accent (the line-item table header, the total
  row, the "Prepared For" card's left bar) is a flat, solid pull from the
  same palette, per this feature's own brief: "restrained, not a garish
  gradient-everywhere design."
"""

from __future__ import annotations

import io
from decimal import Decimal
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    Flowable,
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

# ============================================================================
# Brand palette -- read directly off cloudguest-foundation's own
# public/brand/lockup-horizontal.svg (the same file assets/wyfy-guest-
# logo.png is rasterized from), never an invented palette.
# ============================================================================

_INDIGO = colors.HexColor("#6366f1")
_VIOLET = colors.HexColor("#7c3aed")
_NAVY = colors.HexColor("#17364E")
_INK = colors.HexColor("#334155")  # body-copy gray, slate-700
_MUTED = colors.HexColor("#64748B")  # secondary/meta text, slate-500
_BORDER = colors.HexColor("#E2E8F0")  # hairline rules, slate-200
_TINT = colors.HexColor("#F5F5FF")  # near-white indigo tint (card/zebra bg)
_TOTAL_TINT = colors.HexColor("#EEF2FF")  # indigo-50, total-row highlight
_WHITE = colors.white

# ============================================================================
# Fonts -- real Inter/Space Grotesk TTFs vendored under assets/fonts/,
# registered once at import time (see module docstring).
# ============================================================================

_FONT_DIR = Path(__file__).parent / "assets" / "fonts"
_FONT_INTER = "Inter"
_FONT_INTER_SEMIBOLD = "Inter-SemiBold"
_FONT_INTER_BOLD = "Inter-Bold"
_FONT_DISPLAY = "Space Grotesk"


def _register_fonts() -> None:
    """Registers the vendored Inter/Space Grotesk TTFs with reportlab's
    global font registry. Reportlab's registry is process-global and
    registering the same font name twice is harmless but wasteful (this
    module is imported once but ``render_quotation_pdf`` may run many
    times per worker process), so this is guarded on the registry
    reportlab itself already keeps."""
    if _FONT_INTER in pdfmetrics.getRegisteredFontNames():
        return
    pdfmetrics.registerFont(
        TTFont(_FONT_INTER, str(_FONT_DIR / "Inter-Regular.ttf"))
    )
    pdfmetrics.registerFont(
        TTFont(_FONT_INTER_SEMIBOLD, str(_FONT_DIR / "Inter-SemiBold.ttf"))
    )
    pdfmetrics.registerFont(
        TTFont(_FONT_INTER_BOLD, str(_FONT_DIR / "Inter-Bold.ttf"))
    )
    pdfmetrics.registerFont(
        TTFont(_FONT_DISPLAY, str(_FONT_DIR / "SpaceGrotesk-Bold.ttf"))
    )
    # So <b>...</b> inside a Paragraph set in "Inter" resolves to the real
    # Inter-Bold face instead of silently falling back to Helvetica-Bold.
    pdfmetrics.registerFontFamily(
        _FONT_INTER,
        normal=_FONT_INTER,
        bold=_FONT_INTER_BOLD,
        italic=_FONT_INTER,
        boldItalic=_FONT_INTER_BOLD,
    )


_register_fonts()

# ============================================================================
# Page geometry
# ============================================================================

_LEFT_MARGIN = 1.8 * cm
_RIGHT_MARGIN = 1.8 * cm
_TOP_MARGIN = 1.6 * cm
_BOTTOM_MARGIN = 1.6 * cm
_CONTENT_WIDTH = A4[0] - _LEFT_MARGIN - _RIGHT_MARGIN

# Real pixel dimensions of assets/wyfy-guest-logo.png (1496x238, rendered
# from the live brand SVG at 8x its base 187x29.75 viewBox scale for print-
# quality sharpness) -- LOGO_WIDTH/LOGO_HEIGHT below preserve that exact
# aspect ratio at a print-reasonable on-page size, not an arbitrary guess.
_LOGO_PATH = Path(__file__).parent / "assets" / "wyfy-guest-logo.png"
_LOGO_WIDTH = 5.6 * cm
_LOGO_HEIGHT = _LOGO_WIDTH * (238 / 1496)


class _GradientRule(Flowable):
    """A thin horizontal rule painted in the brand's own indigo->violet
    gradient (see module docstring's "the one gradient moment"). Built on
    ``Canvas.linearGradient`` clipped to the rule's own thin rectangle --
    the only way reportlab's ``platypus`` layer can place a real two-stop
    gradient inline in a flowable story."""

    def __init__(self, width: float, height: float = 0.075 * cm) -> None:
        super().__init__()
        self.width = width
        self.height = height

    def wrap(self, available_width: float, available_height: float) -> tuple:
        return self.width, self.height

    def draw(self) -> None:
        canvas = self.canv
        canvas.saveState()
        path = canvas.beginPath()
        path.rect(0, 0, self.width, self.height)
        canvas.clipPath(path, stroke=0, fill=0)
        canvas.linearGradient(0, 0, self.width, 0, [_INDIGO, _VIOLET])
        canvas.restoreState()


# ============================================================================
# Paragraph styles -- Inter throughout, Space Grotesk reserved for the one
# "QUOTATION" display heading (per the brief's Master-Console "Clean
# Enterprise: Inter throughout" note).
# ============================================================================


def _styles() -> dict[str, ParagraphStyle]:
    return {
        "company_name": ParagraphStyle(
            "company_name",
            fontName=_FONT_INTER_SEMIBOLD,
            fontSize=10,
            leading=13,
            textColor=_NAVY,
            alignment=TA_RIGHT,
        ),
        "cin": ParagraphStyle(
            "cin",
            fontName=_FONT_INTER,
            fontSize=8,
            leading=11,
            textColor=_MUTED,
            alignment=TA_RIGHT,
        ),
        "title": ParagraphStyle(
            "title",
            fontName=_FONT_DISPLAY,
            fontSize=25,
            leading=28,
            textColor=_NAVY,
        ),
        "meta_label": ParagraphStyle(
            "meta_label",
            fontName=_FONT_INTER,
            fontSize=8,
            leading=13,
            textColor=_MUTED,
            alignment=TA_LEFT,
        ),
        "meta_value": ParagraphStyle(
            "meta_value",
            fontName=_FONT_INTER_SEMIBOLD,
            fontSize=9,
            leading=13,
            textColor=_NAVY,
            alignment=TA_RIGHT,
        ),
        "section_label": ParagraphStyle(
            "section_label",
            fontName=_FONT_INTER_SEMIBOLD,
            fontSize=8.5,
            leading=11,
            textColor=_INDIGO,
            spaceAfter=4,
        ),
        "client_name": ParagraphStyle(
            "client_name",
            fontName=_FONT_INTER_SEMIBOLD,
            fontSize=11.5,
            leading=15,
            textColor=_NAVY,
        ),
        "client_detail": ParagraphStyle(
            "client_detail",
            fontName=_FONT_INTER,
            fontSize=9.5,
            leading=14,
            textColor=_INK,
        ),
        "table_header": ParagraphStyle(
            "table_header",
            fontName=_FONT_INTER_SEMIBOLD,
            fontSize=9,
            leading=12,
            textColor=_WHITE,
        ),
        "table_header_right": ParagraphStyle(
            "table_header_right",
            fontName=_FONT_INTER_SEMIBOLD,
            fontSize=9,
            leading=12,
            textColor=_WHITE,
            alignment=TA_RIGHT,
        ),
        "table_cell": ParagraphStyle(
            "table_cell",
            fontName=_FONT_INTER,
            fontSize=9,
            leading=13,
            textColor=_INK,
        ),
        "table_cell_right": ParagraphStyle(
            "table_cell_right",
            fontName=_FONT_INTER,
            fontSize=9,
            leading=13,
            textColor=_INK,
            alignment=TA_RIGHT,
        ),
        "totals_label": ParagraphStyle(
            "totals_label",
            fontName=_FONT_INTER,
            fontSize=9.5,
            leading=16,
            textColor=_INK,
        ),
        "totals_value": ParagraphStyle(
            "totals_value",
            fontName=_FONT_INTER,
            fontSize=9.5,
            leading=16,
            textColor=_INK,
            alignment=TA_RIGHT,
        ),
        "total_label": ParagraphStyle(
            "total_label",
            fontName=_FONT_INTER_BOLD,
            fontSize=11,
            leading=18,
            textColor=_NAVY,
        ),
        "total_value": ParagraphStyle(
            "total_value",
            fontName=_FONT_INTER_BOLD,
            fontSize=11,
            leading=18,
            textColor=_INDIGO,
            alignment=TA_RIGHT,
        ),
        "notes_body": ParagraphStyle(
            "notes_body",
            fontName=_FONT_INTER,
            fontSize=9.5,
            leading=14,
            textColor=_INK,
        ),
        "footer": ParagraphStyle(
            "footer",
            fontName=_FONT_INTER,
            fontSize=8.5,
            leading=13,
            textColor=_MUTED,
            alignment=TA_CENTER,
        ),
    }


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
        leftMargin=_LEFT_MARGIN,
        rightMargin=_RIGHT_MARGIN,
        topMargin=_TOP_MARGIN,
        bottomMargin=_BOTTOM_MARGIN,
    )
    styles = _styles()

    left_col = _CONTENT_WIDTH * 0.55
    right_col = _CONTENT_WIDTH - left_col

    story: list = []

    # -- Header: logo + company legal line -----------------------------------
    header_table = Table(
        [
            [
                Image(
                    str(_LOGO_PATH),
                    width=_LOGO_WIDTH,
                    height=_LOGO_HEIGHT,
                    hAlign="LEFT",
                ),
                [
                    Paragraph(QUOTATION_COMPANY_LEGAL_NAME, styles["company_name"]),
                    Paragraph(f"CIN: {QUOTATION_COMPANY_CIN}", styles["cin"]),
                ],
            ]
        ],
        colWidths=[left_col, right_col],
    )
    header_table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )
    story.append(header_table)
    story.append(Spacer(1, 0.35 * cm))
    story.append(_GradientRule(_CONTENT_WIDTH))
    story.append(Spacer(1, 0.55 * cm))

    # -- Title + meta (quotation number / date / valid until) ----------------
    meta_rows = [
        ["Quotation Number", quotation.quotation_number],
        ["Date", quotation.created_at.date().isoformat()],
        ["Valid Until", quotation.valid_until.date().isoformat()],
    ]
    meta_table = Table(
        [
            [
                Paragraph(label, styles["meta_label"]),
                Paragraph(value, styles["meta_value"]),
            ]
            for label, value in meta_rows
        ],
        colWidths=[right_col * 0.46, right_col * 0.54],
    )
    meta_table.setStyle(
        TableStyle(
            [
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 1.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5),
            ]
        )
    )
    title_row = Table(
        [[Paragraph("QUOTATION", styles["title"]), meta_table]],
        colWidths=[left_col, right_col],
    )
    title_row.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )
    story.append(title_row)
    story.append(Spacer(1, 0.7 * cm))

    # -- Client block: a card with a solid indigo left accent bar ------------
    client_cell = [
        Paragraph("PREPARED FOR", styles["section_label"]),
        Paragraph(quotation.client_name, styles["client_name"]),
        Paragraph(quotation.client_company_name, styles["client_detail"]),
        Paragraph(quotation.client_email, styles["client_detail"]),
    ]
    client_table = Table([[client_cell]], colWidths=[_CONTENT_WIDTH])
    client_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), _TINT),
                ("LINEBEFORE", (0, 0), (0, -1), 2.5, _INDIGO),
                ("LEFTPADDING", (0, 0), (-1, -1), 16),
                ("RIGHTPADDING", (0, 0), (-1, -1), 14),
                ("TOPPADDING", (0, 0), (-1, -1), 12),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
            ]
        )
    )
    story.append(client_table)
    story.append(Spacer(1, 0.7 * cm))

    # -- Line items ------------------------------------------------------------
    story.append(Paragraph("LINE ITEMS", styles["section_label"]))
    story.append(Spacer(1, 0.15 * cm))

    header = [
        Paragraph("Description", styles["table_header"]),
        Paragraph("Qty", styles["table_header_right"]),
        Paragraph("Unit Price", styles["table_header_right"]),
        Paragraph("Amount", styles["table_header_right"]),
    ]
    body_rows = [
        [
            Paragraph(item.description, styles["table_cell"]),
            Paragraph(_amount(item.quantity), styles["table_cell_right"]),
            Paragraph(_amount(item.unit_price), styles["table_cell_right"]),
            Paragraph(_amount(item.amount), styles["table_cell_right"]),
        ]
        for item in items
    ]
    item_col_widths = [
        _CONTENT_WIDTH * 0.49,
        _CONTENT_WIDTH * 0.12,
        _CONTENT_WIDTH * 0.185,
        _CONTENT_WIDTH * 0.205,
    ]
    item_table = Table(
        [header, *body_rows],
        colWidths=item_col_widths,
        hAlign="LEFT",
        repeatRows=1,
    )
    item_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), _INDIGO),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_WHITE, _TINT]),
                ("LINEBELOW", (0, 0), (-1, 0), 0.75, _INDIGO),
                ("LINEBELOW", (0, 1), (-1, -2), 0.5, _BORDER),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, 0), 8),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                ("TOPPADDING", (0, 1), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 1), (-1, -1), 7),
                ("LEFTPADDING", (0, 0), (0, -1), 10),
                ("RIGHTPADDING", (-1, 0), (-1, -1), 10),
            ]
        )
    )
    story.append(item_table)
    story.append(Spacer(1, 0.5 * cm))

    # -- Totals ------------------------------------------------------------------
    totals_rows: list[list] = [
        [
            Paragraph("Subtotal", styles["totals_label"]),
            Paragraph(_amount(quotation.subtotal), styles["totals_value"]),
        ]
    ]
    if quotation.tax_percentage > 0:
        totals_rows.append(
            [
                Paragraph(
                    f"Tax ({quotation.tax_percentage}%)", styles["totals_label"]
                ),
                Paragraph(_amount(quotation.tax_amount), styles["totals_value"]),
            ]
        )
    totals_rows.append(
        [
            Paragraph(f"Total ({quotation.currency})", styles["total_label"]),
            Paragraph(_amount(quotation.total_amount), styles["total_value"]),
        ]
    )
    total_row_index = len(totals_rows) - 1
    totals_table = Table(
        totals_rows,
        colWidths=[_CONTENT_WIDTH * 0.28, _CONTENT_WIDTH * 0.20],
        hAlign="RIGHT",
    )
    totals_table.setStyle(
        TableStyle(
            [
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("LINEABOVE", (0, total_row_index), (-1, total_row_index), 1, _INDIGO),
                (
                    "BACKGROUND",
                    (0, total_row_index),
                    (-1, total_row_index),
                    _TOTAL_TINT,
                ),
                ("TOPPADDING", (0, total_row_index), (-1, total_row_index), 8),
                ("BOTTOMPADDING", (0, total_row_index), (-1, total_row_index), 8),
            ]
        )
    )
    story.append(totals_table)
    story.append(Spacer(1, 0.6 * cm))

    if quotation.notes:
        story.append(Paragraph("NOTES", styles["section_label"]))
        story.append(Paragraph(quotation.notes, styles["notes_body"]))
        story.append(Spacer(1, 0.5 * cm))

    story.append(Spacer(1, 0.3 * cm))
    story.append(_GradientRule(_CONTENT_WIDTH))
    story.append(Spacer(1, 0.35 * cm))
    story.append(
        Paragraph(
            f"This quotation is valid until "
            f"{quotation.valid_until.date().isoformat()}. Prices are quoted "
            f"in {quotation.currency} and are subject to change thereafter. "
            f"Thank you for considering {QUOTATION_PRODUCT_NAME}.",
            styles["footer"],
        )
    )

    document.build(story)
    return buffer.getvalue()


__all__ = ["render_quotation_pdf"]
