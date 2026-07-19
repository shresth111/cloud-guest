"""The Export Engine (BE-012 Part 5): renders one already-assembled
``report_types.ReportPayload`` into each of :class:`~.constants.
ExportFormat`'s four real formats. No metric/section is computed here --
this module's only job is turning a plain, JSON-shaped tree into bytes of a
specific file format.

## JSON

Trivial and real: :meth:`~.report_types.ReportPayload.to_dict` is already
the payload's canonical shape (also what ``report_schemas
.ReportPayloadResponse`` documents and what ``GET``-style JSON callers of
``POST /reports`` receive via the standard ``ApiResponse`` envelope) --
``json.dumps`` of that dict, nothing more.

## CSV flattening convention

A CSV file is fundamentally one flat grid; a report payload is a tree of
named sections, each an arbitrarily nested JSON object. Rather than
silently dropping nested data (dishonest) or inventing a bespoke nested-CSV
dialect no spreadsheet tool actually understands, this domain adopts one
explicit, documented convention (implemented once, in
``report_types.flatten_scalar_fields``/``extract_tabular_blocks``, shared
with the Excel renderer below):

1. Every **scalar** leaf across every section (including nested dict
   fields, dotted-path-flattened, e.g. ``organization_summary.revenue
   .available``) is written into one ``Summary`` block: three columns,
   ``section``, ``field``, ``value``. A list of plain scalars (e.g.
   ``recipient_emails``) counts as one scalar leaf, joined with ``"; "``.
2. Every **list-of-objects** field anywhere in the payload (the payload's
   own genuinely tabular data -- e.g. an organization dashboard's
   ``organization_summary`` rollup rows, a guest analytics response's
   ``top_devices``) becomes its own block: a blank line, a
   ``"## <section>.<dotted.path>"`` marker row, a column-header row (the
   union of every row's own keys), then one CSV row per list item.

All blocks are written into the **same** CSV file/bytes object, one after
another -- a single-sheet-equivalent file any spreadsheet tool can open,
with the ``## `` marker rows making each tabular block's boundary
unambiguous on re-import or manual inspection. This is the "only export the
sections that are genuinely tabular, plus one flattened key/value summary
for everything else" strategy the module brief itself invites.

## Excel

A real ``.xlsx`` workbook (``openpyxl``) -- **at least one sheet per major
report section**: one ``Summary`` sheet (the exact same scalar
``field``/``value`` rows the CSV's ``Summary`` block has), plus one
additional sheet per :class:`~.report_types.TabularBlock` found anywhere in
the payload (named after that block's dotted path, sanitized/truncated to
Excel's 31-character sheet-name limit, de-duplicated on collision).

## PDF

A real, valid PDF (``reportlab``, chosen over lighter alternatives -- see
``docs/analytics/FLOW.md``'s Part 5 write-up for the full comparison
against ``fpdf2``/``weasyprint``: ``reportlab`` is the most mature, most
widely deployed pure-Python PDF generator with no system-level dependency
like a headless-browser/Cairo install, and its ``platypus`` layout engine
handles page-breaking real tables natively, which this domain's own
Router/Guest/Network-analytics-sized tabular sections need). Real
content: a title, the report's own scope/window line, then one heading
plus either a real ``Table`` (for a section's own tabular blocks) or a
``Metric: Value`` bullet list (for its scalar fields) per section --
never a placeholder "PDF support coming soon" page.
"""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass

from openpyxl import Workbook
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from .constants import ExportFormat
from .exceptions import UnsupportedExportFormatError
from .report_types import ReportPayload, extract_tabular_blocks, flatten_scalar_fields

_CONTENT_TYPES: dict[ExportFormat, str] = {
    ExportFormat.JSON: "application/json",
    ExportFormat.CSV: "text/csv",
    ExportFormat.EXCEL: (
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    ),
    ExportFormat.PDF: "application/pdf",
}

_FILE_EXTENSIONS: dict[ExportFormat, str] = {
    ExportFormat.JSON: "json",
    ExportFormat.CSV: "csv",
    ExportFormat.EXCEL: "xlsx",
    ExportFormat.PDF: "pdf",
}

_MAX_SHEET_NAME_LENGTH = 31
_INVALID_SHEET_NAME_CHARS = ("[", "]", ":", "*", "?", "/", "\\")


@dataclass(frozen=True, slots=True)
class RenderedExport:
    """The real, format-ready bytes of one rendered report, plus what an
    HTTP response needs to serve them correctly."""

    content: bytes
    content_type: str
    filename: str


def _filename(payload: ReportPayload, export_format: ExportFormat) -> str:
    # A plain, filesystem-friendly timestamp -- strips the ISO string's
    # ":"/"-" separators plus any sub-second/timezone-offset punctuation
    # ("." microseconds, "+" UTC offset) `generated_at` may carry, down to
    # a single digit run.
    timestamp = "".join(ch for ch in payload.generated_at if ch.isdigit())
    extension = _FILE_EXTENSIONS[export_format]
    return f"report_{payload.report_type}_{timestamp}.{extension}"


def render_report(
    payload: ReportPayload, export_format: ExportFormat
) -> RenderedExport:
    """Renders ``payload`` into ``export_format`` -- the single entry point
    both ``report_router.py`` (on-demand generation) and ``report_tasks.py``
    (scheduled generation) call."""
    if export_format == ExportFormat.JSON:
        content = _render_json(payload)
    elif export_format == ExportFormat.CSV:
        content = _render_csv(payload)
    elif export_format == ExportFormat.EXCEL:
        content = _render_excel(payload)
    elif export_format == ExportFormat.PDF:
        content = _render_pdf(payload)
    else:  # pragma: no cover -- defensive, see UnsupportedExportFormatError's docstring
        raise UnsupportedExportFormatError(str(export_format))

    return RenderedExport(
        content=content,
        content_type=_CONTENT_TYPES[export_format],
        filename=_filename(payload, export_format),
    )


# ============================================================================
# JSON
# ============================================================================


def _render_json(payload: ReportPayload) -> bytes:
    return json.dumps(payload.to_dict(), default=str).encode("utf-8")


# ============================================================================
# CSV -- see module docstring for the full flattening convention
# ============================================================================


def _render_csv(payload: ReportPayload) -> bytes:
    buffer = io.StringIO()
    writer = csv.writer(buffer)

    writer.writerow([f"Report: {payload.title}"])
    writer.writerow(["Generated at", payload.generated_at])
    writer.writerow(["Report type", payload.report_type])
    writer.writerow([])

    writer.writerow(["## Summary"])
    writer.writerow(["section", "field", "value"])
    for section in payload.sections:
        for field_path, value in flatten_scalar_fields(section.data):
            writer.writerow([section.key, field_path, value])

    for section in payload.sections:
        for block in extract_tabular_blocks(section.data):
            writer.writerow([])
            writer.writerow([f"## {section.key}.{block.name}"])
            writer.writerow(block.columns)
            for row in block.rows:
                writer.writerow(row)

    return buffer.getvalue().encode("utf-8")


# ============================================================================
# Excel -- one Summary sheet plus one sheet per tabular block
# ============================================================================


def _sanitize_sheet_name(name: str, *, taken: set[str]) -> str:
    cleaned = name
    for char in _INVALID_SHEET_NAME_CHARS:
        cleaned = cleaned.replace(char, "_")
    cleaned = cleaned[:_MAX_SHEET_NAME_LENGTH] or "Sheet"

    candidate = cleaned
    suffix = 2
    while candidate in taken:
        trimmed = cleaned[: _MAX_SHEET_NAME_LENGTH - len(str(suffix)) - 1]
        candidate = f"{trimmed}_{suffix}"
        suffix += 1
    taken.add(candidate)
    return candidate


def _render_excel(payload: ReportPayload) -> bytes:
    workbook = Workbook()
    taken_sheet_names: set[str] = set()

    summary_sheet = workbook.active
    summary_sheet.title = _sanitize_sheet_name("Summary", taken=taken_sheet_names)
    summary_sheet.append(["Section", "Field", "Value"])
    for section in payload.sections:
        for field_path, value in flatten_scalar_fields(section.data):
            summary_sheet.append([section.key, field_path, str(value)])

    for section in payload.sections:
        for block in extract_tabular_blocks(section.data):
            sheet_name = _sanitize_sheet_name(
                f"{section.key}_{block.name}", taken=taken_sheet_names
            )
            sheet = workbook.create_sheet(title=sheet_name)
            sheet.append(block.columns)
            for row in block.rows:
                sheet.append([str(cell) for cell in row])

    buffer = io.BytesIO()
    workbook.save(buffer)
    return buffer.getvalue()


# ============================================================================
# PDF -- real content via reportlab's platypus layout engine
# ============================================================================


def _render_pdf(payload: ReportPayload) -> bytes:
    buffer = io.BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        topMargin=1.5 * cm,
        bottomMargin=1.5 * cm,
    )
    styles = getSampleStyleSheet()
    story = [
        Paragraph(payload.title, styles["Title"]),
        Paragraph(f"Generated at: {payload.generated_at}", styles["Normal"]),
        Paragraph(f"Report type: {payload.report_type}", styles["Normal"]),
    ]
    if payload.organization_id is not None:
        story.append(
            Paragraph(f"Organization: {payload.organization_id}", styles["Normal"])
        )
    if payload.location_id is not None:
        story.append(Paragraph(f"Location: {payload.location_id}", styles["Normal"]))
    if payload.period_start and payload.period_end:
        story.append(
            Paragraph(
                f"Period: {payload.period_start} to {payload.period_end}",
                styles["Normal"],
            )
        )
    story.append(Spacer(1, 0.5 * cm))

    table_style = TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2C3E50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]
    )

    for section in payload.sections:
        story.append(Paragraph(section.title, styles["Heading2"]))

        scalar_fields = flatten_scalar_fields(section.data)
        if scalar_fields:
            metrics_rows = [["Metric", "Value"]] + [
                [field_path, str(value)] for field_path, value in scalar_fields
            ]
            story.append(Table(metrics_rows, style=table_style, hAlign="LEFT"))
            story.append(Spacer(1, 0.3 * cm))

        for block in extract_tabular_blocks(section.data):
            story.append(Paragraph(block.name, styles["Heading3"]))
            table_rows = [block.columns] + [
                [str(cell) for cell in row] for row in block.rows
            ]
            story.append(Table(table_rows, style=table_style, hAlign="LEFT"))
            story.append(Spacer(1, 0.3 * cm))

        if not scalar_fields and not extract_tabular_blocks(section.data):
            story.append(Paragraph("No data available.", styles["Normal"]))

    document.build(story)
    return buffer.getvalue()


__all__ = ["RenderedExport", "render_report"]
