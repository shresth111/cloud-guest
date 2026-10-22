"""GST maths and Indian FY numbering (ADDENDUM_03 §3, §6). Pure functions.

All money is integer paise. Rounding is half-up to the paisa.

* Inclusive price: taxable = round(price * 10000 / (10000 + rate_bp)); tax =
  price - taxable; split CGST = tax // 2, SGST = tax - CGST (so the total is
  the price exactly), or IGST = tax.
* Exclusive price: taxable = price; each component is rounded from taxable;
  total = taxable + components.
* Seller state == place of supply -> CGST + SGST at half the rate each;
  otherwise IGST at the full rate.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date

_GSTIN = re.compile(r"^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]$")
_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_NUMBER_ALLOWED = re.compile(r"^[A-Za-z0-9/-]{1,16}$")
INVOICE_PREFIX = re.compile(r"^[A-Z0-9]{1,4}$")
MAX_INVOICE_NUMBER = 16


def round_half_up(numerator: int, denominator: int) -> int:
    """``round(numerator / denominator)`` with halves rounded up, for
    non-negative integers, without floating point."""
    if denominator <= 0 or numerator < 0:
        raise ValueError("non-negative numerator, positive denominator")
    return (2 * numerator + denominator) // (2 * denominator)


@dataclass(frozen=True)
class LineTax:
    taxable: int
    cgst: int
    sgst: int
    igst: int
    total: int

    @property
    def tax(self) -> int:
        return self.cgst + self.sgst + self.igst


def compute_line(
    amount_paise: int,
    *,
    includes_gst: bool,
    gst_applied: bool,
    rate_bp: int,
    intra_state: bool,
) -> LineTax:
    if amount_paise < 0:
        raise ValueError("amount must be non-negative")
    if not gst_applied or rate_bp == 0:
        return LineTax(amount_paise, 0, 0, 0, amount_paise)
    if includes_gst:
        taxable = round_half_up(amount_paise * 10000, 10000 + rate_bp)
        tax = amount_paise - taxable
        if intra_state:
            cgst = tax // 2
            return LineTax(taxable, cgst, tax - cgst, 0, amount_paise)
        return LineTax(taxable, 0, 0, tax, amount_paise)
    taxable = amount_paise
    if intra_state:
        half = round_half_up(taxable * rate_bp, 20000)
        return LineTax(taxable, half, half, 0, taxable + 2 * half)
    igst = round_half_up(taxable * rate_bp, 10000)
    return LineTax(taxable, 0, 0, igst, taxable + igst)


def sum_lines(lines: list[LineTax]) -> LineTax:
    return LineTax(
        sum(x.taxable for x in lines),
        sum(x.cgst for x in lines),
        sum(x.sgst for x in lines),
        sum(x.igst for x in lines),
        sum(x.total for x in lines),
    )


def gstin_valid(gstin: str) -> bool:
    """15 characters, the official shape, and the mod-36 check character."""
    value = (gstin or "").strip().upper()
    if not _GSTIN.match(value):
        return False
    total = 0
    for i, ch in enumerate(value[:14]):
        product = _CHARS.index(ch) * (2 if i % 2 else 1)
        total += product // 36 + product % 36
    check = (36 - total % 36) % 36
    return _CHARS[check] == value[14]


def fiscal_year(day: date) -> str:
    """Indian FY (1 Apr - 31 Mar) as ``YY-YY``: 2025-10-21 -> ``25-26``."""
    start = day.year if day.month >= 4 else day.year - 1
    return f"{start % 100:02d}-{(start + 1) % 100:02d}"


def fy_start(day: date) -> date:
    return date(day.year if day.month >= 4 else day.year - 1, 4, 1)


def document_number(prefix: str, fy: str, seq: int) -> str:
    number = f"{prefix}/{fy}/{seq}"
    if len(number) > MAX_INVOICE_NUMBER or not _NUMBER_ALLOWED.match(number):
        from .exceptions import IspInvoiceNumberOverflowError

        raise IspInvoiceNumberOverflowError(number=number)
    return number


def receipt_number(prefix: str, fy: str, seq: int) -> str:
    """Receipts are not GST documents; only a 32-character column limit."""
    return f"{prefix}/{fy}/{seq}"[:32]


_ONES = (
    "", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine", "Ten",
    "Eleven", "Twelve", "Thirteen", "Fourteen", "Fifteen", "Sixteen", "Seventeen",
    "Eighteen", "Nineteen",
)
_TENS = ("", "", "Twenty", "Thirty", "Forty", "Fifty", "Sixty", "Seventy", "Eighty", "Ninety")


def _below_hundred(n: int) -> str:
    if n < 20:
        return _ONES[n]
    return (_TENS[n // 10] + (" " + _ONES[n % 10] if n % 10 else "")).strip()


def _below_thousand(n: int) -> str:
    hundreds, rest = divmod(n, 100)
    parts = []
    if hundreds:
        parts.append(f"{_ONES[hundreds]} Hundred")
    if rest:
        parts.append(_below_hundred(rest))
    return " ".join(parts)


def rupees_in_words(paise: int) -> str:
    """Indian numbering: 1,23,45,678.50 -> "One Crore Twenty Three Lakh
    Forty Five Thousand Six Hundred Seventy Eight Rupees and Fifty Paise"."""
    rupees, p = divmod(int(paise), 100)
    if rupees == 0:
        words = "Zero"
    else:
        parts = []
        crore, rupees = divmod(rupees, 10_000_000)
        lakh, rupees = divmod(rupees, 100_000)
        thousand, rupees = divmod(rupees, 1000)
        if crore:
            parts.append(f"{rupees_in_words(crore * 100).removesuffix(' Rupees Only')} Crore")
        if lakh:
            parts.append(f"{_below_hundred(lakh)} Lakh")
        if thousand:
            parts.append(f"{_below_hundred(thousand)} Thousand")
        if rupees:
            parts.append(_below_thousand(rupees))
        words = " ".join(parts)
    out = f"{words} Rupees"
    if p:
        out += f" and {_below_hundred(p)} Paise"
    return out + " Only"
