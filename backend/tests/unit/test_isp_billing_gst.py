"""ADDENDUM_03 §3/§6 pure parts: GST engine fixtures, FY, number guards,
amount in words, GSTIN; and ADDENDUM_01 §A.9 test 9 (no suspension route
takes a router or NAS id)."""

from __future__ import annotations

from datetime import date

import pytest

from app.domains.isp_partner.billing_pdf import rupees, upi_uri
from app.domains.isp_partner.gst import (
    INVOICE_PREFIX,
    compute_line,
    document_number,
    fiscal_year,
    fy_start,
    gstin_valid,
    round_half_up,
    rupees_in_words,
)


class TestGst:
    def test_inclusive_185_intra_state(self) -> None:
        t = compute_line(
            18500, includes_gst=True, gst_applied=True, rate_bp=1800, intra_state=True
        )
        assert (t.taxable, t.cgst, t.sgst, t.igst, t.total) == (
            15678,
            1411,
            1411,
            0,
            18500,
        )

    def test_inclusive_185_inter_state(self) -> None:
        t = compute_line(
            18500, includes_gst=True, gst_applied=True, rate_bp=1800, intra_state=False
        )
        assert (t.taxable, t.cgst, t.sgst, t.igst, t.total) == (
            15678,
            0,
            0,
            2822,
            18500,
        )

    def test_exclusive_185_intra_state(self) -> None:
        t = compute_line(
            18500, includes_gst=False, gst_applied=True, rate_bp=1800, intra_state=True
        )
        assert (t.taxable, t.cgst, t.sgst, t.igst, t.total) == (
            18500,
            1665,
            1665,
            0,
            21830,
        )

    def test_exclusive_185_inter_state(self) -> None:
        t = compute_line(
            18500, includes_gst=False, gst_applied=True, rate_bp=1800, intra_state=False
        )
        assert (t.taxable, t.igst, t.total) == (18500, 3330, 21830)

    def test_odd_paise_split_keeps_inclusive_total_exact(self) -> None:
        for price in (101, 999, 18501, 49999, 1):
            t = compute_line(
                price,
                includes_gst=True,
                gst_applied=True,
                rate_bp=1800,
                intra_state=True,
            )
            assert t.total == price == t.taxable + t.cgst + t.sgst
            assert t.sgst - t.cgst in (0, 1)

    def test_no_gst_is_a_bill_of_supply(self) -> None:
        t = compute_line(
            18500, includes_gst=True, gst_applied=False, rate_bp=1800, intra_state=True
        )
        assert (t.taxable, t.cgst, t.sgst, t.igst, t.total) == (18500, 0, 0, 0, 18500)

    def test_round_half_up(self) -> None:
        assert round_half_up(5, 10) == 1 and round_half_up(4, 10) == 0
        assert round_half_up(15, 2) == 8


class TestNumbering:
    @pytest.mark.parametrize(
        ("day", "fy"),
        [
            (date(2026, 3, 31), "25-26"),
            (date(2026, 4, 1), "26-27"),
            (date(2025, 10, 21), "25-26"),
            (date(2099, 12, 1), "99-00"),
        ],
    )
    def test_fiscal_year(self, day, fy) -> None:
        assert fiscal_year(day) == fy

    def test_fy_rollover_at_31_march(self) -> None:
        assert fy_start(date(2026, 3, 31)) == date(2025, 4, 1)
        assert fy_start(date(2026, 4, 1)) == date(2026, 4, 1)

    def test_number_format_and_16_char_guard(self) -> None:
        assert document_number("NETX", "25-26", 1042) == "NETX/25-26/1042"
        assert len(document_number("NETX", "25-26", 99999)) == 16
        from app.domains.isp_partner.exceptions import IspInvoiceNumberOverflowError

        with pytest.raises(IspInvoiceNumberOverflowError):
            document_number("NETX", "25-26", 100000)

    @pytest.mark.parametrize("prefix", ["INV", "CN", "N1", "ABCD"])
    def test_valid_prefixes(self, prefix) -> None:
        assert INVOICE_PREFIX.match(prefix)

    @pytest.mark.parametrize("prefix", ["", "ABCDE", "in", "A-B", "A/B"])
    def test_invalid_prefixes(self, prefix) -> None:
        assert not INVOICE_PREFIX.match(prefix)


class TestWordsAndMoney:
    def test_indian_words(self) -> None:
        assert rupees_in_words(18500) == "One Hundred Eighty Five Rupees Only"
        assert (
            rupees_in_words(21830)
            == "Two Hundred Eighteen Rupees and Thirty Paise Only"
        )
        assert (
            rupees_in_words(1_234_567_850)
            == "One Crore Twenty Three Lakh Forty Five Thousand Six Hundred Seventy "
            "Eight Rupees and Fifty Paise Only"
        )
        assert rupees_in_words(0) == "Zero Rupees Only"

    def test_indian_grouping_and_upi(self) -> None:
        assert rupees(1_234_567_89) == "Rs 12,34,567.89"
        assert rupees(18500) == "Rs 185.00"
        uri = upi_uri("isp@upi", "Test ISP", 18501, "INV/25-26/1")
        assert uri.startswith(
            "upi://pay?pa=isp%40upi&pn=Test%20ISP&am=185.01&tn=INV/25-26/1"
        )
        assert uri.endswith("&cu=INR")


class TestGstin:
    def test_checksum(self) -> None:
        # Shape-valid with a correct mod-36 check character (computed, invented).
        base = "27AAPFU0939F1Z"
        from app.domains.isp_partner.gst import _CHARS

        total = 0
        for i, ch in enumerate(base):
            product = _CHARS.index(ch) * (2 if i % 2 else 1)
            total += product // 36 + product % 36
        good = base + _CHARS[(36 - total % 36) % 36]
        assert gstin_valid(good)
        wrong = good[:-1] + ("0" if good[-1] != "0" else "1")
        assert not gstin_valid(wrong)
        assert not gstin_valid("27AAPFU0939F1Z")
        assert not gstin_valid("")


def test_no_suspension_or_billing_route_takes_a_router_or_nas_id() -> None:
    """ADDENDUM_01 §A.9 test 9: the only input to suspension is the
    customer; no route under service/ or billing/ names a router or NAS."""
    from app.main import create_app

    app = create_app()
    checked = 0
    for route in app.routes:
        path = getattr(route, "path", "")
        if "/isp/" not in path:
            continue
        if not any(
            part in path for part in ("/service", "/billing", "/invoices", "/zones")
        ):
            continue
        checked += 1
        names = {
            p.name for p in route.dependant.path_params + route.dependant.query_params
        }
        assert not names & {"router_id", "nas_id", "isp_router_id"}, (path, names)
    assert checked >= 30
