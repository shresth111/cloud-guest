"""SMALL-2: splitting one invoice-level discount across lines (pure)."""

from __future__ import annotations

from app.domains.isp_partner.customer_discount import split_discount


def test_split_is_exact_and_proportional() -> None:
    assert split_discount([60000, 60000], 15000) == [7500, 7500]
    assert split_discount([100, 100, 100], 100) == [34, 33, 33]
    got = split_discount([33333, 66667, 1], 10001)
    assert sum(got) == 10001 and all(g >= 0 for g in got)


def test_split_edges() -> None:
    assert split_discount([500], 900) == [500]  # never above the gross
    assert split_discount([0, 0], 100) == [0, 0]
    assert split_discount([100, 200], 0) == [0, 0]
