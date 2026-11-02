"""SMALL-4: DSO and the trend fallback (pure)."""

from __future__ import annotations

from datetime import date
from decimal import Decimal
from types import SimpleNamespace

from app.domains.isp_partner import revenue_snapshot as rs


def test_dso() -> None:
    assert rs.dso(0, 0) is None
    assert rs.dso(236000, 236000) == Decimal("90.0")
    assert rs.dso(1, 3) == Decimal("30.0")
    assert rs.dso(100, 7) == Decimal("1285.7")


def test_trend_sources() -> None:
    trend = [
        {"month": "2026-09", "partial": False, "billed_paise": 5},
        {"month": "2026-10", "partial": False, "billed_paise": 7},
        {"month": "2026-11", "partial": True, "billed_paise": 9},
    ]
    snap = SimpleNamespace(
        mrr_paise=80, arpu_paise=40, active=2, snapshot_date=date(2026, 9, 20)
    )
    rs.apply_to_trend(
        trend, {"2026-09": snap}, live_mrr=100, live_arpu=50, live_active=2
    )
    assert [t["mrr_source"] for t in trend] == ["snapshot", "billed_proxy", "live"]
    assert [t["mrr_paise"] for t in trend] == [80, 7, 100]
    rs.apply_to_trend(trend, None, live_mrr=1, live_arpu=None, live_active=0)
    assert trend[0]["mrr_source"] == "billed_proxy"
