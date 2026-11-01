"""SMALL-3: save-rate arithmetic and the action route's guard shape."""

from __future__ import annotations

from app.domains.isp_partner.winback_service import rate


def test_rate() -> None:
    assert rate(0, 0) is None
    assert rate(2, 1) == 0.6667
    assert rate(3, 0) == 1.0


def test_routes_are_flag_gated_and_keyed() -> None:
    from app.domains.isp_partner.revenue_router import RequireRevenueHubEnabled
    from app.domains.isp_partner.winback_router import winback_router

    for r in winback_router.routes:
        deps = [d.dependency for d in r.dependencies]
        assert RequireRevenueHubEnabled in deps, r.path
