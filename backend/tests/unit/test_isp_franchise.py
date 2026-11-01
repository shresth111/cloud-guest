"""FRANCHISE-2 pure rules + guards."""

from __future__ import annotations

from datetime import date

import pytest

from app.domains.isp_partner import franchise_service as fs


@pytest.mark.parametrize(
    ("mode", "total", "bp", "wh", "want"),
    [
        ("percent", 50000, 3000, 0, 35000),
        ("percent", 50000, 0, 0, 50000),
        ("percent", 50000, 10000, 0, 0),
        ("percent", 50001, 3000, 0, 35000),  # floor, never over-debits
        ("percent", 50000, 12000, 0, 0),  # clamped
        ("wholesale", 50000, 3000, 12000, 12000),
        ("wholesale", 50000, 3000, -5, 0),
    ],
)
def test_isp_share(mode, total, bp, wh, want) -> None:  # noqa: ANN001
    assert (
        fs.isp_share(mode, total_paise=total, zone_share_bp=bp, wholesale_paise=wh)
        == want
    )


def test_reversal_amount() -> None:
    assert (
        fs.reversal_amount(
            35000, note_paise=50000, invoice_total_paise=50000, already_reversed=0
        )
        == 35000
    )
    assert (
        fs.reversal_amount(
            35000, note_paise=25000, invoice_total_paise=50000, already_reversed=0
        )
        == 17500
    )
    # never more than what is left
    assert (
        fs.reversal_amount(
            35000, note_paise=50000, invoice_total_paise=50000, already_reversed=30000
        )
        == 5000
    )
    assert (
        fs.reversal_amount(0, note_paise=1, invoice_total_paise=1, already_reversed=0)
        == 0
    )
    assert (
        fs.reversal_amount(10, note_paise=1, invoice_total_paise=0, already_reversed=0)
        == 0
    )


def test_standing_matches_jaze4() -> None:
    assert fs.standing(100, 100) == "paid"
    assert fs.standing(99, 100) == "unpaid"
    assert fs.standing(-5, -10) == "paid"


def test_due_period() -> None:
    start = date(2026, 1, 1)
    assert fs.due_period(date(2026, 11, 5), 5, start, None) == "2026-11"
    assert fs.due_period(date(2026, 11, 4), 5, start, None) is None
    assert fs.due_period(date(2026, 11, 20), 5, start, "2026-11") is None
    assert fs.due_period(date(2026, 12, 5), 5, start, "2026-11") == "2026-12"
    assert fs.due_period(date(2025, 12, 31), 1, start, None) is None


def test_flags_default_off(monkeypatch: pytest.MonkeyPatch) -> None:
    for k in (
        "ISP_FRANCHISE_ENABLED",
        "ISP_ZONE_AUTODEBIT_ENABLED",
        "ISP_ZONE_ENFORCE_CREDIT",
    ):
        monkeypatch.delenv(k, raising=False)
    fs.get_franchise_settings.cache_clear()
    s = fs.get_franchise_settings()
    assert not (
        s.franchise_enabled or s.zone_autodebit_enabled or s.zone_enforce_credit
    )
    fs.get_franchise_settings.cache_clear()


def test_routes_guarded_and_flag_gated() -> None:
    from app.domains.isp_partner.franchise_router import (
        RequireFranchiseEnabled,
        franchise_router,
    )

    for r in franchise_router.routes:
        deps = {d.call for d in r.dependant.dependencies}
        names = {getattr(d, "__name__", type(d).__name__) for d in deps}
        assert RequireFranchiseEnabled in deps, r.path
        assert {"RequireIspPartner", "RejectLocationRouterHeaders"} <= names, r.path
    assert len(franchise_router.routes) == 11  # + FINISH settlement invoice


def test_hook_is_registered_by_the_models_module() -> None:
    from sqlalchemy import event
    from sqlalchemy.orm import Session

    import app.domains.isp_partner.models  # noqa: F401

    assert event.contains(Session, "before_flush", fs._zone_autodebit)
