"""DISCOUNT-WIRE: the pre-tax math and the wiring contract (no DB)."""

from __future__ import annotations

import inspect

from app.domains.isp_partner import discount_wire as dw
from app.domains.isp_partner import discount_wire_router as dwr


def test_discount_is_taken_before_gst_intra_and_inter() -> None:
    kw = {"gst_applied": True, "rate_bp": 1800}
    t = dw.line_tax_after_discount(
        100000, 10000, includes_gst=False, intra_state=True, **kw
    )
    assert (t.taxable, t.cgst, t.sgst, t.igst, t.total) == (
        90000,
        8100,
        8100,
        0,
        106200,
    )
    t = dw.line_tax_after_discount(
        100000, 10000, includes_gst=False, intra_state=False, **kw
    )
    assert (t.taxable, t.igst, t.total) == (90000, 16200, 106200)
    # GST-inclusive Rs 1,180 = Rs 1,000 taxable; the discount comes off that
    t = dw.line_tax_after_discount(
        118000, 10000, includes_gst=True, intra_state=True, **kw
    )
    assert (t.taxable, t.total) == (90000, 106200)
    assert dw.taxable_gross(118000, includes_gst=True, **kw) == 100000
    # never below zero; GST off = the plain difference
    assert (
        dw.line_tax_after_discount(
            5000, 9000, includes_gst=False, intra_state=True, **kw
        ).total
        == 0
    )
    t = dw.line_tax_after_discount(
        100000,
        10000,
        includes_gst=True,
        intra_state=True,
        gst_applied=False,
        rate_bp=1800,
    )
    assert (t.taxable, t.total) == (90000, 90000)


def test_every_path_quotes_before_writing_and_records_after() -> None:
    from app.domains.isp_partner import onboarding_router, plans_service

    for mod, fn in (
        (plans_service.IspPlansService, "recharge"),
        (onboarding_router, "_first_invoice"),
    ):
        src = inspect.getsource(getattr(mod, fn))
        a, b, c = (
            src.index("apply_to_line("),
            src.index("issue_subscriber_invoice("),
            src.index("record_discount("),
        )
        assert a < b < c, fn


def test_flag_off_by_default_and_probe_route() -> None:
    assert dw.IspDiscountApplySettings().discount_apply_enabled is False
    paths = {r.path for r in dwr.discount_wire_router.routes}
    assert paths == {"/billing/discount-apply"}
