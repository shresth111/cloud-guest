"""IPDR-2 pure rules: event vs receipt time never conflated, confidence,
retention maths, the field-coverage statement, renderers, guards."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from types import SimpleNamespace

import pytest

from app.domains.isp_partner import ipdr_lea as lea

T0 = datetime(2026, 10, 31, 18, 30, tzinfo=UTC)  # 2026-11-01 00:00 IST


def test_ist_formatting() -> None:
    assert lea.ist(T0) == "2026-11-01 00:00:00 IST"
    assert lea.ist(None) is None


def test_receipt_never_stands_in_for_event_time() -> None:
    p = lea.time_pair(None, T0, None, gap_minutes=5)
    assert p["event_time_ist"] is None and p["event_time_reported"] is False
    assert p["receipt_time_ist"] == "2026-11-01 00:00:00 IST"
    assert p["gap_minutes"] is None and p["gap_flag"] is False


def test_gap_flag_and_receipt_basis() -> None:
    p = lea.time_pair(T0, T0 + timedelta(minutes=7), None, gap_minutes=5)
    assert p["gap_minutes"] == 7.0 and p["gap_flag"] is True
    assert p["receipt_basis"] == "arrived_at"
    p = lea.time_pair(T0, None, T0 + timedelta(minutes=1), gap_minutes=5)
    assert p["receipt_basis"] == "collector_window" and p["gap_flag"] is False
    # a router clock ahead of ours shows as a negative gap and is flagged
    assert lea.time_pair(T0, T0 - timedelta(minutes=30), None, gap_minutes=5)[
        "gap_flag"
    ]


@pytest.mark.parametrize(
    ("verdict", "source", "n", "want"),
    [
        ("unique", "nat_event", 1, "high"),
        ("unique", "derived", 1, "medium"),
        ("unique", "ambiguous", 1, "low"),
        ("multiple", "nat_event", 2, "low"),
        ("multiple_candidates", "nat_event", 1, "low"),
        ("none", None, 0, "none"),
    ],
)
def test_confidence(verdict, source, n, want) -> None:  # noqa: ANN001
    assert lea.confidence(verdict, source, n) == want


def test_zero_row_days() -> None:
    d = date(2026, 10, 1)
    up = {d, d + timedelta(days=1), d + timedelta(days=2)}
    rows = {d, d + timedelta(days=2)}
    assert lea.zero_row_days(up, rows, since=d, until=d + timedelta(days=3)) == [
        "2026-10-02"
    ]  # day 4 the router was not up: not a gap


def test_retention_row() -> None:
    now = T0
    r = lea.retention_row(
        oldest_nat=now - timedelta(days=100),
        oldest_session=now - timedelta(days=800),
        now=now,
        gaps=["2026-10-02"],
    )
    assert r["nat_days_held"] == 100 and r["session_days_held"] == 800
    assert r["target_met"] is False and r["days_to_target"] == 630
    assert r["zero_row_day_count"] == 1
    none = lea.retention_row(oldest_nat=None, oldest_session=None, now=now, gaps=[])
    assert none["target_met"] is False and none["days_to_target"] is None


def test_never_pruned_lists_cert_in_tables() -> None:
    for t in (
        "guest_sessions",
        "guest_login_history",
        "otp_requests",
        "audit_log_entries",
    ):
        assert t in lea.NEVER_PRUNED


def test_field_coverage_is_honest() -> None:
    statuses = {f["status"] for f in lea.FIELD_COVERAGE}
    assert statuses <= {"available", "partial", "not_collected", "not_applicable"}
    text = " ".join(f["field"] + " " + f["source"] for f in lea.FIELD_COVERAGE)
    assert "last 4" in text and "never" in text.lower()
    assert any(f["status"] == "not_collected" for f in lea.FIELD_COVERAGE)


def _report() -> dict:
    row = {"router_name": "hEX", "public_ip": "1.2.3.4", "gap_flag": True}
    match = {
        "candidate": "1 of 1",
        "id_number_masked": "XXXX XXXX 1234",
        "name": "A <b>",
    }
    return {
        "lea_reference": "LEA/2026/77",
        "reason": "Notice u/s 91",
        "generated_at_ist": "x",
        "generated_by": "Owner",
        "query": {
            "public_ip": "1.2.3.4",
            "public_port": 4000,
            "at_ist": "a",
            "window_start_ist": "b",
            "window_end_ist": "c",
        },
        "verdict": "unique",
        "time_basis": "t",
        "nat_rows": [row],
        "matches": [match],
    }


def test_xlsx_renders_sheets() -> None:
    import io

    from openpyxl import load_workbook

    wb = load_workbook(io.BytesIO(lea.render_xlsx(_report())))
    assert wb.sheetnames == ["Request", "NAT rows", "Matches"]
    vals = [c.value for row in wb["Matches"].iter_rows() for c in row]
    assert "XXXX XXXX 1234" in vals
    assert "LEA/2026/77" in [c.value for row in wb["Request"].iter_rows() for c in row]


def test_pdf_renders() -> None:
    assert lea.render_pdf(_report())[:4] == b"%PDF"


def test_request_needs_lea_reference_and_reason() -> None:
    from pydantic import ValidationError

    from app.domains.isp_partner.ipdr_lea_router import LeaTraceRequest

    base = {"public_ip": "1.2.3.4", "at": "2026-11-01T10:00:00"}
    for bad in (
        {},
        {"lea_reference": "LEA-1"},
        {"lea_reference": "", "reason": "x" * 5},
    ):
        with pytest.raises(ValidationError):
            LeaTraceRequest(**base, **bad)
    with pytest.raises(ValidationError):
        LeaTraceRequest(**base, lea_reference="LEA\n1", reason="court order")
    assert (
        LeaTraceRequest(**base, lea_reference="LEA-1", reason="court order").format
        == "json"
    )


async def test_non_owner_admin_refused_before_any_work() -> None:
    from app.domains.isp_partner.ipdr_lea_router import (
        IspLeaOwnerAdminOnlyError,
        LeaTraceRequest,
        lea_trace,
    )

    body = LeaTraceRequest(
        public_ip="1.2.3.4", at="2026-11-01T10:00:00", lea_reference="L-1", reason="abc"
    )
    for role in ("isp-noc", "isp-technician", "isp-billing", "isp-viewer"):
        with pytest.raises(IspLeaOwnerAdminOnlyError):
            await lea_trace(
                None, body, SimpleNamespace(role_slug=role), None, None, None, None
            )


def test_routes_guarded_and_flag_gated() -> None:
    from app.domains.isp_partner.ipdr_lea_router import (
        RequireIpdrLeaEnabled,
        ipdr_lea_router,
    )

    seen = set()
    for r in ipdr_lea_router.routes:
        deps = {d.call for d in r.dependant.dependencies}
        names = {getattr(d, "__name__", type(d).__name__) for d in deps}
        assert RequireIpdrLeaEnabled in deps
        assert {"RequireIspPartner", "RejectLocationRouterHeaders"} <= names
        seen.add((r.path, tuple(sorted(r.methods))))
    assert seen == {
        ("/compliance/lea-trace", ("POST",)),
        ("/compliance/retention", ("GET",)),
        ("/compliance/ipdr-field-coverage", ("GET",)),
    }
