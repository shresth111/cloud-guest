"""IPDR-2 (ADDENDUM_06): LEA reverse-IP trace report, retention status, and
the DoT IPDR field-coverage statement. Pure helpers + renderers; the routes
are in ``ipdr_lea_router``.

Time rules (ADDENDUM_06 IPDR-2 §2):
* ``event_time`` is the router's own timestamp for the flow / NAT event
  (``traffic_flow_records.flow_start``). When the router did not send one it
  is ``None`` and the report says "not reported". Receipt time NEVER stands
  in for it.
* ``receipt_time`` is when the platform received the record
  (``arrived_at``; ``window_start`` of the collector bucket only when
  ``arrived_at`` is missing, and then labelled so).
* Both are shown in IST; a row whose receipt lags its event by more than
  ``gap_minutes`` is flagged.

Aadhaar: the platform stores only the last four digits (J6); the report
prints ``id_number_masked`` and nothing else. Nothing here prunes data.
"""

from __future__ import annotations

import io
from datetime import UTC, date, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

IST = ZoneInfo("Asia/Kolkata")
RETENTION_TARGET_DAYS = 730  # 2 years (DoT licence condition for IPDR)

#: CERT-In / audit tables that the retention job must never prune
#: (memory: wyfy_db_retention_and_indexes). Shown on the retention card.
NEVER_PRUNED = (
    "guest_sessions",
    "guest_login_history",
    "otp_requests",
    "audit_log_entries",
    "login_attempts",
    "traffic_flow_records",
)


def ist(value: datetime | None) -> str | None:
    if value is None:
        return None
    aware = value if value.tzinfo else value.replace(tzinfo=UTC)
    return aware.astimezone(IST).strftime("%Y-%m-%d %H:%M:%S IST")


def time_pair(
    event: datetime | None,
    arrived: datetime | None,
    window_start: datetime | None,
    *,
    gap_minutes: int,
) -> dict[str, Any]:
    """Event vs receipt, never conflated."""
    receipt = arrived or window_start
    receipt_basis = (
        "arrived_at" if arrived else ("collector_window" if window_start else None)
    )
    gap = None
    if event is not None and receipt is not None:
        e = event if event.tzinfo else event.replace(tzinfo=UTC)
        r = receipt if receipt.tzinfo else receipt.replace(tzinfo=UTC)
        gap = round((r - e).total_seconds() / 60, 1)
    return {
        "event_time_ist": ist(event),
        "event_time_reported": event is not None,
        "receipt_time_ist": ist(receipt),
        "receipt_basis": receipt_basis,
        "gap_minutes": gap,
        "gap_flag": gap is not None and abs(gap) > gap_minutes,
    }


def confidence(verdict: str, nat_source: str | None, candidates: int) -> str:
    """high: one identity from a router-reported translation; medium: one
    identity from a derived translation; low: ambiguous translation or
    several candidates; none: nothing matched."""
    if candidates == 0:
        return "none"
    if (
        candidates > 1
        or verdict in ("multiple", "multiple_candidates")
        or (nat_source == "ambiguous")
    ):
        return "low"
    if nat_source == "derived":
        return "medium"
    return "high"


def zero_row_days(
    up_days: set[date], row_days: set[date], *, since: date, until: date
) -> list[str]:
    """Days the router was up (a health snapshot exists) but sent no row."""
    out = []
    d = since
    while d <= until:
        if d in up_days and d not in row_days:
            out.append(d.isoformat())
        d += timedelta(days=1)
    return out


def retention_row(
    *,
    oldest_nat: datetime | None,
    oldest_session: datetime | None,
    now: datetime,
    gaps: list[str],
) -> dict[str, Any]:
    def days(v: datetime | None) -> int | None:
        if v is None:
            return None
        a = v if v.tzinfo else v.replace(tzinfo=UTC)
        return max(0, (now - a).days)

    nat_days, sess_days = days(oldest_nat), days(oldest_session)
    held = (
        min(x for x in (nat_days, sess_days) if x is not None)
        if (nat_days is not None or sess_days is not None)
        else None
    )
    return {
        "oldest_nat_ist": ist(oldest_nat),
        "oldest_session_ist": ist(oldest_session),
        "nat_days_held": nat_days,
        "session_days_held": sess_days,
        "target_days": RETENTION_TARGET_DAYS,
        "target_met": held is not None and held >= RETENTION_TARGET_DAYS,
        "days_to_target": None
        if held is None
        else max(0, RETENTION_TARGET_DAYS - held),
        "zero_row_days": gaps,
        "zero_row_day_count": len(gaps),
    }


# ---------------------------------------------------------------------------
# DoT IPDR field coverage (documented, never faked)
# ---------------------------------------------------------------------------

#: status: available | partial | not_collected | not_applicable
FIELD_COVERAGE: tuple[dict[str, str], ...] = (
    {
        "field": "Subscriber user id / login",
        "status": "available",
        "source": "guest session identifier; isp_subscribers.identifier",
    },
    {
        "field": "Subscriber name, address, phone, email",
        "status": "available",
        "source": "isp_subscribers + JAZE-3 KYC (installation / permanent address)",
    },
    {
        "field": "ID proof type and number",
        "status": "partial",
        "source": "KYC: type + masked number only. Aadhaar is stored as last 4 digits; "
        "the full number is never held, so it can never be produced.",
    },
    {
        "field": "Gender / date of birth",
        "status": "partial",
        "source": "KYC gender / date_of_birth, only when the ISP collected them; empty "
        "otherwise (never inferred).",
    },
    {
        "field": "Device MAC address",
        "status": "available",
        "source": "guest device MAC; DHCP lease MAC when the session has none",
    },
    {
        "field": "Private (source) IP and port",
        "status": "available",
        "source": "traffic_flow_records.src_address / src_port",
    },
    {
        "field": "Public (translated) IP and port",
        "status": "partial",
        "source": "router NAT events (nat_source=nat_event). When the router exports "
        "flows without NAT fields the port is derived or ambiguous, and the "
        "report says so.",
    },
    {
        "field": "Destination IP and port",
        "status": "available",
        "source": "traffic_flow_records.dst_address / dst_port",
    },
    {
        "field": "Protocol",
        "status": "available",
        "source": "traffic_flow_records.protocol",
    },
    {
        "field": "Connection start / end time (event)",
        "status": "partial",
        "source": "flow_start / flow_end from the router. Not every exporter "
        "sends them; "
        "when absent the event time is reported as missing, never replaced by "
        "receipt time.",
    },
    {
        "field": "Record receipt time",
        "status": "available",
        "source": "traffic_flow_records.arrived_at "
        "(collector window as fallback, labelled)",
    },
    {
        "field": "IP lease allocate / release time",
        "status": "partial",
        "source": "guest session start / end, or the DHCP lease window where synced",
    },
    {
        "field": "NAS / router identity",
        "status": "available",
        "source": "router name and id; NAS client for PPPoE",
    },
    {
        "field": "NAS port / interface",
        "status": "partial",
        "source": "PPPoE NAS-Port-Id (JAZE-6). Hotspot sessions do not record one.",
    },
    {
        "field": "IPv6 delegated prefix",
        "status": "partial",
        "source": "PPPoE Delegated-IPv6-Prefix when the NAS sends it; "
        "hotspot is IPv4 only",
    },
    {
        "field": "Bytes up / down",
        "status": "available",
        "source": "flow bytes; session byte counters",
    },
    {
        "field": "Router clock skew (NTP)",
        "status": "not_collected",
        "source": "No per-router NTP offset is polled today; compare event and receipt "
        "times (gap flag) instead.",
    },
    {
        "field": "Cell / tower / location of the user",
        "status": "not_applicable",
        "source": "Fixed-line and hotspot service; "
        "the installation address is the location.",
    },
)


# ---------------------------------------------------------------------------
# renderers
# ---------------------------------------------------------------------------

NAT_COLUMNS = (
    ("router_name", "Router"),
    ("private_ip", "Private IP"),
    ("private_port", "Private port"),
    ("public_ip", "Public IP"),
    ("public_port", "Public port"),
    ("dst_ip", "Destination IP"),
    ("dst_port", "Destination port"),
    ("protocol", "Protocol"),
    ("event_time_ist", "Event time (router, IST)"),
    ("receipt_time_ist", "Receipt time (platform, IST)"),
    ("gap_minutes", "Gap (min)"),
    ("gap_flag", "Gap flagged"),
)
MATCH_COLUMNS = (
    ("candidate", "Candidate"),
    ("confidence", "Confidence"),
    ("user_id", "User id"),
    ("mac", "MAC"),
    ("router_name", "NAS / router"),
    ("interface", "Interface"),
    ("private_ip", "Private IP"),
    ("private_port", "Private port"),
    ("lease_start_ist", "Lease / session start (IST)"),
    ("lease_end_ist", "Lease / session end (IST)"),
    ("event_time_ist", "Event time (router, IST)"),
    ("receipt_time_ist", "Receipt time (platform, IST)"),
    ("nat_source", "Translation source"),
    ("name", "Subscriber name"),
    ("phone", "Phone"),
    ("email", "Email"),
    ("installation_address", "Installation address"),
    ("permanent_address", "Permanent address"),
    ("id_proof_type", "ID proof"),
    ("id_number_masked", "ID number (masked)"),
    ("caf_number", "CAF no."),
    ("caf_pdf", "CAF PDF"),
)


def _cell(v: Any) -> Any:
    if v is None:
        return ""
    if isinstance(v, bool):
        return "yes" if v else "no"
    return v


def render_xlsx(report: dict[str, Any]) -> bytes:
    from openpyxl import Workbook

    wb = Workbook()
    ws = wb.active
    ws.title = "Request"
    for k, v in (
        ("LEA reference", report["lea_reference"]),
        ("Reason", report["reason"]),
        ("Public IP", report["query"]["public_ip"]),
        ("Public port", report["query"]["public_port"]),
        ("Time asked (IST)", report["query"]["at_ist"]),
        (
            "Window (IST)",
            f"{report['query']['window_start_ist']} .. "
            f"{report['query']['window_end_ist']}",
        ),
        ("Verdict", report["verdict"]),
        ("Generated (IST)", report["generated_at_ist"]),
        ("Generated by", report["generated_by"]),
        ("Time basis", report["time_basis"]),
        (
            "Aadhaar",
            "Only the last 4 digits are held; the full number is never stored.",
        ),
    ):
        ws.append([k, _cell(v)])
    for title, cols, rows in (
        ("NAT rows", NAT_COLUMNS, report["nat_rows"]),
        ("Matches", MATCH_COLUMNS, report["matches"]),
    ):
        sheet = wb.create_sheet(title)
        sheet.append([label for _k, label in cols])
        for r in rows:
            sheet.append([_cell(r.get(k)) for k, _label in cols])
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def render_pdf(report: dict[str, Any]) -> bytes:
    from xml.sax.saxutils import escape

    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    styles = getSampleStyleSheet()
    small = styles["BodyText"].clone("small", fontSize=7, leading=8)
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=landscape(A4),
        leftMargin=1 * cm,
        rightMargin=1 * cm,
        topMargin=1 * cm,
        bottomMargin=1 * cm,
        title=f"Reverse IP trace {report['lea_reference']}",
    )
    p = lambda t: Paragraph(escape("" if t is None else str(t)), small)  # noqa: E731
    q = report["query"]
    story: list[Any] = [
        Paragraph("Reverse IP trace report", styles["Title"]),
        Paragraph(
            escape(
                f"LEA reference: {report['lea_reference']} | "
                f"Reason: {report['reason']} | "
                f"Generated {report['generated_at_ist']} by {report['generated_by']}"
            ),
            styles["BodyText"],
        ),
        Paragraph(
            escape(
                f"Public {q['public_ip']}:{q['public_port'] or '*'} at {q['at_ist']} "
                f"(window {q['window_start_ist']} .. {q['window_end_ist']}). "
                f"Verdict: {report['verdict']}."
            ),
            styles["BodyText"],
        ),
        Paragraph(escape(report["time_basis"]), small),
        Paragraph(
            "Aadhaar: only the last 4 digits are held by the platform; the full "
            "number is never stored and cannot appear in this report.",
            small,
        ),
        Spacer(1, 6),
    ]
    for title, cols, rows in (
        ("NAT rows", NAT_COLUMNS, report["nat_rows"]),
        ("Matching sessions and subscribers", MATCH_COLUMNS, report["matches"]),
    ):
        story.append(Paragraph(title, styles["Heading3"]))
        if not rows:
            story.append(p("None."))
            continue
        data = [[p(label) for _k, label in cols]] + [
            [p(_cell(r.get(k))) for k, _label in cols] for r in rows
        ]
        t = Table(data, repeatRows=1)
        t.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(t)
        story.append(Spacer(1, 6))
    doc.build(story)
    return buf.getvalue()


__all__ = [
    "FIELD_COVERAGE",
    "IST",
    "NEVER_PRUNED",
    "RETENTION_TARGET_DAYS",
    "confidence",
    "ist",
    "render_pdf",
    "render_xlsx",
    "retention_row",
    "time_pair",
    "zero_row_days",
]
