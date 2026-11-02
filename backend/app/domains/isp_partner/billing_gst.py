"""BILL-2 (ADDENDUM_06): GSTR-1-ready export for one month.

``GET /isp/gst/gstr1?month=YYYY-MM&section=all|b2b|b2cl|b2cs|cdnr|cdnur|hsn
&format=csv|xlsx`` (``isp_invoices.export``; flag ``ISP_BILL2_ENABLED``,
default OFF -> 404). Column headers follow the GST offline tool's CSV
templates so the file can be pasted section by section.

Rules (documented, not guessed at the call site):

* Every invoice issued in the month is reported, whatever its status: a void
  or a full credit note is itself a credit note, reported in CDNR / CDNUR /
  B2CS for the month the *note* was issued (GST practice).
* Bills of supply (``gst_applied`` false) are not taxable supplies: they are
  counted in ``nil_value_paise`` and left out of every taxable section.
* B2B = buyer GSTIN present. B2CL = no GSTIN, inter-state, invoice value over
  ``B2CL_THRESHOLD_PAISE`` (Rs 1,00,000 since 1 Aug 2024). B2CS = every
  other unregistered supply, summed by place of supply + rate; unregistered
  credit notes that do not belong to a B2CL invoice reduce B2CS.
* The tax rate of a line is derived from its own tax / taxable, snapped to
  the GST slabs; every ISP line is SAC 9984xx, normally 18 %.
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from collections import defaultdict
from datetime import UTC, date, datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session

from .apps_export import csv_response
from .bill2_config import RequireBill2Enabled
from .billing_models import IspInvoice, IspInvoiceLine
from .constants import ISP_BILLING_EXPORT  # RBAC-FIX
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .exceptions import IspInvalidQueryError

__all__ = ["B2CL_THRESHOLD_PAISE", "build_gstr1", "gst_router", "state_label"]

B2CL_THRESHOLD_PAISE = 1_00_000_00  # Rs 1,00,000 (CBIC 12/2024, from 1 Aug 2024)
_SLABS = (0, 5, 12, 18, 28)
SECTIONS = ("b2b", "b2cl", "b2cs", "cdnr", "cdnur", "hsn")

#: GST state / UT codes (CBIC list) for the "Place Of Supply" column.
STATE_NAMES: dict[str, str] = {
    "01": "Jammu and Kashmir", "02": "Himachal Pradesh", "03": "Punjab",
    "04": "Chandigarh", "05": "Uttarakhand", "06": "Haryana", "07": "Delhi",
    "08": "Rajasthan", "09": "Uttar Pradesh", "10": "Bihar", "11": "Sikkim",
    "12": "Arunachal Pradesh", "13": "Nagaland", "14": "Manipur",
    "15": "Mizoram", "16": "Tripura", "17": "Meghalaya", "18": "Assam",
    "19": "West Bengal", "20": "Jharkhand", "21": "Odisha",
    "22": "Chhattisgarh", "23": "Madhya Pradesh", "24": "Gujarat",
    "26": "Dadra and Nagar Haveli and Daman and Diu", "27": "Maharashtra",
    "29": "Karnataka", "30": "Goa", "31": "Lakshadweep", "32": "Kerala",
    "33": "Tamil Nadu", "34": "Puducherry", "35": "Andaman and Nicobar Islands",
    "36": "Telangana", "37": "Andhra Pradesh", "38": "Ladakh",
    "97": "Other Territory",
}  # fmt: skip

HEADERS: dict[str, tuple[str, ...]] = {
    "b2b": (
        "GSTIN/UIN of Recipient", "Receiver Name", "Invoice Number",
        "Invoice date", "Invoice Value", "Place Of Supply", "Reverse Charge",
        "Applicable % of Tax Rate", "Invoice Type", "E-Commerce GSTIN", "Rate",
        "Taxable Value", "Cess Amount",
    ),
    "b2cl": (
        "Invoice Number", "Invoice date", "Invoice Value", "Place Of Supply",
        "Applicable % of Tax Rate", "Rate", "Taxable Value", "Cess Amount",
        "E-Commerce GSTIN",
    ),
    "b2cs": (
        "Type", "Place Of Supply", "Applicable % of Tax Rate", "Rate",
        "Taxable Value", "Cess Amount", "E-Commerce GSTIN",
    ),
    "cdnr": (
        "GSTIN/UIN of Recipient", "Receiver Name", "Note Number", "Note Date",
        "Note Type", "Place Of Supply", "Reverse Charge", "Note Supply Type",
        "Note Value", "Applicable % of Tax Rate", "Rate", "Taxable Value",
        "Cess Amount",
    ),
    "cdnur": (
        "UR Type", "Note Number", "Note Date", "Note Type", "Place Of Supply",
        "Note Value", "Applicable % of Tax Rate", "Rate", "Taxable Value",
        "Cess Amount",
    ),
    "hsn": (
        "HSN", "Description", "UQC", "Total Quantity", "Total Value", "Rate",
        "Taxable Value", "Integrated Tax Amount", "Central Tax Amount",
        "State/UT Tax Amount", "Cess Amount",
    ),
}  # fmt: skip


def state_label(code: str | None) -> str:
    c = (code or "").zfill(2)[:2]
    return f"{c}-{STATE_NAMES.get(c, 'Unknown')}" if code else ""


def _safe(v: Any) -> Any:
    """Spreadsheet formula guard (same rule as the other ISP exports)."""
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return v


def _r(paise: int) -> float:
    return round(paise / 100, 2)


def _d(d: date) -> str:
    return d.strftime("%d-%b-%Y")


def line_rate(taxable: int, tax: int) -> int:
    """The GST slab (percent) a line's own figures imply."""
    if taxable <= 0 or tax <= 0:
        return 0
    pct = tax * 100 / taxable
    return min(_SLABS, key=lambda s: abs(s - pct))


def _rated(lines: list[Any], doc: Any) -> dict[int, dict[str, int]]:
    """{rate: {taxable, igst, cgst, sgst}} for one document. Falls back to
    the document totals when it has no line rows (pre-1b invoices)."""
    out: dict[int, dict[str, int]] = defaultdict(
        lambda: {"taxable": 0, "igst": 0, "cgst": 0, "sgst": 0}
    )
    src = lines or [doc]
    for li in src:
        tax = li.cgst_paise + li.sgst_paise + li.igst_paise
        b = out[line_rate(li.taxable_paise, tax)]
        b["taxable"] += li.taxable_paise
        b["igst"] += li.igst_paise
        b["cgst"] += li.cgst_paise
        b["sgst"] += li.sgst_paise
    return out


def _inter(doc: Any) -> bool:
    pos = doc.place_of_supply_state_code
    return bool(pos and doc.seller_state_code and pos != doc.seller_state_code)


def build_gstr1(
    docs: list[Any],
    lines_by_doc: dict[uuid.UUID, list[Any]],
    originals: dict[uuid.UUID, Any],
) -> dict[str, Any]:
    """Pure: ``docs`` are this month's invoices + credit notes (any status),
    ``originals`` maps a note's ``credit_note_for_invoice_id`` to its invoice
    (which may be from an earlier month)."""
    out: dict[str, list[dict]] = {k: [] for k in SECTIONS}
    b2cs: dict[tuple[str, int], int] = defaultdict(int)
    hsn: dict[tuple[str, int], dict[str, Any]] = {}
    nil = 0
    for doc in sorted(docs, key=lambda d: (d.issue_date, d.number)):
        if not doc.gst_applied:
            nil += doc.total_paise if doc.doc_type == "invoice" else -doc.total_paise
            continue
        lines = lines_by_doc.get(doc.id, [])
        rated = _rated(lines, doc)
        sign = 1 if doc.doc_type == "invoice" else -1
        pos = state_label(doc.place_of_supply_state_code or doc.seller_state_code)
        for li in lines or [doc]:
            sac = getattr(li, "sac_code", None) or "998422"
            tax = li.cgst_paise + li.sgst_paise + li.igst_paise
            key = (sac, line_rate(li.taxable_paise, tax))
            h = hsn.setdefault(
                key,
                {"qty": 0, "value": 0, "taxable": 0, "igst": 0, "cgst": 0, "sgst": 0},
            )
            h["qty"] += sign * int(getattr(li, "quantity", 1) or 1)
            h["value"] += sign * li.total_paise
            h["taxable"] += sign * li.taxable_paise
            h["igst"] += sign * li.igst_paise
            h["cgst"] += sign * li.cgst_paise
            h["sgst"] += sign * li.sgst_paise
        if doc.doc_type == "invoice":
            if doc.bill_to_gstin:
                for rate, b in sorted(rated.items()):
                    out["b2b"].append(
                        {
                            "GSTIN/UIN of Recipient": doc.bill_to_gstin,
                            "Receiver Name": doc.bill_to_name or "",
                            "Invoice Number": doc.number,
                            "Invoice date": _d(doc.issue_date),
                            "Invoice Value": _r(doc.total_paise),
                            "Place Of Supply": pos,
                            "Reverse Charge": "N",
                            "Applicable % of Tax Rate": "",
                            "Invoice Type": "Regular B2B",
                            "E-Commerce GSTIN": "",
                            "Rate": rate,
                            "Taxable Value": _r(b["taxable"]),
                            "Cess Amount": 0,
                        }
                    )
            elif _inter(doc) and doc.total_paise > B2CL_THRESHOLD_PAISE:
                for rate, b in sorted(rated.items()):
                    out["b2cl"].append(
                        {
                            "Invoice Number": doc.number,
                            "Invoice date": _d(doc.issue_date),
                            "Invoice Value": _r(doc.total_paise),
                            "Place Of Supply": pos,
                            "Applicable % of Tax Rate": "",
                            "Rate": rate,
                            "Taxable Value": _r(b["taxable"]),
                            "Cess Amount": 0,
                            "E-Commerce GSTIN": "",
                        }
                    )
            else:
                for rate, b in rated.items():
                    b2cs[(pos, rate)] += b["taxable"]
            continue
        # credit note
        orig = originals.get(doc.credit_note_for_invoice_id)
        if doc.bill_to_gstin:
            for rate, b in sorted(rated.items()):
                out["cdnr"].append(
                    {
                        "GSTIN/UIN of Recipient": doc.bill_to_gstin,
                        "Receiver Name": doc.bill_to_name or "",
                        "Note Number": doc.number,
                        "Note Date": _d(doc.issue_date),
                        "Note Type": "C",
                        "Place Of Supply": pos,
                        "Reverse Charge": "N",
                        "Note Supply Type": "Regular",
                        "Note Value": _r(doc.total_paise),
                        "Applicable % of Tax Rate": "",
                        "Rate": rate,
                        "Taxable Value": _r(b["taxable"]),
                        "Cess Amount": 0,
                    }
                )
        elif (
            orig is not None
            and _inter(orig)
            and orig.total_paise > B2CL_THRESHOLD_PAISE
        ):
            for rate, b in sorted(rated.items()):
                out["cdnur"].append(
                    {
                        "UR Type": "B2CL",
                        "Note Number": doc.number,
                        "Note Date": _d(doc.issue_date),
                        "Note Type": "C",
                        "Place Of Supply": pos,
                        "Note Value": _r(doc.total_paise),
                        "Applicable % of Tax Rate": "",
                        "Rate": rate,
                        "Taxable Value": _r(b["taxable"]),
                        "Cess Amount": 0,
                    }
                )
        else:
            for rate, b in rated.items():
                b2cs[(pos, rate)] -= b["taxable"]
    for (pos, rate), taxable in sorted(b2cs.items()):
        if taxable == 0:
            continue
        out["b2cs"].append(
            {
                "Type": "OE",
                "Place Of Supply": pos,
                "Applicable % of Tax Rate": "",
                "Rate": rate,
                "Taxable Value": _r(taxable),
                "Cess Amount": 0,
                "E-Commerce GSTIN": "",
            }
        )
    for (sac, rate), h in sorted(hsn.items()):
        out["hsn"].append(
            {
                "HSN": sac,
                "Description": "Internet access services",
                "UQC": "NA",
                "Total Quantity": h["qty"],
                "Total Value": _r(h["value"]),
                "Rate": rate,
                "Taxable Value": _r(h["taxable"]),
                "Integrated Tax Amount": _r(h["igst"]),
                "Central Tax Amount": _r(h["cgst"]),
                "State/UT Tax Amount": _r(h["sgst"]),
                "Cess Amount": 0,
            }
        )
    return {"sections": out, "nil_value_paise": nil}


def month_bounds(month: str) -> tuple[date, date]:
    try:
        start = datetime.strptime(month, "%Y-%m").date()
    except ValueError:
        raise IspInvalidQueryError(
            "month must be YYYY-MM", field="month", reason="ISP_MONTH_FORMAT"
        ) from None
    nxt = (start.replace(day=28) + timedelta(days=4)).replace(day=1)
    return start, nxt


async def gstr1_for(session: Any, isp_org_id: uuid.UUID, month: str) -> dict[str, Any]:
    start, end = month_bounds(month)
    docs = (
        (
            await session.execute(
                select(IspInvoice).where(
                    IspInvoice.isp_organization_id == isp_org_id,
                    IspInvoice.issue_date >= start,
                    IspInvoice.issue_date < end,
                )
            )
        )
        .scalars()
        .all()
    )
    ids = [d.id for d in docs]
    lines_by_doc: dict[uuid.UUID, list[Any]] = defaultdict(list)
    if ids:
        for li in (
            await session.execute(
                select(IspInvoiceLine).where(IspInvoiceLine.invoice_id.in_(ids))
            )
        ).scalars():
            lines_by_doc[li.invoice_id].append(li)
    orig_ids = {
        d.credit_note_for_invoice_id for d in docs if d.credit_note_for_invoice_id
    }
    originals: dict[uuid.UUID, Any] = {}
    if orig_ids:
        for o in (
            await session.execute(
                select(IspInvoice).where(
                    IspInvoice.id.in_(orig_ids),
                    IspInvoice.isp_organization_id == isp_org_id,
                )
            )
        ).scalars():
            originals[o.id] = o
    return build_gstr1(list(docs), lines_by_doc, originals)


gst_router = APIRouter(
    prefix="/gst",
    tags=["ISP Partner: GST returns"],
    dependencies=[Depends(RequireBill2Enabled)],
)


@gst_router.get("/gstr1", dependencies=isp_guards(ISP_BILLING_EXPORT))
async def gstr1_export(
    month: str = Query(pattern=r"^\d{4}-\d{2}$"),
    section: Literal["all", "b2b", "b2cl", "b2cs", "cdnr", "cdnur", "hsn"] = "all",
    format: Literal["csv", "xlsx", "json"] = "xlsx",
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> Response:
    from app.domains.analytics.constants import ExportFormat
    from app.domains.analytics.export import render_report
    from app.domains.analytics.report_types import ReportPayload, ReportSection

    data = await gstr1_for(db, isp.isp_org_id, month)
    keys = SECTIONS if section == "all" else (section,)
    if format == "csv" and section == "all":
        raise IspInvalidQueryError(
            "CSV is one section per file: pick a section, or use xlsx",
            field="section",
            reason="ISP_CSV_ONE_SECTION",
        )
    if format == "json":
        body = {
            "month": month,
            "nil_value_paise": data["nil_value_paise"],
            **{k: data["sections"][k] for k in keys},
        }
        return Response(json.dumps(body), media_type="application/json")
    if format == "csv":
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=HEADERS[section])
        w.writeheader()
        for row in data["sections"][section]:
            w.writerow({k: _safe(v) for k, v in row.items()})
        return csv_response(buf.getvalue().encode(), f"gstr1-{month}-{section}.csv")
    payload = ReportPayload(
        report_type="isp_gstr1",
        title=f"GSTR-1 {month} {isp.organization.name}",
        generated_at=datetime.now(UTC).isoformat(),
        organization_id=None,
        location_id=None,
        period_start=month,
        period_end=month,
        sections=[
            ReportSection(
                key=k,
                title=k.upper(),
                data={k: data["sections"][k] or [dict.fromkeys(HEADERS[k], "")]},
            )
            for k in keys
        ],
    )
    rendered = render_report(payload, ExportFormat.EXCEL)
    return Response(
        content=rendered.content,
        media_type=rendered.content_type,
        headers={
            "Content-Disposition": f'attachment; filename="gstr1-{month}.xlsx"',
            "Cache-Control": "no-store",
        },
    )
