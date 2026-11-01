"""CSV exports for the J16 Apps lists (``isp_apps.export``).

Each export re-uses the list service with the same filters as its list
route, so an export can never show a row the list would hide (confinement
included). Cells that start with a spreadsheet formula character are
prefixed with ``'`` (the same guard as ``billing_router._csv``).
"""

from __future__ import annotations

import csv
import io
from collections.abc import Callable, Iterable
from datetime import datetime
from typing import Any

from fastapi import Response

#: Hard cap on rows in one export; the list services page through this.
MAX_EXPORT_ROWS = 50_000


def _cell(v: Any) -> Any:
    if v is None:
        return ""
    if isinstance(v, datetime):
        return v.isoformat()
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return v


Column = tuple[str, Callable[[dict], Any]]


def _key(name: str) -> Callable[[dict], Any]:
    return lambda row: row.get(name)


TICKET_COLUMNS: tuple[Column, ...] = (
    ("Number", _key("number")),
    ("Opened", _key("opened_at")),
    ("Customer", _key("customer_name")),
    ("Subscriber", _key("subscriber_label")),
    ("Type", _key("type_name")),
    ("Subject", _key("subject")),
    ("Source", _key("source")),
    ("Priority", _key("priority")),
    ("Status", _key("status")),
    ("Assignee", _key("assignee_name")),
    ("RFO", _key("rfo_reason")),
    ("First response", _key("first_response_at")),
    ("Resolved", _key("resolved_at")),
    ("Closed", _key("closed_at")),
    ("Due", _key("due_at")),
    ("SLA minutes", _key("sla_minutes")),
    ("TAT minutes", _key("tat_minutes")),
    ("SLA state", _key("sla_state")),
    ("Resolution note", _key("resolution_note")),
)

TASK_COLUMNS: tuple[Column, ...] = (
    ("Created", _key("created_at")),
    ("Kind", _key("kind")),
    ("Title", _key("title")),
    ("Customer", _key("customer_name")),
    ("Address", _key("address")),
    ("Latitude", _key("latitude")),
    ("Longitude", _key("longitude")),
    ("Scheduled", _key("scheduled_at")),
    ("Status", _key("status")),
    ("Assignee", _key("assignee_name")),
    ("Started", _key("started_at")),
    ("Completed", _key("completed_at")),
    ("Completion note", _key("completion_note")),
    ("Rejected reason", _key("rejected_reason")),
)

LEAD_COLUMNS: tuple[Column, ...] = (
    ("Number", _key("number")),
    ("Created", _key("created_at")),
    ("Name", _key("name")),
    ("Phone", _key("phone")),
    ("Email", _key("email")),
    ("Address", _key("address")),
    ("City", _key("city")),
    ("Source", _key("source")),
    ("Status", _key("status")),
    ("Customer", _key("customer_name")),
    ("Assignee", _key("assignee_name")),
    ("Feasibility note", _key("feasibility_note")),
    ("Dropped reason", _key("dropped_reason")),
    ("Converted", _key("converted_at")),
)

UNIT_COLUMNS: tuple[Column, ...] = (
    ("Item", _key("item_name")),
    ("SKU", _key("sku")),
    ("Serial", _key("serial")),
    ("MAC", _key("mac")),
    ("State", _key("state")),
    ("Customer", _key("customer_name")),
    ("Subscriber id", _key("subscriber_id")),
    ("State changed", _key("state_changed_at")),
    ("Note", _key("note")),
)


def render_csv(columns: Iterable[Column], rows: Iterable[dict]) -> bytes:
    cols = tuple(columns)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([name for name, _ in cols])
    for row in rows:
        w.writerow([_cell(get(row)) for _, get in cols])
    return buf.getvalue().encode()


def csv_response(content: bytes, filename: str) -> Response:
    return Response(
        content=content,
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )


__all__ = [
    "LEAD_COLUMNS",
    "MAX_EXPORT_ROWS",
    "TASK_COLUMNS",
    "TICKET_COLUMNS",
    "UNIT_COLUMNS",
    "csv_response",
    "render_csv",
]
