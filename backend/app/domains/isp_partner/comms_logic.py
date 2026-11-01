"""COMMS-2 pure rules: the delivery lifecycle, the event catalogue, template
rendering, and the Meta webhook (signature + status parsing)."""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from typing import Any

#: queued -> sent -> delivered -> read, or failed. ``skipped`` (JAZE-4: no
#: template / no number) is kept as is.
LIFECYCLE = ("queued", "sent", "delivered", "read", "failed", "skipped")
_RANK = {"sent": 1, "delivered": 2, "read": 3}


def lifecycle(log_status: str, receipts: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """The status shown for one message. ``delivered`` and ``read`` come
    ONLY from a Meta receipt; the log row's own ``sent`` means "Meta accepted
    it", never "delivered"."""
    rs = list(receipts)
    failed = [r for r in rs if r["status"] == "failed"]
    if log_status == "failed" or failed:
        at = failed[-1]["occurred_at"] if failed else None
        err = failed[-1].get("error_title") if failed else None
        return {"status": "failed", "status_at": at, "receipt_error": err}
    if log_status in ("skipped", "queued"):
        return {"status": log_status, "status_at": None, "receipt_error": None}
    best = None
    for r in rs:
        if r["status"] in _RANK and (
            best is None or _RANK[r["status"]] > _RANK[best["status"]]
        ):
            best = r
    if best is None:
        return {"status": "sent", "status_at": None, "receipt_error": None}
    return {
        "status": best["status"],
        "status_at": best["occurred_at"],
        "receipt_error": None,
    }


# ---------------------------------------------------------------------------
# events
# ---------------------------------------------------------------------------

#: event -> JAZE-4 automation trigger it feeds (None: stored + previewed,
#: not sent automatically yet) and its variables IN ORDER. The order is the
#: order JAZE-4 passes WhatsApp body parameters {{1}}..{{n}}.
EVENTS: dict[str, dict[str, Any]] = {
    "pre_due": {
        "label": "Before the due date",
        "trigger": "pre_expiry",
        "vars": ["name", "expiry_date", "package"],
    },
    "overdue": {
        "label": "Overdue outstanding",
        "trigger": "overdue",
        "vars": ["name", "invoice_number", "balance", "pay_link"],
    },
    "unpaid_invoice": {
        "label": "Unpaid invoice with pay link",
        "trigger": "unpaid",
        "vars": ["name", "invoice_number", "balance", "pay_link"],
    },
    "payment_receipt": {
        "label": "Payment receipt",
        "trigger": "receipt",
        "vars": ["name", "receipt_number", "amount", "paid_on"],
    },
    "renewal": {
        "label": "Renewal confirmation",
        "trigger": "renewal",
        "vars": ["name", "invoice_number", "valid_until"],
    },
    "welcome": {
        "label": "Welcome",
        "trigger": "welcome",
        "vars": ["name", "username", "package"],
    },
    # INCIDENTS-1: sent from an incident's broadcast only.
    "outage": {
        "label": "Outage notice",
        "trigger": "outage",
        "vars": ["name", "area", "since"],
    },
    "restored": {
        "label": "Service restored",
        "trigger": "restored",
        "vars": ["name", "area", "restored_at"],
    },
}

SAMPLE: dict[str, str] = {
    "name": "Customer name",
    "expiry_date": "05-Nov-2026",
    "package": "50 Mbps · 30 days",
    "invoice_number": "INV/26-27/0042",
    "balance": "₹ 708.00",
    "amount": "₹ 708.00",
    "receipt_number": "RCT/26-27/0017",
    "paid_on": "01-Nov-2026",
    "valid_until": "01-Dec-2026",
    "username": "user123",
    "area": "Zone Sector 12",
    "since": "01 Nov 2026, 14:05",
    "restored_at": "01 Nov 2026, 16:40",
}

_PLACEHOLDER = re.compile(r"\{\{\s*([a-z_]+)\s*\}\}")


def unknown_placeholders(text: str | None, event: str) -> list[str]:
    allowed = set(EVENTS[event]["vars"])
    return sorted({m for m in _PLACEHOLDER.findall(text or "") if m not in allowed})


def render(text: str | None, values: Mapping[str, str]) -> str:
    return _PLACEHOLDER.sub(
        lambda m: str(values.get(m.group(1), m.group(0))), text or ""
    )


def sample_values(event: str, pay_link: str) -> dict[str, str]:
    out = {k: SAMPLE.get(k, k) for k in EVENTS[event]["vars"]}
    if "pay_link" in out:
        out["pay_link"] = pay_link
    return out


def find_approved(
    templates: Iterable[Mapping[str, Any]], name: str, language: str
) -> tuple[str | None, int | None]:
    """(status, body parameter count) of ``name``/``language`` in the WABA's
    template list, or (None, None) when it is not there."""
    for t in templates:
        if t.get("name") == name and (t.get("language") or "") == language:
            body = next(
                (c for c in (t.get("components") or []) if c.get("type") == "BODY"), {}
            )
            n = len(set(re.findall(r"\{\{\s*(\w+)\s*\}\}", body.get("text") or "")))
            return str(t.get("status") or "").upper() or None, n
    return None, None


# ---------------------------------------------------------------------------
# Meta webhook
# ---------------------------------------------------------------------------


def signature_ok(app_secret: str, raw_body: bytes, header: str | None) -> bool:
    """``X-Hub-Signature-256: sha256=<hex HMAC of the raw body>``."""
    if not app_secret or not header or not header.startswith("sha256="):
        return False
    want = hmac.new(app_secret.encode(), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, header.split("=", 1)[1].strip())


def parse_statuses(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Status updates from a WhatsApp Cloud API webhook body. Messages and
    anything else are ignored (no inbound handling in this lane)."""
    out = []
    for entry in payload.get("entry") or []:
        for change in entry.get("changes") or []:
            value = change.get("value") or {}
            for s in value.get("statuses") or []:
                status = str(s.get("status") or "").lower()
                mid = s.get("id")
                if status not in ("sent", "delivered", "read", "failed") or not mid:
                    continue
                try:
                    at = datetime.fromtimestamp(int(s.get("timestamp")), tz=UTC)
                except (TypeError, ValueError):
                    at = datetime.now(UTC)
                err = (s.get("errors") or [{}])[0]
                out.append(
                    {
                        "provider_message_id": str(mid)[:128],
                        "status": status,
                        "occurred_at": at,
                        "error_code": str(err["code"])[:32]
                        if err.get("code")
                        else None,
                        "error_title": (
                            str(err.get("title") or err.get("message"))[:300]
                            if (err.get("title") or err.get("message"))
                            else None
                        ),
                    }
                )
    return out


__all__ = [
    "EVENTS",
    "LIFECYCLE",
    "SAMPLE",
    "find_approved",
    "lifecycle",
    "parse_statuses",
    "render",
    "sample_values",
    "signature_ok",
    "unknown_placeholders",
]
