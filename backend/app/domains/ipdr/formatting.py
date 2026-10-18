"""Pure rendering of one IPDR record: IST dates, online time, protocol,
masking, CSV cells. No I/O, no database.

A *record* is the dict the builder produces (``join.build_records``) and the
archive stores (NDJSON). Every view is rendered from it:

* ``csv_cells`` -- the 18 standard columns, unmasked (the download);
* ``list_item`` -- the on-screen row, phone and email **masked**.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Any

from .constants import (
    ALLOCATION_DYNAMIC,
    IST,
    TRANSLATION_NONE,
    UNKNOWN_USER,
)

_PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}
_PHONE = re.compile(r"^\+?[\d\s-]{10,16}$")


def parse_instant(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value))


def ist_minute(value: Any) -> str:
    """``DD-MM-YYYY HH:MM`` in Asia/Kolkata; blank for nothing."""
    moment = parse_instant(value)
    if moment is None:
        return ""
    return moment.astimezone(IST).strftime("%d-%m-%Y %H:%M")


def online_time(seconds: int | float | None) -> str:
    """``1d 9h 7m 1s``. Leading zero units are dropped (``7m 1s``,
    ``45s``); inner zeros are kept (``1d 0h 0m 5s``). Blank for unknown."""
    if seconds is None:
        return ""
    total = max(0, int(seconds))
    days, rest = divmod(total, 86_400)
    hours, rest = divmod(rest, 3_600)
    minutes, secs = divmod(rest, 60)
    parts = [(days, "d"), (hours, "h"), (minutes, "m"), (secs, "s")]
    while len(parts) > 1 and parts[0][0] == 0:
        parts.pop(0)
    return " ".join(f"{value}{unit}" for value, unit in parts)


def protocol_label(protocol: int | None) -> str:
    if protocol is None:
        return ""
    return _PROTOCOLS.get(int(protocol), str(int(protocol)))


def is_phone(value: str | None) -> bool:
    return bool(value) and bool(_PHONE.match(str(value).strip()))


def phone_digits(value: str | None) -> str:
    return re.sub(r"\D", "", value or "")


def phone_key(value: str | None) -> str | None:
    """The comparable form of a phone: its last 10 digits."""
    digits = phone_digits(value)
    return digits[-10:] if len(digits) >= 10 else None


def is_email(value: str | None) -> bool:
    return bool(value) and "@" in str(value)


def normalize_mac(value: str | None) -> str | None:
    """``AA:BB:CC:DD:EE:FF`` from any of the usual spellings."""
    if not value:
        return None
    hexes = re.sub(r"[^0-9A-Fa-f]", "", value).upper()
    if len(hexes) != 12:
        return None
    return ":".join(hexes[i : i + 2] for i in range(0, 12, 2))


def normalize_ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def mask_phone(value: str | None) -> str:
    """``98xxxxxx20``: first two and last two digits, the rest ``x``."""
    digits = phone_digits(value)
    if not digits:
        return ""
    if len(digits) <= 4:
        return "x" * len(digits)
    return digits[:2] + "x" * (len(digits) - 4) + digits[-2:]


def mask_email(value: str | None) -> str:
    """``a***@example.com``."""
    if not value or "@" not in value:
        return ""
    local, _, domain = value.partition("@")
    return (local[:1] or "") + "***@" + domain


def mask_identifier(value: str | None) -> str:
    """A user id that IS a phone or an email gets the same mask."""
    if not value:
        return ""
    if is_email(value):
        return mask_email(value)
    if is_phone(value):
        return mask_phone(value)
    return value


def csv_safe(value: Any) -> str:
    """No spreadsheet formula injection (same rule as NetLogs)."""
    text = "" if value is None else str(value)
    if text and text[0] in "=+-@\t\r":
        return "'" + text
    return text


def _port(value: Any) -> str:
    return "" if value is None else str(int(value))


def csv_cells(record: dict[str, Any], *, provenance: bool = False) -> list[str]:
    """The 18 standard IPDR cells, unmasked, in ``IPDR_COLUMNS`` order."""
    known = bool(record.get("user_known"))
    cells = [
        ist_minute(record.get("ts")),
        record.get("name") or "",
        record.get("phone") or "",
        record.get("alt_phone") or "",
        record.get("email") or "",
        record.get("user_id") or UNKNOWN_USER,
        record.get("src_ip") or "",
        _port(record.get("src_port")),
        record.get("nat_ip") or "",
        _port(record.get("nat_port")),
        record.get("allocation") or ALLOCATION_DYNAMIC,
        record.get("dst_ip") or "",
        _port(record.get("dst_port")),
        protocol_label(record.get("protocol")),
        ist_minute(record.get("alloc_start")) if known else "",
        ist_minute(record.get("alloc_end")) if known else "",
        online_time(record.get("online_seconds")) if known else "",
        record.get("mac") or "",
    ]
    if provenance:
        cells += [
            record.get("nat_source") or TRANSLATION_NONE,
            "matched" if known else "no session",
        ]
    return [csv_safe(c) for c in cells]


def list_item(record: dict[str, Any]) -> dict[str, Any]:
    """The on-screen row: the same columns as the CSV, phone/email masked,
    plus the raw instants and the provenance flags."""
    cells = csv_cells(record)
    known = bool(record.get("user_known"))
    return {
        "time_stamp_ist": cells[0],
        "name": record.get("name") or "",
        "contact_no": mask_phone(record.get("phone")),
        "alternate_contact_no": mask_phone(record.get("alt_phone")),
        "email": mask_email(record.get("email")),
        "user_id": (mask_identifier(record.get("user_id")) if known else UNKNOWN_USER),
        "source_ip": cells[6],
        "source_port": cells[7],
        "translated_ip": cells[8],
        "translated_port": cells[9],
        "allocation": cells[10],
        "destination_ip": cells[11],
        "destination_port": cells[12],
        "protocol": cells[13],
        "allocation_start_ist": cells[14],
        "allocation_end_ist": cells[15],
        "total_online_time": cells[16],
        "mac": cells[17],
        "ts": record.get("ts"),
        "location_id": record.get("location_id"),
        "router_id": record.get("router_id"),
        "translated_source": record.get("nat_source") or TRANSLATION_NONE,
        "ts_source": record.get("ts_source"),
        "user_known": known,
        "ports_merged": bool(record.get("ports_merged")),
    }
