"""JAZE-3 pure functions: no I/O, so every rule here is unit-tested directly.

* subscriber state classification for the dashboard counters (J4);
* NAT-feed freshness per router (J4 banner);
* CGNAT lookup matching and its evidence verdict (J5);
* ID-number masking, Aadhaar Verhoeff check (J6);
* TRAI PMR speed tiers and AGR split (J17).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

# ---------------------------------------------------------------------------
# J4: subscriber states
# ---------------------------------------------------------------------------

#: Counter keys, in display order.
COUNTER_KEYS: tuple[str, ...] = (
    "online",
    "active",
    "expiring_7d",
    "expired",
    "suspended",
    "frozen",
    "blocked",
    "churned",
    "new_7d",
    "scheduled_renewals",
    "total",
)

#: Lifecycle overlay states JAZE-1 may record for a subscriber. Absent =
#: derived from ``isp_subscribers.status`` + ``valid_until`` alone.
OVERLAY_SUSPENDED = "suspended"
OVERLAY_FROZEN = "frozen"
OVERLAY_BLOCKED = "blocked"
OVERLAYS = frozenset({OVERLAY_SUSPENDED, OVERLAY_FROZEN, OVERLAY_BLOCKED})


def subscriber_state(
    *,
    status: str,
    valid_until: datetime | None,
    now: datetime,
    overlay: str | None = None,
    churn_after: timedelta = timedelta(days=60),
) -> str:
    """One primary state per subscriber, so the tiles add up to ``total``:
    ``blocked`` > ``frozen`` > ``suspended`` > ``churned`` > ``expired`` >
    ``active``. ``isp_subscribers.status='disabled'`` is ``blocked`` (the
    ISP turned it off); an overlay from JAZE-1 wins over the derived state.
    """
    if overlay in OVERLAYS:
        return overlay
    if status == "disabled":
        return OVERLAY_BLOCKED
    lapsed = status == "expired" or (valid_until is not None and valid_until <= now)
    if lapsed:
        if valid_until is not None and now - valid_until > churn_after:
            return "churned"
        return "expired"
    return "active"


def count_states(
    rows: Iterable[Mapping[str, Any]],
    *,
    now: datetime,
    online_ids: set[Any],
    renewal_ids: set[Any],
    churn_after: timedelta,
) -> dict[str, int]:
    """``rows``: dicts with id, status, valid_until, created_at, overlay."""
    out = dict.fromkeys(COUNTER_KEYS, 0)
    week = now + timedelta(days=7)
    for row in rows:
        out["total"] += 1
        state = subscriber_state(
            status=row["status"],
            valid_until=row.get("valid_until"),
            now=now,
            overlay=row.get("overlay"),
            churn_after=churn_after,
        )
        out[state] += 1
        valid_until = row.get("valid_until")
        if state == "active" and valid_until is not None and valid_until <= week:
            out["expiring_7d"] += 1
        created = row.get("created_at")
        if created is not None and created >= now - timedelta(days=7):
            out["new_7d"] += 1
        if row["id"] in online_ids:
            out["online"] += 1
        if row["id"] in renewal_ids:
            out["scheduled_renewals"] += 1
    return out


# ---------------------------------------------------------------------------
# J4: NAT feed freshness
# ---------------------------------------------------------------------------

FEED_OK = "ok"
FEED_STALE = "stale"
FEED_NEVER = "never_received"
FEED_NOT_CONFIGURED = "not_configured"
FEED_ROUTER_OFFLINE = "router_offline"
#: States that raise the banner.
FEED_ALERTING = frozenset({FEED_STALE, FEED_NEVER, FEED_NOT_CONFIGURED})


def nat_feed_state(
    *,
    last_nat_at: datetime | None,
    export_configured: bool,
    router_online: bool,
    now: datetime,
    stale_after: timedelta,
) -> str:
    """Whether NAT translations from one router are reaching us.

    An offline router is reported as such and does not raise the banner on
    its own: its NAT feed stopping is a consequence, and the router-offline
    alert already covers it. Fresh data from an offline-marked router still
    counts as ``ok`` (the status poll may lag)."""
    if last_nat_at is not None and now - last_nat_at <= stale_after:
        return FEED_OK
    if not router_online:
        return FEED_ROUTER_OFFLINE
    if not export_configured:
        return FEED_NOT_CONFIGURED
    if last_nat_at is None:
        return FEED_NEVER
    return FEED_STALE


# ---------------------------------------------------------------------------
# J5: CGNAT lookup
# ---------------------------------------------------------------------------

#: Default and max +/- window around the instant the requester gave.
DEFAULT_TOLERANCE = timedelta(seconds=60)
MAX_TOLERANCE = timedelta(minutes=15)

VERDICT_UNIQUE = "unique_match"
VERDICT_MULTIPLE = "multiple_candidates"
VERDICT_NONE = "no_match"
VERDICT_NO_DATA = "no_nat_data_for_window"


def normalize_ip(value: str) -> str:
    return str(ipaddress.ip_address(value.strip()))


def _parse_ts(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value))


@dataclass(frozen=True)
class LookupQuery:
    public_ip: str
    public_port: int | None
    at: datetime
    tolerance: timedelta
    protocol: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None

    @property
    def since(self) -> datetime:
        return self.at - self.tolerance

    @property
    def until(self) -> datetime:
        return self.at + self.tolerance


def record_covers(record: Mapping[str, Any], q: LookupQuery) -> bool:
    """An IPDR record answers the query when its translated address (and
    port, if given) match and its connection interval overlaps the window.
    Records with an *ambiguous* or *derived* translation still match on
    address; their ``nat_source`` is reported so the reader can weigh them.
    """
    if record.get("nat_ip") != q.public_ip:
        return False
    if q.public_port is not None and record.get("nat_port") != q.public_port:
        return False
    if q.protocol is not None and record.get("protocol") not in (q.protocol, None):
        return False
    if q.dst_ip is not None and record.get("dst_ip") != q.dst_ip:
        return False
    if q.dst_port is not None and record.get("dst_port") != q.dst_port:
        return False
    start = _parse_ts(record.get("ts"))
    end = _parse_ts(record.get("ts_end")) or start
    if start is None:
        return False
    return start <= q.until and end >= q.since


def verdict(matches: list[Mapping[str, Any]], *, had_nat_data: bool) -> str:
    """Never guess: one subscriber across all matches is a unique match;
    several distinct identities are reported as candidates; nothing found
    with no NAT data in the window is an evidence gap, not a "no match"."""
    if not matches:
        return VERDICT_NONE if had_nat_data else VERDICT_NO_DATA
    identities = {
        (
            m.get("organization_id"),
            m.get("user_id") if m.get("user_known") else None,
            m.get("mac"),
            m.get("src_ip"),
        )
        for m in matches
    }
    users = {i[1] for i in identities}
    if len(users) == 1 and None not in users:
        return VERDICT_UNIQUE
    if len(identities) == 1:
        return VERDICT_UNIQUE
    return VERDICT_MULTIPLE


# ---------------------------------------------------------------------------
# J6: ID numbers
# ---------------------------------------------------------------------------

ID_TYPES = (
    "aadhaar",
    "voter_id",
    "passport",
    "pan",
    "driving_licence",
    "ration_card",
    "other",
)
DOCUMENT_KINDS = (
    "photo",
    "signature",
    "id_proof",
    "address_proof",
    "caf_signed",
    "install_report",
)
DOCUMENT_TYPES = {
    "image/jpeg",
    "image/png",
    "image/webp",
    "application/pdf",
}
MAX_DOCUMENT_BYTES = 5 * 1024 * 1024

_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)


def verhoeff_ok(digits: str) -> bool:
    check = 0
    for i, ch in enumerate(reversed(digits)):
        check = _VERHOEFF_D[check][_VERHOEFF_P[i % 8][int(ch)]]
    return check == 0


class IdNumberError(ValueError):
    pass


_PAN = re.compile(r"^[A-Z]{5}[0-9]{4}[A-Z]$")


def mask_id_number(id_type: str, raw: str | None) -> tuple[str | None, str | None]:
    """``(stored_value, last4)``. For Aadhaar the stored value is masked to
    the last four digits and the full number is discarded here, before it
    reaches any model. A 4-digit input is accepted for Aadhaar (the ISP may
    have only the masked copy). Other types are normalised and kept."""
    if raw is None or not raw.strip():
        return None, None
    value = re.sub(r"[\s-]", "", raw.strip()).upper()
    if id_type == "aadhaar":
        if re.fullmatch(r"\d{4}", value):
            return f"XXXX XXXX {value}", value
        if re.fullmatch(r"X{8}\d{4}", value):
            return f"XXXX XXXX {value[-4:]}", value[-4:]
        if not re.fullmatch(r"[2-9]\d{11}", value) or not verhoeff_ok(value):
            raise IdNumberError("Not a valid Aadhaar number")
        return f"XXXX XXXX {value[-4:]}", value[-4:]
    if id_type == "pan" and not _PAN.fullmatch(value):
        raise IdNumberError("PAN must look like ABCDE1234F")
    if len(value) > 40 or not re.fullmatch(r"[A-Z0-9/]+", value):
        raise IdNumberError("ID number may contain letters, digits and / only")
    return value, value[-4:]


def display_id_number(stored: str | None, *, unmasked: bool) -> str | None:
    """Aadhaar is already masked at rest. Other numbers show only their last
    four unless the caller may see them in full."""
    if stored is None or unmasked or stored.startswith("XXXX"):
        return stored
    return "X" * max(len(stored) - 4, 0) + stored[-4:]


# ---------------------------------------------------------------------------
# J17: TRAI PMR speed tiers + AGR
# ---------------------------------------------------------------------------

#: (label, lower Mbps inclusive, upper Mbps exclusive)
SPEED_TIERS: tuple[tuple[str, float, float | None], ...] = (
    ("< 2 Mbps", 0.0, 2.0),
    ("2 - 10 Mbps", 2.0, 10.0),
    ("10 - 50 Mbps", 10.0, 50.0),
    ("50 - 100 Mbps", 50.0, 100.0),
    ("> 100 Mbps", 100.0, None),
)
TIER_UNKNOWN = "Speed not set"


def speed_tier(download_kbps: int | None) -> str:
    if download_kbps is None or download_kbps <= 0:
        return TIER_UNKNOWN
    mbps = download_kbps / 1000
    for label, low, high in SPEED_TIERS:
        if mbps >= low and (high is None or mbps < high):
            return label
    return TIER_UNKNOWN


#: SAC codes under heading 9984 (telecommunications) count as licensed
#: revenue for AGR; everything else (installation 9954, equipment, other)
#: is shown separately. The ISP's accountant decides the final filing.
TELECOM_SAC_PREFIX = "9984"


def agr_split(lines: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    """Lines: dicts with ``sac_code``, ``taxable_paise`` and ``sign`` (+1
    for an invoice, -1 for a credit note). Paise, taxable value only (GST
    is not revenue)."""
    telecom = other = 0
    for line in lines:
        amount = int(line["taxable_paise"]) * int(line.get("sign", 1))
        if str(line.get("sac_code") or "").startswith(TELECOM_SAC_PREFIX):
            telecom += amount
        else:
            other += amount
    return {
        "telecom_taxable_paise": telecom,
        "other_taxable_paise": other,
        "gross_taxable_paise": telecom + other,
    }


def month_bounds(period: str) -> tuple[datetime, datetime]:
    """``YYYY-MM`` -> [first instant, first instant of next month) in UTC.
    TRAI periods are calendar months; IST vs UTC at the edges is documented
    in the report header (we report on the ISP's IST month)."""
    from zoneinfo import ZoneInfo

    m = re.fullmatch(r"(\d{4})-(\d{2})", period or "")
    if not m or not 1 <= int(m.group(2)) <= 12:
        raise ValueError("period must be YYYY-MM")
    year, month = int(m.group(1)), int(m.group(2))
    ist = ZoneInfo("Asia/Kolkata")
    start = datetime(year, month, 1, tzinfo=ist)
    end = datetime(year + (month == 12), month % 12 + 1, 1, tzinfo=ist)
    return start, end
