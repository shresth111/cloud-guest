"""Customer NetLogs: one organization's device log lines, a summary, and a
CSV export.

Tenant rules, all enforced here and not trusted to the route:

* The organization is the one ``RequireOrganization`` resolved; there is no
  organization parameter. It is a mandatory filter on every query
  (``repository.CustomerFilters``), which also excludes unattributed lines.
* ``location_id`` / ``router_id`` filters are loaded and must belong to
  that organization -- a foreign or unknown id is the same 404.
* The caller's ``network_logs.read`` location confinement
  (``customer_scope``) narrows every query; naming a location (or a router
  at a location) outside it is 403.

Never shown to a customer: the router's tunnel address (``source_ip``), the
``wyfy-`` tag and the attribution verdict -- tunnel internals are Master
only.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import re
import uuid
from collections import defaultdict
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager
from datetime import UTC, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from app.core.config import Settings

from .classifier import summary_for
from .constants import (
    CUSTOMER_EXPORT_CHUNK,
    CUSTOMER_EXPORT_MAX_ROWS,
    CUSTOMER_MAX_QUERY_WINDOW_DAYS,
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    SEVERITY_NAMES,
    SUMMARY_TOP_ROUTERS,
    LogCategory,
    LogStatus,
)
from .customer_scope import LogsConfinement
from .exceptions import (
    DeviceLogsDisabledError,
    NetLogsBadFilterError,
    NetLogsLocationForbiddenError,
    NetLogsLocationNotFoundError,
    NetLogsRouterNotFoundError,
)
from .repository import CustomerFilters, CustomerLogsRepository
from .service import decode_cursor, encode_cursor

DEFAULT_TIMEZONE = "Asia/Kolkata"
_SEVERITY_BY_NAME = {name: number for number, name in SEVERITY_NAMES.items()}
_CATEGORIES = [c.value for c in LogCategory]
_STATUSES = [s.value for s in LogStatus]

CSV_COLUMNS = (
    "received_at",
    "device_time",
    "location",
    "router",
    "host",
    "category",
    "protocol",
    "src_ip",
    "dst_ip",
    "status",
    "severity",
    "device_mac",
    "summary",
    "message",
)

RepositoryOpener = Callable[[], AbstractAsyncContextManager[CustomerLogsRepository]]


def _id(value: uuid.UUID | None) -> str | None:
    return str(value) if value is not None else None


def _csv_safe(value: Any) -> str:
    """No spreadsheet formula injection: a cell starting with = + - @ (or a
    tab/CR) is prefixed with a quote."""
    text = "" if value is None else str(value)
    if text and text[0] in "=+-@\t\r":
        return "'" + text
    return text


# Platform plumbing never reaches a customer (owner rule: no WireGuard/tunnel
# internals on the customer dashboard). Router tunnel addresses (10.20.0.0/24)
# and the platform's VPC (172.31.0.0/16) are replaced, and so are WireGuard
# interface names, wherever they appear in a log row.
_INTERNAL_NETS = (
    ipaddress.ip_network("10.20.0.0/24"),
    ipaddress.ip_network("172.31.0.0/16"),
)
_IPV4_IN_TEXT = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_WG_IN_TEXT = re.compile(r"\b(?:wg[\w-]*|wireguard[\w-]*)\b", re.IGNORECASE)
INTERNAL_PLACEHOLDER = "[platform]"


def _is_internal(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _INTERNAL_NETS)


def redact_internal(text: str | None) -> str | None:
    """Hide tunnel/VPC addresses and WireGuard interface names in free text."""
    if not text:
        return text
    text = _IPV4_IN_TEXT.sub(
        lambda m: INTERNAL_PLACEHOLDER if _is_internal(m.group(0)) else m.group(0),
        text,
    )
    return _WG_IN_TEXT.sub(INTERNAL_PLACEHOLDER, text)


def _ip_for_customer(ip: str | None) -> str | None:
    return INTERNAL_PLACEHOLDER if ip and _is_internal(ip) else ip


def event_view(row: dict[str, Any]) -> dict[str, Any]:
    e = row["event"]
    category = e.category or LogCategory.OTHER.value
    return {
        "id": e.id,
        "received_at": e.received_at,
        "device_time": e.device_time,
        "location_id": _id(e.location_id),
        "location_name": row.get("location_name"),
        "router_id": _id(e.router_id),
        "router_name": row.get("router_name"),
        "hostname": redact_internal(e.hostname),
        "source": e.source,
        "category": category,
        "protocol": e.protocol,
        "src_ip": _ip_for_customer(e.src_ip),
        "dst_ip": _ip_for_customer(e.dst_ip),
        "status": e.status,
        "device_mac": e.device_mac,
        "severity": e.severity,
        "severity_name": SEVERITY_NAMES.get(e.severity)
        if e.severity is not None
        else None,
        "summary": summary_for(category, e.status),
        "message": redact_internal(e.message),
    }


def _parse_list(
    values: list[str] | None, *, field: str, allowed: list[str] | None
) -> tuple[str, ...]:
    """Repeatable or comma-separated query values, lower-cased, validated."""
    out: list[str] = []
    for raw in values or []:
        for part in raw.split(","):
            item = part.strip().lower()
            if not item:
                continue
            if allowed is not None and item not in allowed:
                raise NetLogsBadFilterError(field, item, allowed)
            if item not in out:
                out.append(item)
    return tuple(out)


class NetLogsCustomerService:
    def __init__(
        self,
        repository: CustomerLogsRepository,
        settings: Settings,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.repository = repository
        self.settings = settings
        self._clock = clock or (lambda: datetime.now(UTC))

    @property
    def enabled(self) -> bool:
        return bool(self.settings.device_logs_enabled)

    # -- filters ---------------------------------------------------------
    async def _allowed_locations(
        self, organization_id: uuid.UUID, confinement: LogsConfinement
    ) -> tuple[uuid.UUID, ...] | None:
        if confinement.nothing:
            return ()
        if confinement.allowed is not None:
            return tuple(sorted(confinement.allowed, key=str))
        if confinement.denied:
            every = await self.repository.organization_location_ids(organization_id)
            return tuple(
                sorted((x for x in every if x not in confinement.denied), key=str)
            )
        return None

    async def build_filters(
        self,
        *,
        organization_id: uuid.UUID,
        confinement: LogsConfinement,
        since: datetime | None = None,
        until: datetime | None = None,
        location_id: uuid.UUID | None = None,
        router_id: uuid.UUID | None = None,
        severity: list[str] | None = None,
        max_severity: int | None = None,
        category: list[str] | None = None,
        protocol: list[str] | None = None,
        status: list[str] | None = None,
        q: str | None = None,
        cursor: str | None = None,
        default_window: timedelta = timedelta(hours=24),
    ) -> CustomerFilters:
        now = self._clock()
        until = until or now
        if until.tzinfo is None:
            until = until.replace(tzinfo=UTC)
        since = since or (until - default_window)
        if since.tzinfo is None:
            since = since.replace(tzinfo=UTC)
        if since > until:
            since, until = until, since
        if until - since > timedelta(days=CUSTOMER_MAX_QUERY_WINDOW_DAYS):
            since = until - timedelta(days=CUSTOMER_MAX_QUERY_WINDOW_DAYS)

        allowed = await self._allowed_locations(organization_id, confinement)

        if location_id is not None:
            owner = await self.repository.location_organization(location_id)
            if owner != organization_id:
                raise NetLogsLocationNotFoundError(location_id)
            if allowed is not None and location_id not in allowed:
                raise NetLogsLocationForbiddenError()
        if router_id is not None:
            found = await self.repository.router_owner(router_id)
            if found is None or found[0] != organization_id:
                raise NetLogsRouterNotFoundError(router_id)
            if allowed is not None and found[1] not in allowed:
                raise NetLogsLocationForbiddenError()

        severities: list[int] = []
        for name in _parse_list(
            severity, field="severity", allowed=list(_SEVERITY_BY_NAME)
        ):
            severities.append(_SEVERITY_BY_NAME[name])
        return CustomerFilters(
            organization_id=organization_id,
            since=since,
            until=until,
            allowed_location_ids=allowed,
            location_id=location_id,
            router_id=router_id,
            severities=tuple(severities),
            max_severity=max_severity,
            categories=_parse_list(category, field="category", allowed=_CATEGORIES),
            protocols=tuple(
                p.upper()[:16]
                for p in _parse_list(protocol, field="protocol", allowed=None)
            ),
            statuses=_parse_list(status, field="status", allowed=_STATUSES),
            text=(q or "").strip() or None,
            cursor=decode_cursor(cursor) if cursor else None,
        )

    # -- list ------------------------------------------------------------
    async def list_events(
        self, filters: CustomerFilters, *, limit: int | None
    ) -> dict[str, Any]:
        size = max(1, min(limit or DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE))
        base = {"since": filters.since, "until": filters.until}
        if not self.enabled:
            return {"feature_enabled": False, "items": [], "next_cursor": None, **base}
        rows = await self.repository.list_events(filters, limit=size + 1)
        has_more = len(rows) > size
        rows = rows[:size]
        next_cursor = None
        if has_more and rows:
            last = rows[-1]["event"]
            next_cursor = encode_cursor(last.received_at, last.id)
        return {
            "feature_enabled": True,
            "items": [event_view(r) for r in rows],
            "next_cursor": next_cursor,
            **base,
        }

    # -- summary ---------------------------------------------------------
    async def summary(
        self, filters: CustomerFilters, *, tz: str | None = None
    ) -> dict[str, Any]:
        zone = tz or DEFAULT_TIMEZONE
        try:
            ZoneInfo(zone)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise NetLogsBadFilterError("tz", zone, [DEFAULT_TIMEZONE, "UTC"]) from exc
        empty_categories = dict.fromkeys(_CATEGORIES, 0)
        result: dict[str, Any] = {
            "feature_enabled": self.enabled,
            "since": filters.since,
            "until": filters.until,
            "timezone": zone,
            "totals": {"events": 0, "errors": 0, "warnings": 0},
            "by_day": [],
            "by_category": dict(empty_categories),
            "by_severity": {**dict.fromkeys(SEVERITY_NAMES.values(), 0), "unknown": 0},
            "top_routers": [],
        }
        if not self.enabled:
            return result
        days: dict[str, dict[str, Any]] = defaultdict(
            lambda: {
                "total": 0,
                "errors": 0,
                "warnings": 0,
                "by_category": dict(empty_categories),
            }
        )
        for day, category, severity, count in await self.repository.summary_buckets(
            filters, tz=zone
        ):
            key = day.isoformat() if hasattr(day, "isoformat") else str(day)
            bucket = days[key]
            bucket["total"] += count
            cat = category if category in empty_categories else "other"
            bucket["by_category"][cat] += count
            result["by_category"][cat] += count
            result["totals"]["events"] += count
            sev_name = (
                SEVERITY_NAMES.get(severity, "unknown")
                if severity is not None
                else "unknown"
            )
            result["by_severity"][sev_name] += count
            if severity is not None and severity <= 3:
                bucket["errors"] += count
                result["totals"]["errors"] += count
            elif severity == 4:
                bucket["warnings"] += count
                result["totals"]["warnings"] += count
        result["by_day"] = [{"day": k, **days[k]} for k in sorted(days)]
        result["top_routers"] = [
            {
                "router_id": _id(router_id),
                "router_name": name,
                "location_id": _id(location_id),
                "location_name": location_name,
                "total": int(total),
                "errors": int(errors),
                "warnings": int(warnings),
            }
            for (
                router_id,
                name,
                location_id,
                location_name,
                total,
                errors,
                warnings,
            ) in await self.repository.top_routers(filters, limit=SUMMARY_TOP_ROUTERS)
        ]
        return result

    # -- export ----------------------------------------------------------
    def require_enabled(self) -> None:
        if not self.enabled:
            raise DeviceLogsDisabledError()

    @staticmethod
    async def export_csv(
        filters: CustomerFilters,
        open_repository: RepositoryOpener,
        *,
        max_rows: int = CUSTOMER_EXPORT_MAX_ROWS,
        chunk: int = CUSTOMER_EXPORT_CHUNK,
    ) -> AsyncIterator[str]:
        """CSV lines, newest first, keyset-paged on a session of its own (the
        request's session is closed before a streamed body is sent). Filters
        were validated on the request session already."""
        buffer = io.StringIO()
        writer = csv.writer(buffer)

        def line(values: list[Any]) -> str:
            buffer.seek(0)
            buffer.truncate()
            writer.writerow([_csv_safe(v) for v in values])
            return buffer.getvalue()

        yield line(list(CSV_COLUMNS))
        written = 0
        current = filters
        async with open_repository() as repository:
            while written < max_rows:
                size = min(chunk, max_rows - written)
                rows = await repository.list_events(current, limit=size)
                for row in rows:
                    v = event_view(row)
                    yield line(
                        [
                            v["received_at"].isoformat(),
                            v["device_time"].isoformat() if v["device_time"] else "",
                            v["location_name"],
                            v["router_name"],
                            v["hostname"],
                            v["category"],
                            v["protocol"],
                            v["src_ip"],
                            v["dst_ip"],
                            v["status"],
                            v["severity_name"],
                            v["device_mac"],
                            v["summary"],
                            v["message"],
                        ]
                    )
                written += len(rows)
                if len(rows) < size:
                    return
                last = rows[-1]["event"]
                current = _with_cursor(current, (last.received_at, last.id))
            # Hit the cap with more rows possibly remaining: say so.
            more = await repository.list_events(current, limit=1)
            if more:
                yield line(
                    [f"# truncated at {max_rows} rows; narrow the date range"]
                    + [""] * (len(CSV_COLUMNS) - 1)
                )


def _with_cursor(
    filters: CustomerFilters, cursor: tuple[datetime, int]
) -> CustomerFilters:
    from dataclasses import replace

    return replace(filters, cursor=cursor)
