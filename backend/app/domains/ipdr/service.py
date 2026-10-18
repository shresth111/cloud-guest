"""IPDR for one organization: the masked Connections list and the unmasked
CSV export. Tenant rules, enforced here and not trusted to the route:

* The organization is the one ``RequireOrganization`` resolved; there is no
  organization parameter, and it is a filter on every index read. A
  ``location_id``/``router_id`` of another organization is 404 -- the same
  answer as "does not exist".
* Rows come from archived day files of that organization's locations, or are
  built live from that organization's locations' flow records.
* Every list page and every export is audited by the caller of
  ``audit`` (the route), and an export's row is committed before a byte is
  streamed.
"""

from __future__ import annotations

import base64
import binascii
import json
import time
import uuid
from collections import OrderedDict
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, date, datetime, timedelta
from typing import Any

from app.core.config import Settings

from .archive import ArchiveReader, IpdrArchiveError
from .builder import IpdrBuilder, ist_day, ist_day_bounds, subject_digest
from .constants import (
    COVERAGE_ARCHIVED,
    COVERAGE_LIVE,
    COVERAGE_MISSING,
    DEFAULT_LIST_WINDOW,
    DEFAULT_PAGE_SIZE,
    LIVE_CACHE_ENTRIES,
    LIVE_CACHE_SECONDS,
    MAX_DAYS_PER_PAGE,
    MAX_PAGE_SIZE,
    MAX_RANGE_DAYS,
    SUBJECT_IP,
    SUBJECT_MAC,
    SUBJECT_PHONE,
    SUBJECT_USER,
)
from .exceptions import (
    IpdrBadCursorError,
    IpdrBadFilterError,
    IpdrLocationNotFoundError,
    IpdrRangeTooLongError,
    IpdrRouterNotFoundError,
)
from .formatting import (
    list_item,
    mask_identifier,
    mask_phone,
    normalize_ip,
    normalize_mac,
    phone_key,
)
from .join import sort_key
from .repository import DayFileRow, IpdrRepository


@dataclass(frozen=True)
class IpdrCursor:
    day: date
    ts: str | None = None
    key: str | None = None


def encode_cursor(cursor: IpdrCursor) -> str:
    raw = json.dumps(
        {"d": cursor.day.isoformat(), "t": cursor.ts, "k": cursor.key},
        separators=(",", ":"),
    ).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(text: str) -> IpdrCursor:
    try:
        padded = text + "=" * (-len(text) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded))
        return IpdrCursor(date.fromisoformat(data["d"]), data.get("t"), data.get("k"))
    except (ValueError, KeyError, TypeError, binascii.Error) as exc:
        raise IpdrBadCursorError() from exc


@dataclass(frozen=True)
class IpdrFilters:
    organization_id: uuid.UUID
    since: datetime
    until: datetime
    location_id: uuid.UUID | None = None
    router_id: uuid.UUID | None = None
    phone: str | None = None
    user_id: str | None = None
    mac: str | None = None
    ip: str | None = None
    dst_ip: str | None = None
    cursor: IpdrCursor | None = None
    #: (location, day) pairs whose day file contains every subject asked
    #: for; ``None`` = no subject filter.
    subject_days: frozenset[tuple[uuid.UUID, date]] | None = field(
        default=None, compare=False
    )

    def audit_view(self) -> dict[str, Any]:
        """The filters as written to the audit row: phone/user masked."""
        return {
            "location_id": str(self.location_id) if self.location_id else None,
            "router_id": str(self.router_id) if self.router_id else None,
            "phone": mask_phone(self.phone) if self.phone else None,
            "user_id": mask_identifier(self.user_id) if self.user_id else None,
            "mac": self.mac,
            "ip": self.ip,
            "dst_ip": self.dst_ip,
        }


def record_matches(record: dict[str, Any], f: IpdrFilters) -> bool:
    if f.router_id is not None and record.get("router_id") != str(f.router_id):
        return False
    if f.phone is not None and phone_key(record.get("phone")) != f.phone:
        return False
    if f.user_id is not None:
        if not record.get("user_known"):
            return False
        if (record.get("user_id") or "").strip().lower() != f.user_id:
            return False
    if f.mac is not None and record.get("mac") != f.mac:
        return False
    if f.ip is not None and f.ip not in (record.get("src_ip"), record.get("nat_ip")):
        return False
    if f.dst_ip is not None and record.get("dst_ip") != f.dst_ip:
        return False
    return (
        f.since.isoformat(timespec="microseconds")
        <= record["ts"]
        < (f.until.isoformat(timespec="microseconds"))
    )


class _LiveCache:
    """Process-wide, short: a live day changes at most every 5-minute window."""

    def __init__(self, ttl: float = LIVE_CACHE_SECONDS) -> None:
        self.ttl = ttl
        self._items: OrderedDict[tuple[Any, ...], tuple[float, Any]] = OrderedDict()

    def get(self, key: tuple[Any, ...]) -> Any:
        hit = self._items.get(key)
        if hit is None or hit[0] < time.monotonic():
            self._items.pop(key, None)
            return None
        return hit[1]

    def put(self, key: tuple[Any, ...], value: Any) -> None:
        self._items[key] = (time.monotonic() + self.ttl, value)
        self._items.move_to_end(key)
        while len(self._items) > LIVE_CACHE_ENTRIES:
            self._items.popitem(last=False)


LIVE_CACHE = _LiveCache()


def _aware(moment: datetime) -> datetime:
    """Naive = UTC; always returned in UTC (records compare as UTC text)."""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC)


class IpdrService:
    def __init__(
        self,
        repository: IpdrRepository,
        settings: Settings,
        builder: IpdrBuilder,
        reader: ArchiveReader,
        *,
        clock: Callable[[], datetime] | None = None,
        live_cache: _LiveCache | None = None,
    ) -> None:
        self.repository = repository
        self.settings = settings
        self.builder = builder
        self.reader = reader
        self._clock = clock or (lambda: datetime.now(UTC))
        self._cache = live_cache if live_cache is not None else LIVE_CACHE

    # -- filters ---------------------------------------------------------
    async def build_filters(
        self,
        *,
        organization_id: uuid.UUID,
        since: datetime | None = None,
        until: datetime | None = None,
        location_id: uuid.UUID | None = None,
        router_id: uuid.UUID | None = None,
        phone: str | None = None,
        user_id: str | None = None,
        mac: str | None = None,
        ip: str | None = None,
        dst_ip: str | None = None,
        cursor: str | None = None,
    ) -> IpdrFilters:
        now = _aware(self._clock())
        until = _aware(until) if until else now
        since = _aware(since) if since else until - DEFAULT_LIST_WINDOW
        if since >= until:
            raise IpdrBadFilterError("since", "since must be before until")
        if until - since > timedelta(days=MAX_RANGE_DAYS):
            raise IpdrRangeTooLongError(MAX_RANGE_DAYS)
        if location_id is not None:
            owner = await self.repository.location_organization(location_id)
            if owner != organization_id:
                raise IpdrLocationNotFoundError(location_id)
        if router_id is not None:
            found = await self.repository.router_owner(router_id)
            if found is None or found[0] != organization_id:
                raise IpdrRouterNotFoundError(router_id)
            if location_id is not None and found[1] != location_id:
                raise IpdrRouterNotFoundError(router_id)
        filters = IpdrFilters(
            organization_id=organization_id,
            since=since,
            until=until,
            location_id=location_id,
            router_id=router_id,
            phone=_parsed(phone, phone_key, "phone"),
            user_id=_parsed(user_id, lambda v: v.strip().lower() or None, "user_id"),
            mac=_parsed(mac, normalize_mac, "mac"),
            ip=_parsed(ip, normalize_ip, "ip"),
            dst_ip=_parsed(dst_ip, normalize_ip, "dst_ip"),
            cursor=decode_cursor(cursor) if cursor else None,
        )
        return await self._with_subject_days(filters)

    async def _with_subject_days(self, f: IpdrFilters) -> IpdrFilters:
        wanted = [
            (SUBJECT_PHONE, f.phone),
            (SUBJECT_USER, f.user_id),
            (SUBJECT_MAC, f.mac),
            (SUBJECT_IP, f.ip),
        ]
        first, last = self._days(f)[-1], self._days(f)[0]
        allowed: set[tuple[uuid.UUID, date]] | None = None
        for kind, value in wanted:
            if value is None:
                continue
            digest = subject_digest(kind, value)
            if digest is None:
                continue
            days = await self.repository.days_with_subject(
                f.organization_id, first, last, kind, digest
            )
            allowed = days if allowed is None else allowed & days
        if allowed is None:
            return f
        return replace(f, subject_days=frozenset(allowed))

    @staticmethod
    def _days(f: IpdrFilters) -> list[date]:
        """IST days of the range, newest first."""
        last = ist_day(f.until - timedelta(microseconds=1))
        first = ist_day(f.since)
        return [last - timedelta(days=i) for i in range((last - first).days + 1)]

    # -- one day -----------------------------------------------------------
    def _live_ok(self, day: date) -> bool:
        retention = int(self.settings.traffic_flow_record_retention_days)
        start, _ = ist_day_bounds(day)
        return start >= self._clock() - timedelta(days=retention)

    async def _scope_locations(self, f: IpdrFilters) -> tuple[uuid.UUID, ...]:
        if f.location_id is not None:
            return (f.location_id,)
        return tuple(await self.repository.organization_location_ids(f.organization_id))

    async def day_records(
        self, f: IpdrFilters, day: date, locations: tuple[uuid.UUID, ...]
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """One IST day's matching records of the scope, newest first, and
        that day's coverage."""
        files: dict[uuid.UUID, DayFileRow] = {
            row.location_id: row
            for row in await self.repository.day_files(
                f.organization_id, locations, day, day
            )
        }
        records: list[dict[str, Any]] = []
        coverage = {
            "day": day.isoformat(),
            "archived": 0,
            "live": 0,
            "records_incomplete": False,
            "unreadable": 0,
        }
        for location_id, row in sorted(files.items(), key=lambda p: str(p[0])):
            coverage["archived"] += 1
            coverage["records_incomplete"] |= row.records_incomplete
            if f.subject_days is not None and (location_id, day) not in (
                f.subject_days
            ):
                continue
            try:
                rows = await self.reader.read(row.store, row.object_key, row.sha256)
            except IpdrArchiveError:
                coverage["unreadable"] += 1
                continue
            records.extend(rows)
        if self._live_ok(day):
            start, end = ist_day_bounds(day)
            end = min(end, self._clock())
            if start < end:
                flowing = {
                    loc: org
                    for loc, org in await self.repository.locations_with_flows(
                        start, end
                    )
                    if org == f.organization_id
                }
                for location_id in locations:
                    if location_id in files or location_id not in flowing:
                        continue
                    coverage["live"] += 1
                    records.extend(
                        await self._live(
                            location_id, f.organization_id, day, start, end
                        )
                    )
        if coverage["live"]:
            coverage["status"] = COVERAGE_LIVE
        elif coverage["archived"]:
            coverage["status"] = COVERAGE_ARCHIVED
        else:
            coverage["status"] = (
                COVERAGE_LIVE if self._live_ok(day) else COVERAGE_MISSING
            )
        matched = [r for r in records if record_matches(r, f)]
        matched.sort(key=sort_key, reverse=True)
        return matched, coverage

    async def _live(
        self,
        location_id: uuid.UUID,
        organization_id: uuid.UUID,
        day: date,
        start: datetime,
        end: datetime,
    ) -> list[dict[str, Any]]:
        key = (location_id, day)
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        records = await self.builder.build(location_id, organization_id, start, end)
        self._cache.put(key, records)
        return records

    # -- list --------------------------------------------------------------
    async def list_page(
        self, f: IpdrFilters, *, limit: int | None = None
    ) -> dict[str, Any]:
        size = max(1, min(limit or DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE))
        locations = await self._scope_locations(f)
        days = self._days(f)
        if f.cursor is not None:
            days = [d for d in days if d <= f.cursor.day]
        items: list[dict[str, Any]] = []
        coverage: list[dict[str, Any]] = []
        next_cursor: IpdrCursor | None = None
        for index, day in enumerate(days):
            if index >= MAX_DAYS_PER_PAGE:
                next_cursor = IpdrCursor(day)
                break
            records, day_coverage = await self.day_records(f, day, locations)
            coverage.append(day_coverage)
            if f.cursor is not None and f.cursor.day == day and f.cursor.ts:
                mark = (f.cursor.ts, f.cursor.key or "")
                records = [r for r in records if sort_key(r) < mark]
            room = size - len(items)
            items.extend(records[:room])
            if len(records) > room:
                last = items[-1]
                next_cursor = IpdrCursor(day, last["ts"], last["rk"])
                break
            if len(items) >= size:
                following = days[index + 1 :]
                next_cursor = IpdrCursor(following[0]) if following else None
                break
        return {
            "since": f.since,
            "until": f.until,
            "items": [list_item(r) for r in items],
            "next_cursor": encode_cursor(next_cursor) if next_cursor else None,
            "coverage": coverage,
        }

    # -- export ------------------------------------------------------------
    async def iter_records(self, f: IpdrFilters) -> AsyncIterator[dict[str, Any]]:
        locations = await self._scope_locations(f)
        for day in self._days(f):
            records, _ = await self.day_records(f, day, locations)
            for record in records:
                yield record


def _parsed(
    value: str | None, normalize: Callable[[str], str | None], field_name: str
) -> str | None:
    if value is None or not value.strip():
        return None
    normal = normalize(value)
    if normal is None:
        raise IpdrBadFilterError(field_name, f"Not a valid {field_name}: {value!r}")
    return normal
