"""The public threat list the "known-bad destinations" finding matches
against. No I/O except reading the list files once.

## Which list, and why (terms read 2026-10-13)

**Spamhaus DROP** ("Don't Route Or Peer"), IPv4 and IPv6: net-blocks that
are "hijacked" or leased by professional spam or cyber-crime operations.

* Use in a commercial product is allowed. The DROP page
  (https://www.spamhaus.org/blocklists/do-not-route-or-peer/) says:
  "Spamhaus believes that due to the vital nature of the DROP list data, it
  should be available at no cost, regardless of size or business type, to
  protect internet users. We do ask, when used in a product, credit must be
  given to Spamhaus Project, and the date and (c) text should remain with
  the file and data."
* Redistribution is NOT granted. The terms
  (https://www.spamhaus.org/drop/terms/) say, 3.1: "Nothing in these Terms
  shall be construed as granting an assignment or licence of any
  intellectual property rights in the DROP Lists." So the files are **not in
  this repository** (it is public): ``scripts/fetch_threat_data.py``
  downloads them at image build into ``data/threat/``, byte for byte, with
  Spamhaus's own date and copyright line still inside them.
* Terms 3.2 forbid the Spamhaus name "in your marketing, promotional or any
  other commercial materials". ``CREDIT`` below is the in-product credit the
  DROP page asks for and nothing more. It must not be copied to the website.
* Terms 4.2: "If you do not keep this type of filter data up to date, you
  will encounter errors when allocations listed in an old version of the
  DROP lists get reassigned to new networks." So a list older than
  ``THREAT_LIST_MAX_AGE_DAYS`` is not matched against at all: the finding
  reads "could not be checked", never "clear".

Evaluated and not used:

* abuse.ch **Feodo Tracker**: allowed ("All datasets offered by Feodo
  Tracker can be used for both, commercial and non-commercial purpose
  without any limitations (CC0)"), but dormant: 5 addresses, "Last updated:
  2026-03-04", and the recommended list is empty. Seven-month-old addresses
  are a source of false matches, not of findings.
* abuse.ch **ThreatFox**: not allowed without a contract ("Use of the API by
  companies, networks, or individuals with commercial or for- profit needs
  may require a paid subscription").
* **FireHOL level1**: an aggregate with no licence of its own; one of its
  parts, DShield, is "some rights reserved ...
  creativecommons.org/licenses/by-nc-sa/2.5/" (non-commercial), and it
  contains bogon ranges that would flag ordinary carrier-grade NAT.

## What a match means

The venue exchanged traffic with an address inside a listed net-block. It
does not say which device did (nothing stores that), and it is not proof of
an infection. When the files are absent or unreadable the application runs
as before and ``ThreatList.available`` is false.
"""

from __future__ import annotations

import bisect
import ipaddress
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.core.logging import get_logger

logger = get_logger(__name__)

__all__ = [
    "CREDIT",
    "MANIFEST_FILENAME",
    "THREAT_LIST_FILENAMES",
    "THREAT_LIST_MAX_AGE_DAYS",
    "THREAT_LIST_NAME",
    "ThreatEntry",
    "ThreatList",
    "default_threat_data_dir",
    "get_threat_list",
]

THREAT_LIST_NAME = "Spamhaus DROP"

#: The files as Spamhaus publishes them (one JSON object per line, the last
#: line a ``{"type": "metadata", ...}`` record with the date and copyright).
THREAT_LIST_FILENAMES: tuple[str, ...] = ("drop_v4.json", "drop_v6.json")

#: A copy fetched longer ago than this is not matched against (terms 4.2,
#: module doc). The list is fetched at image build, so this is also "days
#: since the last deploy" until a scheduled refresh exists.
THREAT_LIST_MAX_AGE_DAYS = 14

#: Written beside the files by ``scripts/fetch_threat_data.py``; its
#: ``fetched_at`` is what the age is measured from. Spamhaus re-dates the
#: IPv6 file only when it changes, so a file's own date says how old its
#: content is, not how old our copy is.
MANIFEST_FILENAME = "SOURCE.json"

#: Returned with every findings response so no screen can forget the credit.
CREDIT: dict[str, str] = {
    "text": "Known-bad address list: Spamhaus DROP, The Spamhaus Project",
    "url": "https://www.spamhaus.org/blocklists/do-not-route-or-peer/",
    "terms_url": "https://www.spamhaus.org/drop/terms/",
}

_MAX_ENTRIES = 200_000


def default_threat_data_dir() -> Path:
    """``<backend>/data/threat`` -- ``/app/data/threat`` in the image."""
    return Path(__file__).resolve().parents[3] / "data" / "threat"


@dataclass(frozen=True, slots=True)
class ThreatEntry:
    """One listed net-block. ``reference`` is the list's own record id."""

    cidr: str
    reference: str | None


class _Ranges:
    """Listed net-blocks of one address family as sorted, non-overlapping
    integer ranges. DROP holds whole allocations, so overlaps are not
    expected; if two entries do overlap the wider one is kept."""

    def __init__(self) -> None:
        self._raw: list[tuple[int, int, ThreatEntry]] = []
        self._starts: list[int] = []
        self._rows: list[tuple[int, int, ThreatEntry]] = []

    def add(self, network: Any, entry: ThreatEntry) -> None:
        self._raw.append(
            (int(network.network_address), int(network.broadcast_address), entry)
        )

    def freeze(self) -> None:
        rows: list[tuple[int, int, ThreatEntry]] = []
        for first, last, entry in sorted(
            self._raw, key=lambda r: (r[0], -(r[1] - r[0]))
        ):
            if rows and first <= rows[-1][1]:
                continue  # inside (or overlapping) the wider block before it
            rows.append((first, last, entry))
        self._rows = rows
        self._starts = [row[0] for row in rows]

    def find(self, value: int) -> ThreatEntry | None:
        index = bisect.bisect_right(self._starts, value) - 1
        if index < 0:
            return None
        _first, last, entry = self._rows[index]
        return entry if value <= last else None

    def __len__(self) -> int:
        return len(self._rows)


class ThreatList:
    """Outside address -> the listed net-block it is in, or ``None``.

    Every file in ``THREAT_LIST_FILENAMES`` is needed. With any missing,
    unreadable, or without its dated metadata line, ``available`` is false
    and nothing matches: a half-loaded list would report "clear" for the
    half it does not have."""

    def __init__(self, data_dir: str | Path | None) -> None:
        self.data_dir = Path(data_dir) if data_dir else default_threat_data_dir()
        self._v4 = _Ranges()
        self._v6 = _Ranges()
        self.list_date: datetime | None = None
        self.fetched_at: datetime | None = None
        self.copyright: str | None = None
        self.unavailable_reason: str | None = None
        try:
            dates = [self._load(self.data_dir / name) for name in THREAT_LIST_FILENAMES]
            self._v4.freeze()
            self._v6.freeze()
            # The date shown is the list's own newest one.
            self.list_date = max(dates)
            self.fetched_at = self._read_fetched_at()
        except (OSError, ValueError) as exc:
            self._v4, self._v6 = _Ranges(), _Ranges()
            self.list_date, self.fetched_at, self.copyright = None, None, None
            self.unavailable_reason = f"{type(exc).__name__}: {exc}"
            logger.info(
                "traffic_flow_threat_list_unavailable",
                extra={"threat_data_dir": str(self.data_dir), "reason": str(exc)},
            )

    def _load(self, path: Path) -> datetime:
        published: datetime | None = None
        count = 0
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                if not isinstance(record, dict):
                    raise ValueError(f"{path.name}: a line is not an object")
                if record.get("type") == "metadata":
                    published = datetime.fromtimestamp(int(record["timestamp"]), tz=UTC)
                    self.copyright = str(record.get("copyright") or "") or None
                    continue
                network = ipaddress.ip_network(str(record["cidr"]), strict=False)
                entry = ThreatEntry(
                    cidr=str(network),
                    reference=str(record["sblid"]) if record.get("sblid") else None,
                )
                (self._v4 if network.version == 4 else self._v6).add(network, entry)
                count += 1
                if count > _MAX_ENTRIES:
                    raise ValueError(f"{path.name}: more than {_MAX_ENTRIES} entries")
        if published is None:
            raise ValueError(f"{path.name}: no dated metadata line")
        if count == 0:
            raise ValueError(f"{path.name}: no entries")
        return published

    def _read_fetched_at(self) -> datetime | None:
        """When our copy was fetched, or ``None`` when that is not recorded
        (the age is then measured from the list's own date)."""
        try:
            manifest = json.loads((self.data_dir / MANIFEST_FILENAME).read_text())
            moment = datetime.fromisoformat(str(manifest["fetched_at"]))
        except (OSError, ValueError, KeyError, TypeError):
            return None
        return moment if moment.tzinfo is not None else moment.replace(tzinfo=UTC)

    @property
    def available(self) -> bool:
        return self.list_date is not None

    @property
    def entries(self) -> int:
        return len(self._v4) + len(self._v6)

    def age_days(self, now: datetime) -> float | None:
        if self.list_date is None:
            return None
        return (now - (self.fetched_at or self.list_date)).total_seconds() / 86400

    def is_stale(self, now: datetime) -> bool:
        age = self.age_days(now)
        return age is not None and age > THREAT_LIST_MAX_AGE_DAYS

    def match(self, address: str) -> ThreatEntry | None:
        if not self.available:
            return None
        try:
            parsed = ipaddress.ip_address(str(address).strip())
        except ValueError:
            return None
        if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
            parsed = parsed.ipv4_mapped
        ranges = self._v4 if parsed.version == 4 else self._v6
        return ranges.find(int(parsed))

    def describe(self, now: datetime) -> dict[str, Any]:
        """What is loaded now: the list's name and its own date. Always the
        same keys, so a screen can say "list not available" from data."""
        return {
            "name": THREAT_LIST_NAME,
            "available": self.available,
            "date": self.list_date.date().isoformat() if self.list_date else None,
            "published_at": self.list_date.isoformat() if self.list_date else None,
            "fetched_at": self.fetched_at.isoformat() if self.fetched_at else None,
            "stale": self.is_stale(now),
            "max_age_days": THREAT_LIST_MAX_AGE_DAYS,
            "entries": self.entries,
            "copyright": self.copyright,
            "credit": dict(CREDIT),
        }


_LISTS: dict[str, ThreatList] = {}


def get_threat_list(data_dir: str | Path | None = None) -> ThreatList:
    """One list per directory per process: the files are read once."""
    key = str(Path(data_dir) if data_dir else default_threat_data_dir())
    found = _LISTS.get(key)
    if found is None:
        found = _LISTS[key] = ThreatList(key)
    return found
