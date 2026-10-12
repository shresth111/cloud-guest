"""Geo Location: where a venue's client traffic goes, by country and by
network (the AS that announces the outside address). No I/O except opening
the two data files.

## Data source

DB-IP Lite (https://db-ip.com/db/lite.php), "IP to Country Lite" and "IP to
ASN Lite", MMDB format, licensed CC BY 4.0. The licence requires a link back
to db-ip.com on every page that shows results; ``ATTRIBUTION`` below is
returned by the API so no screen can forget it.

The files are **not in this repository**. ``scripts/fetch_geo_data.py``
downloads them at image build time into ``data/geo/``. When they are absent
or unreadable the application starts and runs as before:
``GeoLookup.available`` is false, ingest writes no country rows, and the API
answers ``geo_available: false`` -- never a guessed country.

## What is and is not looked up

Only an address that can be routed on the public internet. Private, CGNAT,
link-local, loopback, multicast, reserved and unparseable addresses are
refused before either file is touched and count as "unknown".

## What a country means here

The country DB-IP associates with the address, which for an anycast or CDN
address is where the network is registered or a single one of its sites --
not necessarily where the bytes were served from. An AS name is a
**network**, never an application: video served from a cache inside an ISP
shows under the ISP (RESEARCH.md section 5.5).

## Storage shape (see ``TrafficFlowCountryBucket``)

One row per (router, source, window, country, network). Per window:

* the top ``TOP_COUNTRIES_STORED`` countries keep their own rows, the rest
  are folded into the country ``OTHER_COUNTRY``;
* inside the kept countries, the top ``TOP_GEO_NETWORKS_STORED`` (country,
  network) pairs keep their own rows, the rest are folded into one row per
  country with ``asn = OTHER_NETWORK_ASN``;
* traffic whose outside address has no country is the single row
  ``(UNKNOWN_COUNTRY, UNKNOWN_NETWORK_ASN)``. It is written for **every**
  geo-measured window, even at zero bytes: its presence is what says "this
  window was looked up", so a window ingested while the data files were
  missing is told apart from a window with no traffic.

Nothing is dropped, so the rows of a window sum to its client traffic
(``bytes_up + bytes_down``). A row holds no address of any kind.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from app.core.logging import get_logger

from .mmdb import MMDBError, MMDBReader

logger = get_logger(__name__)

__all__ = [
    "ASN_FILENAME",
    "ATTRIBUTION",
    "COUNTRY_FILENAME",
    "DEFAULT_GEO_COUNTRIES",
    "DEFAULT_GEO_NETWORKS",
    "MAX_GEO_COUNTRIES",
    "MAX_GEO_NETWORKS",
    "OTHER_COUNTRY",
    "OTHER_NETWORK_ASN",
    "TOP_COUNTRIES_STORED",
    "TOP_GEO_NETWORKS_STORED",
    "UNKNOWN_COUNTRY",
    "UNKNOWN_NETWORK_ASN",
    "GeoAnswer",
    "GeoCountryRow",
    "GeoLookup",
    "GeoWindowWriterProtocol",
    "build_geo_summary",
    "default_geo_data_dir",
    "geo_rows",
    "get_geo_lookup",
    "is_public_address",
]

COUNTRY_FILENAME = "dbip-country-lite.mmdb"
ASN_FILENAME = "dbip-asn-lite.mmdb"

#: Returned with every geo response. CC BY 4.0 as DB-IP states it: "you must
#: include a link back to DB-IP.com on pages that display or use results
#: from the database".
ATTRIBUTION: dict[str, str] = {
    "text": "IP Geolocation by DB-IP",
    "url": "https://db-ip.com",
    "license": "CC BY 4.0",
    "license_url": "https://creativecommons.org/licenses/by/4.0/",
}

#: ``country_code`` of the row for traffic with no country, and of the row
#: for countries outside a window's top list. Lower case and longer than two
#: letters, so neither can collide with an ISO 3166-1 alpha-2 code.
UNKNOWN_COUNTRY = "unknown"
OTHER_COUNTRY = "other"
#: ``asn`` when the network is not known (AS0 is reserved and never routed),
#: and of a country's folded remainder.
UNKNOWN_NETWORK_ASN = 0
OTHER_NETWORK_ASN = -1

#: Countries kept per stored window, and (country, network) pairs kept per
#: stored window across those countries.
TOP_COUNTRIES_STORED = 30
TOP_GEO_NETWORKS_STORED = 40

#: ``GET /geo`` list sizes: countries, and networks inside each country.
DEFAULT_GEO_COUNTRIES = 10
MAX_GEO_COUNTRIES = 50
DEFAULT_GEO_NETWORKS = 5
MAX_GEO_NETWORKS = 20

_NETWORK_NAME_MAX = 128
_CACHE_MAX = 50_000
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def default_geo_data_dir() -> Path:
    """``<backend>/data/geo`` -- ``/app/data/geo`` in the image."""
    return Path(__file__).resolve().parents[3] / "data" / "geo"


def is_public_address(
    value: str,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """The parsed address when it may be looked up, else ``None``."""
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if isinstance(address, ipaddress.IPv4Address) and address in _CGNAT:
        return None
    if (
        address.is_private
        or address.is_link_local
        or address.is_loopback
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or not address.is_global
    ):
        return None
    return address


@dataclass(frozen=True, slots=True)
class GeoAnswer:
    """``country_code`` is an ISO 3166-1 alpha-2 code or ``None``; ``asn``
    and ``network_name`` are ``None`` when the network is not known."""

    country_code: str | None
    asn: int | None
    network_name: str | None


_NO_ANSWER = GeoAnswer(None, None, None)


class GeoLookup:
    """Remote address -> country and network, from the two DB-IP Lite
    files in ``data_dir``. Both files are needed; with either missing or
    unreadable, ``available`` is false and every lookup answers nothing."""

    def __init__(self, data_dir: str | Path | None) -> None:
        self.data_dir = Path(data_dir) if data_dir else default_geo_data_dir()
        self._country: MMDBReader | None = None
        self._asn: MMDBReader | None = None
        self.unavailable_reason: str | None = None
        self._cache: dict[str, GeoAnswer | None] = {}
        try:
            self._country = MMDBReader(self.data_dir / COUNTRY_FILENAME)
            self._asn = MMDBReader(self.data_dir / ASN_FILENAME)
        except (OSError, MMDBError) as exc:
            self.close()
            self.unavailable_reason = f"{type(exc).__name__}: {exc}"
            logger.info(
                "traffic_flow_geo_unavailable",
                extra={"geo_data_dir": str(self.data_dir), "reason": str(exc)},
            )

    @property
    def available(self) -> bool:
        return self._country is not None and self._asn is not None

    def close(self) -> None:
        for reader in (self._country, self._asn):
            if reader is not None:
                reader.close()
        self._country = self._asn = None

    def describe(self) -> dict[str, Any] | None:
        """What is loaded, for the API's ``source`` block."""
        if not self.available:
            return None
        assert self._country is not None and self._asn is not None  # noqa: S101
        return {
            "name": "DB-IP Lite",
            "country_data_built": _build_date(self._country),
            "network_data_built": _build_date(self._asn),
        }

    def lookup(self, value: str) -> GeoAnswer | None:
        """``None`` when the address is not one that may be looked up (or
        geo is unavailable). Otherwise an answer whose fields may each be
        ``None``: in neither file is still an answer, "unknown"."""
        if not self.available:
            return None
        if value in self._cache:
            return self._cache[value]
        address = is_public_address(value)
        answer = self._resolve(address) if address is not None else None
        if len(self._cache) >= _CACHE_MAX:
            self._cache.clear()
        self._cache[value] = answer
        return answer

    def _resolve(
        self, address: ipaddress.IPv4Address | ipaddress.IPv6Address
    ) -> GeoAnswer:
        assert self._country is not None and self._asn is not None  # noqa: S101
        country_code: str | None = None
        record = self._country.get(address)
        if isinstance(record, dict):
            country = record.get("country")
            code = country.get("iso_code") if isinstance(country, dict) else None
            if isinstance(code, str) and len(code) == 2 and code.isalpha():
                country_code = code.upper()
        asn: int | None = None
        name: str | None = None
        record = self._asn.get(address)
        if isinstance(record, dict):
            number = record.get("autonomous_system_number")
            if isinstance(number, int) and not isinstance(number, bool) and number > 0:
                asn = number
                organization = record.get("autonomous_system_organization")
                if isinstance(organization, str) and organization.strip():
                    name = organization.strip()[:_NETWORK_NAME_MAX]
        if country_code is None and asn is None:
            return _NO_ANSWER
        return GeoAnswer(country_code, asn, name)


def _build_date(reader: MMDBReader) -> str | None:
    epoch = reader.build_epoch
    if not epoch:
        return None
    return datetime.fromtimestamp(epoch, tz=UTC).date().isoformat()


_LOOKUPS: dict[str, GeoLookup] = {}


def get_geo_lookup(data_dir: str | Path | None = None) -> GeoLookup:
    """One lookup per data directory per process. The files are read when
    the process first asks; a refreshed file is picked up on restart (every
    deploy replaces the container)."""
    key = str(Path(data_dir) if data_dir else default_geo_data_dir())
    lookup = _LOOKUPS.get(key)
    if lookup is None:
        lookup = _LOOKUPS[key] = GeoLookup(key)
    return lookup


class GeoWindowWriterProtocol(Protocol):
    """What ingest calls for a new window (``geo_service.GeoWindowWriter``)."""

    async def write_window(
        self, identity: Mapping[str, Any], destinations: Mapping[str, Sequence[int]]
    ) -> int: ...


# ---------------------------------------------------------------------------
# ingest: one window's remote addresses -> country buckets
# ---------------------------------------------------------------------------


def geo_rows(
    destinations: Mapping[str, Sequence[int]],
    lookup: GeoLookup,
    *,
    countries: int = TOP_COUNTRIES_STORED,
    networks: int = TOP_GEO_NETWORKS_STORED,
) -> list[dict[str, Any]]:
    """Country buckets for one window, from its full remote-address map
    (``ExporterWindow.destinations``: address -> ``[bytes, flows, bytes_up,
    bytes_down]``, client traffic only).

    Empty when geo is unavailable -- the window is then "not looked up".
    Otherwise the rows sum exactly to the map, and the unknown row is always
    present (module docstring). No row carries an address."""
    if not lookup.available:
        return []
    # (country, asn) -> [bytes_up, bytes_down, flows]
    pairs: dict[tuple[str, int], list[int]] = {}
    names: dict[int, str] = {}
    for ip, totals in destinations.items():
        answer = lookup.lookup(ip)
        if answer is None or answer.country_code is None:
            key = (UNKNOWN_COUNTRY, UNKNOWN_NETWORK_ASN)
        else:
            key = (answer.country_code, answer.asn or UNKNOWN_NETWORK_ASN)
            if answer.asn and answer.network_name:
                names.setdefault(answer.asn, answer.network_name)
        sums = pairs.setdefault(key, [0, 0, 0])
        sums[0] += int(totals[2])
        sums[1] += int(totals[3])
        sums[2] += int(totals[1])

    unknown = pairs.pop((UNKNOWN_COUNTRY, UNKNOWN_NETWORK_ASN), [0, 0, 0])

    by_country: dict[str, int] = {}
    for (country, _asn), sums in pairs.items():
        by_country[country] = by_country.get(country, 0) + sums[0] + sums[1]
    kept_countries = {
        country
        for country, _ in sorted(by_country.items(), key=lambda kv: (-kv[1], kv[0]))[
            :countries
        ]
    }

    other_country = [0, 0, 0]
    ranked: list[tuple[tuple[str, int], list[int]]] = []
    for key, sums in pairs.items():
        if key[0] in kept_countries:
            ranked.append((key, sums))
        else:
            for index in range(3):
                other_country[index] += sums[index]
    ranked.sort(key=lambda kv: (-(kv[1][0] + kv[1][1]), kv[0]))

    def _row(country: str, asn: int, sums: Sequence[int]) -> dict[str, Any]:
        return {
            "country_code": country,
            "asn": asn,
            "network_name": names.get(asn) if asn > 0 else None,
            "bytes_up": sums[0],
            "bytes_down": sums[1],
            "flows": sums[2],
        }

    rows = [_row(country, asn, sums) for (country, asn), sums in ranked[:networks]]
    folded: dict[str, list[int]] = {}
    for (country, _asn), sums in ranked[networks:]:
        rest = folded.setdefault(country, [0, 0, 0])
        for index in range(3):
            rest[index] += sums[index]
    rows.extend(
        _row(country, OTHER_NETWORK_ASN, sums)
        for country, sums in sorted(folded.items())
    )
    if any(other_country):
        rows.append(_row(OTHER_COUNTRY, OTHER_NETWORK_ASN, other_country))
    rows.append(_row(UNKNOWN_COUNTRY, UNKNOWN_NETWORK_ASN, unknown))
    return rows


# ---------------------------------------------------------------------------
# read: stored buckets -> the by-country summary
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class GeoCountryRow:
    """Country buckets of a range, summed per (country, network) by the
    database."""

    country_code: str
    asn: int
    network_name: str | None
    bytes_up: int
    bytes_down: int
    flows: int
    #: The same three sums over only the windows whose networks may be shown
    #: (the small-venue rule, customer callers). ``None`` = no rule applied.
    shown_bytes_up: int | None = None
    shown_bytes_down: int | None = None
    shown_flows: int | None = None


def _share(part: int, whole: int) -> float:
    return round(part / whole, 4) if whole > 0 else 0.0


def _iso(moment: datetime | None) -> str | None:
    return moment.isoformat() if moment else None


def _volume(sums: Sequence[int], whole: int) -> dict[str, Any]:
    nbytes = sums[0] + sums[1]
    return {
        "bytes_up": sums[0],
        "bytes_down": sums[1],
        "bytes": nbytes,
        "flows": sums[2],
        "share": _share(nbytes, whole),
    }


def build_geo_summary(
    *,
    feature_enabled: bool,
    geo_available: bool,
    source: Mapping[str, Any] | None,
    windows: int,
    windows_measured: int,
    rows: Sequence[GeoCountryRow],
    since: datetime,
    until: datetime,
    window_seconds: int,
    limit: int,
    networks: int,
    data_oldest: datetime | None,
    data_newest: datetime | None,
    networks_min_devices: int = 0,
    networks_withheld_windows: int = 0,
) -> dict[str, Any]:
    """``networks_min_devices`` above zero (a customer caller) applies the
    small-venue rule to **networks only**: a window with fewer devices
    contributes to its country's total but to no network, and each country
    says how much that was (``networks.withheld_bytes``). Country totals are
    never withheld.

    Three different empties, kept apart:

    * ``measured: false`` -- no traffic window exists in the range at all;
    * ``measured: true, geo_measured: false`` -- traffic was measured but no
      window in the range was looked up (``geo_available`` says whether the
      server could look one up now);
    * ``geo_measured: true`` with zero bytes -- looked up, genuinely nothing.

    Only the third has ``totals``."""
    measured = windows > 0
    geo_measured = measured and windows_measured > 0
    out: dict[str, Any] = {
        "feature_enabled": feature_enabled,
        "measured": measured,
        "geo_available": geo_available,
        "geo_measured": geo_measured,
        "exact": geo_measured and windows_measured == windows,
        "since": since.isoformat(),
        "until": until.isoformat(),
        "window_seconds": window_seconds,
        "windows": windows,
        "windows_measured": windows_measured if measured else 0,
        "data_oldest": _iso(data_oldest),
        "data_newest": _iso(data_newest),
        "totals": None,
        "countries": {"items": [], "other_bytes": 0, "other_share": 0.0},
        "unknown": None,
        "attribution": dict(ATTRIBUTION),
        "source": dict(source) if source else None,
    }
    ruled = networks_min_devices > 0
    if ruled:
        out["networks_min_devices"] = networks_min_devices
        out["networks_withheld_windows"] = (
            networks_withheld_windows if geo_measured else 0
        )
    if not geo_measured:
        return out

    total = [0, 0, 0]
    unknown = [0, 0, 0]
    other = [0, 0, 0]
    countries: dict[str, dict[str, Any]] = {}
    for row in rows:
        sums = (int(row.bytes_up), int(row.bytes_down), int(row.flows))
        for index in range(3):
            total[index] += sums[index]
        if row.country_code == UNKNOWN_COUNTRY:
            target = unknown
        elif row.country_code == OTHER_COUNTRY:
            target = other
        else:
            country = countries.setdefault(
                row.country_code, {"sums": [0, 0, 0], "shown": 0, "networks": {}}
            )
            target = country["sums"]
            shown = (
                sums
                if not ruled
                else (
                    int(row.shown_bytes_up or 0),
                    int(row.shown_bytes_down or 0),
                    int(row.shown_flows or 0),
                )
            )
            country["shown"] += shown[0] + shown[1]
            if any(shown):
                network = country["networks"].setdefault(
                    row.asn, {"sums": [0, 0, 0], "name": None}
                )
                for index in range(3):
                    network["sums"][index] += shown[index]
                network["name"] = network["name"] or row.network_name
        for index in range(3):
            target[index] += sums[index]
    whole = total[0] + total[1]

    ranked = sorted(
        countries.items(),
        key=lambda kv: (-(kv[1]["sums"][0] + kv[1]["sums"][1]), kv[0]),
    )
    items = []
    for code, country in ranked[:limit]:
        country_bytes = country["sums"][0] + country["sums"][1]
        named = sorted(
            ((asn, network) for asn, network in country["networks"].items() if asn > 0),
            key=lambda kv: (-(kv[1]["sums"][0] + kv[1]["sums"][1]), kv[0]),
        )
        network_items = [
            {
                "asn": asn,
                "network_name": network["name"],
                **_volume(network["sums"], country_bytes),
            }
            for asn, network in named[:networks]
        ]
        unknown_network = country["networks"].get(UNKNOWN_NETWORK_ASN)
        unknown_bytes = (
            unknown_network["sums"][0] + unknown_network["sums"][1]
            if unknown_network
            else 0
        )
        listed = sum(item["bytes"] for item in network_items)
        network_block: dict[str, Any] = {
            "items": network_items,
            # Networks below the list, plus what a window folded.
            "other_bytes": max(country["shown"] - listed - unknown_bytes, 0),
            "unknown_bytes": unknown_bytes,
        }
        if ruled:
            # In this country, in windows with too few devices: counted in
            # the country, attributed to no network.
            network_block["withheld_bytes"] = max(country_bytes - country["shown"], 0)
        items.append(
            {
                "country_code": code,
                **_volume(country["sums"], whole),
                "networks": network_block,
            }
        )
    for _code, country in ranked[limit:]:
        for index in range(3):
            other[index] += country["sums"][index]

    out["totals"] = {
        "bytes_up": total[0],
        "bytes_down": total[1],
        "bytes": whole,
        "flows": total[2],
    }
    out["countries"] = {
        "items": items,
        "other_bytes": other[0] + other[1],
        "other_share": _share(other[0] + other[1], whole),
    }
    out["unknown"] = _volume(unknown, whole)
    return out
