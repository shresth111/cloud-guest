"""Flow records: the Master console's flow table.

One row per flow as the collector aggregated it inside one 5-minute window:
start, end, source address and port, destination address and port, protocol,
the NAT translation, bytes, packets and the exporter. Unlike every other
table of this domain, **a row here puts a device beside the address it
talked to**. That is a deliberate owner decision for this table only, and
these are the safeguards that come with it. Do not relax one without the
owner:

* **Off unless switched on.** Nothing is written unless
  ``CLOUDGUEST_TRAFFIC_FLOW_RECORDS_ENABLED`` is true (default false) *and*
  the router's own export switch is on. The aggregate tables do not depend
  on either.
* **Two readers, no more.** The Master console
  (``flow_records_router.py``, pinned to ``ScopeType.GLOBAL``), and a
  customer's own venue (``flow_records_customer_router.py``) behind a second
  add-on, ``traffic_flow_records``, that is off for every customer until the
  Master console unlocks it for that one, on top of ``traffic_flow`` and
  ``venue_traffic.read``. The customer reader was added by owner decision;
  unlocking it for a real venue is the owner's call per customer, after the
  venue's guest notice covers it (RESEARCH.md section 6).
* **Audited.** Every search and download writes an audit row; the audit
  writer is a required argument.
* **Short retention.** ``traffic_flow_record_retention_days`` (default 7),
  enforced by the existing pull sweep. Not a CERT-In log and never to be
  described as one.
* **A size guard that is never silent.** A per-router, per-UTC-day row cap.
  When a router reaches it, flow records stop for that router for the rest
  of the day (rollups continue), the moment is stored in
  ``traffic_flow_record_caps``, and every reader says "records incomplete
  since ...".
* **Nothing invented.** A field the collector did not send is NULL and
  reads "not recorded" (``fields_not_recorded`` in every response). A NAT
  address is never inferred from the router's WAN address, and a flow's
  start is never guessed from its window.

## What a row is, and is not (COLLECTOR-FLOW-FIELDS.md)

* A row is one record as the collector emitted it: **one direction**, and a
  long flow is re-exported every active timeout. Rows are not paired or
  stitched into conversations here; the response says so.
* Two inputs. If the hub agent sends per-flow rows (``flow_rows``, from a
  print plugin of its own with the NAT and timestamp primitives), they are
  stored with start, end and translation. If it does not -- the collector
  as deployed today -- the rollup's rows are stored instead: one per
  (source, destination, ports, protocol) per window, with start, end and
  NAT **not recorded**.
* pmacct prints a NAT field the router did not send as a zero address and a
  zero port, without an error. Those are stored as NULL, not as 0.0.0.0.
* Start and end are the ROUTER's clock; if the router sent no time element
  pmacct silently substitutes the export time (start equals end). That
  cannot be told apart here. ``arrived_at`` is the collector's own clock,
  kept beside them as the cross-check.
* Unverified on hardware: whether RouterOS sends the NAT elements pmacct
  reads, and whether at a hotspot venue the source is the guest's address.

## What is merged and what is not stored (measured, 2026-10-13)

The hub's first per-flow file, one venue with 5 to 7 devices, 4 minutes of
one window: 5,183 records, i.e. about 6,500 per 5-minute window and 1.9
million a day. 3,207 were outside-to-venue UDP answers of one or two packets
(3,183 from port 123) from 62 outside addresses to 2 venue addresses, each
to a different local port; 1,949 had both ends inside the venue (949 to the
router's DNS); 27 were venue-to-outside. Stored as they came, the daily cap
would be reached about 01:20 every day.

So, per window (``prepare_records``), each rule with a count the reader is
given:

* **Internal records are not stored** unless
  ``traffic_flow_record_store_internal``. 38% of the sample, none of it
  traffic to anywhere.
* **Records identical in addresses, ports and protocol are merged**: bytes,
  packets and flows summed, earliest start, latest end.
* **Records that differ only in the venue-side port are merged too**
  (``traffic_flow_record_merge_ports``, default on); that port is then NULL
  and ``ports_merged`` is true. This is the rule that matters: the sample's
  busiest local port had 4 records, so merging identical records alone
  would leave most of the 3,207 in place, while by outside address and
  service they are at most a few per (outside address, venue address).
  The outside address and port, which say what was reached, are never
  merged away.

For the sample that is at most about 150 rows from the 3,207, plus at most
27: under 200 rows a window, under 58,000 a day, about 18 MB a day and 125
MB at retention for that venue. An estimate from the sample's summary
counts, not a replay of its rows.

## IPDR routers keep their ports (``router_traffic_flow_export.ipdr_ports``)

An IPDR row needs the guest's own source port. For a router whose export
row has ``ipdr_ports`` on (a Master-console switch, off by default), the
venue-side port is **not** merged away, whatever
``traffic_flow_record_merge_ports`` says. One exception keeps the measured
noise bounded: UDP whose outside end is port 123 (NTP, 3,183 of the
sample's 5,183 records) is still port-merged, per venue host and outside
server, and flagged ``ports_merged`` like before. The per-router daily cap
still applies and still says so.

## NAT events (IPFIX ``nat-events=yes``)

RouterOS sends conntrack NAT events as a template of their own (on the
fleet: elements 4, 7, 8, 11, 12, 225-228, 230 natEvent and 323
observationTimeMilliseconds, no byte or packet counter). pmacct prints them
as rows with ``bytes`` and ``packets`` 0, its start time the observation
time, and -- only when the hub's aggregate carries ``nat_event`` -- the
event type. They are stored as rows with ``nat_event`` set (the IANA
natEvent value, 0 when the hub did not send the type) and never merged
with a traffic record. NULL ``nat_event`` = a traffic record.

## Size (the default cap)

A row with every field filled and its indexes measures 307 bytes on
PostgreSQL 17 (500,000 rows, 146 MB), unchanged by the two merge columns.
The cap counts rows as STORED, after merging and without internal records,
because that is what takes the disk. The default stays 100,000 rows per
router per UTC day: at most 31 MB a day and 215 MB per router at the 7-day
retention. Assumed, not measured: the database shares the app server's
disk, and this table may take about 1 GB of it, i.e. four routers at the
cap. The sample venue would use a little over half its cap. A venue with
ten times the devices may still reach it; then storage stops for the day
and every reader says so, with the count.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import time
import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any, Protocol

from fastapi import status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import (
    cast,
    delete,
    func,
    literal,
    not_,
    or_,
    select,
)
from sqlalchemy.dialects.postgresql import CIDR
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.logging import get_logger
from app.domains.location.models import Location
from app.domains.router.models import Router

from .constants import (
    DEFAULT_QUERY_WINDOW_SECONDS,
    RETENTION_BATCH,
    WINDOW_SECONDS,
)
from .flow_record_models import TrafficFlowRecord, TrafficFlowRecordCap
from .ingest import is_local_address, parse_protocol
from .platform_overhead import (
    NO_PLATFORM_ENDPOINTS,
    PlatformEndpoints,
    load_platform_endpoints,
    platform_endpoints_of,
)
from .service import TrafficFlowError
from .summary import protocol_name, service_name

logger = get_logger(__name__)

__all__ = [
    "AUDIT_ACTION_FLOW_RECORDS_EXPORTED",
    "AUDIT_ACTION_FLOW_RECORDS_SEARCHED",
    "CSV_COLUMNS",
    "CUSTOMER_CSV_COLUMNS",
    "CustomerFlowRecordService",
    "FLOW_RECORD_CSV_MAX_ROWS",
    "FLOW_RECORD_SEARCH_LIMIT",
    "RESPONSE_MODELS",
    "FlowRecordFilters",
    "FlowRecordRepository",
    "FlowRecordScope",
    "FlowRecordSearchResponse",
    "FlowRecordService",
    "FlowRecordWriter",
    "TrafficFlowRecord",
    "TrafficFlowRecordCap",
    "flow_record_rows",
    "parse_flow_filters",
    "resolve_record_range",
]

#: Records on the one page a search returns. There is no second page.
FLOW_RECORD_SEARCH_LIMIT = 1000
#: Records in one CSV download, built in memory on a small server.
FLOW_RECORD_CSV_MAX_ROWS = 50_000
#: Flow records deleted per sweep, as a multiple of RETENTION_BATCH.
FLOW_RECORD_RETENTION_FACTOR = 40
#: A range may start this much before the retention edge (clock skew).
RETENTION_SLACK = timedelta(minutes=15)
#: The longest range one search may cover.
MAX_RECORD_QUERY_DAYS = 7

AUDIT_ACTION_FLOW_RECORDS_SEARCHED = "traffic_flow_records_searched"
AUDIT_ACTION_FLOW_RECORDS_EXPORTED = "traffic_flow_records_exported"

#: How a flow sits relative to the venue. Which side is private decides it,
#: never the flow's own direction (see ``ingest.py``).
DIRECTION_UP = "upload"
DIRECTION_DOWN = "download"
DIRECTION_INTERNAL = "internal"
DIRECTION_UNCLASSIFIED = "unclassified"
#: The router's own tunnel to the platform (``platform_overhead``). Stored,
#: so the Master table can show it with this marker; never returned to a
#: customer.
DIRECTION_PLATFORM = "platform"

SORT_KEYS = (
    "start",
    "end",
    "src_address",
    "src_port",
    "dst_address",
    "dst_port",
    "protocol",
    "bytes",
    "packets",
)
ORDERS = ("desc", "asc")


# ---------------------------------------------------------------------------
# reduction: collector rows -> records (pure)
# ---------------------------------------------------------------------------

#: Collector spellings per field, first present wins. pmacct's print plugin
#: names (COLLECTOR-FLOW-FIELDS.md); a key that is absent is "not recorded".
_NAT_SRC_KEYS = ("post_nat_ip_src", "post_nat_src_ip")
_NAT_DST_KEYS = ("post_nat_ip_dst", "post_nat_dst_ip")
_NAT_SRC_PORT_KEYS = ("post_nat_port_src", "post_nat_src_port")
_NAT_DST_PORT_KEYS = ("post_nat_port_dst", "post_nat_dst_port")
_START_KEYS = ("timestamp_start",)
_END_KEYS = ("timestamp_end",)
_ARRIVAL_KEYS = ("timestamp_arrival",)
_EXPORTER_PORT_KEYS = ("peer_port_src", "peer_src_port")
_NAT_EVENT_KEYS = ("nat_event",)

#: ``nat_event`` of a NAT-event row whose type the hub did not send (its
#: aggregate has no ``nat_event``): known to be an event, type unknown.
NAT_EVENT_UNTYPED = 0
#: UDP to or from these outside ports is port-merged even on a router that
#: keeps ports for the IPDR: NTP, the measured bulk of the noise.
SUMMARISED_REMOTE_PORTS = frozenset({123})
_UDP = 17

#: pmacct prints these when a field is in the aggregate but the exporter
#: sent nothing for it. They mean "not recorded", not an address.
_EMPTY_ADDRESSES = frozenset({"", "0.0.0.0", "::", "0", "none", "null"})  # noqa: S104


def _first(row: Mapping[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        if key in row and row[key] is not None:
            return row[key]
    return None


def _address(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if text.lower() in _EMPTY_ADDRESSES:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _port(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if 0 <= number <= 65535 else None


def _count(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def _instant(value: Any) -> datetime | None:
    """A collector timestamp: epoch seconds (number or numeric text) or
    ``YYYY-MM-DD HH:MM:SS[.ffffff]`` in UTC. Zero and the epoch itself are
    pmacct's "no timestamp" and read as not recorded."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return datetime.fromtimestamp(value, tz=UTC) if value > 0 else None
    text = str(value).strip()
    if not text:
        return None
    try:
        number = float(text)
    except ValueError:
        pass
    else:
        return datetime.fromtimestamp(number, tz=UTC) if number > 0 else None
    try:
        parsed = datetime.fromisoformat(text.replace(" ", "T", 1))
    except ValueError:
        return None
    parsed = parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)
    return parsed if parsed.timestamp() > 0 else None


def nat_event_of(row: Mapping[str, Any]) -> int | None:
    """The natEvent value of a NAT-event row, else ``None`` (a traffic
    record). A row with the hub's ``nat_event`` key above 0 is an event of
    that type. Without the key (the hub's aggregate does not carry it), a row
    whose ``packets`` AND ``bytes`` are both an explicit 0 is an event of
    unknown type: no traffic record has zero packets, and pmacct prints the
    counters of a counter-less NAT-event template as 0."""
    typed = _count(_first(row, _NAT_EVENT_KEYS))
    if typed:
        return typed
    if _count(row.get("packets")) == 0 and _count(row.get("bytes")) == 0:
        return NAT_EVENT_UNTYPED
    return None


def _direction(src: str, dst: str) -> str:
    src_local = bool(is_local_address(src))
    dst_local = bool(is_local_address(dst))
    if src_local and dst_local:
        return DIRECTION_INTERNAL
    if src_local:
        return DIRECTION_UP
    if dst_local:
        return DIRECTION_DOWN
    return DIRECTION_UNCLASSIFIED


def flow_record_rows(
    rows: Iterable[Mapping[str, Any]],
    exporter: str,
    platform: PlatformEndpoints = NO_PLATFORM_ENDPOINTS,
) -> list[dict[str, Any]]:
    """One record per collector row of ``exporter``, largest first.

    A row whose source or destination is not an address is left out (it is
    already counted in the window's ``rows_rejected``). Every other field is
    optional: what the collector did not send stays ``None``."""
    out: list[dict[str, Any]] = []
    for row in rows:
        if str(row.get("peer_ip_src") or "").strip() != exporter:
            continue
        src = _address(row.get("ip_src"))
        dst = _address(row.get("ip_dst"))
        if src is None or dst is None:
            continue
        nat_src = _address(_first(row, _NAT_SRC_KEYS))
        nat_dst = _address(_first(row, _NAT_DST_KEYS))
        direction = _direction(src, dst)
        if direction != DIRECTION_INTERNAL and platform.row_direction(row):
            # The router's tunnel to the hub. (What rides INSIDE the tunnel
            # has two private ends and stays "internal", left out as before.)
            direction = DIRECTION_PLATFORM
        out.append(
            {
                "flow_start": _instant(_first(row, _START_KEYS)),
                "flow_end": _instant(_first(row, _END_KEYS)),
                "arrived_at": _instant(_first(row, _ARRIVAL_KEYS)),
                "src_address": src,
                "src_port": _port(row.get("port_src")),
                "dst_address": dst,
                "dst_port": _port(row.get("port_dst")),
                "protocol": parse_protocol(row.get("ip_proto")),
                "nat_src_address": nat_src,
                # A translated port without a translated address is noise.
                "nat_src_port": (
                    _port(_first(row, _NAT_SRC_PORT_KEYS)) if nat_src else None
                ),
                "nat_dst_address": nat_dst,
                "nat_dst_port": (
                    _port(_first(row, _NAT_DST_PORT_KEYS)) if nat_dst else None
                ),
                "bytes": _count(row.get("bytes")) or 0,
                "packets": _count(row.get("packets")),
                "flows": _count(row.get("flows")),
                "direction": direction,
                "exporter_address": exporter,
                "exporter_port": _port(_first(row, _EXPORTER_PORT_KEYS)),
                "records_merged": 1,
                "ports_merged": False,
                "nat_event": nat_event_of(row),
            }
        )
    out.sort(key=lambda r: (-r["bytes"], r["src_address"], r["dst_address"]))
    return out


@dataclass(frozen=True, slots=True)
class WindowCounts:
    """What happened to one window's collector records before storage."""

    #: Records the collector sent for this exporter (with real addresses).
    received: int = 0
    #: Left out because both ends are inside the venue.
    internal: int = 0
    #: Folded into another row; their bytes, packets and flows are kept.
    merged: int = 0


def _venue_side(direction: str) -> str | None:
    """Which end's port is the venue's own (ephemeral) one."""
    if direction == DIRECTION_UP:
        return "src"
    if direction == DIRECTION_DOWN:
        return "dst"
    return None


def _total(values: list[int | None]) -> int | None:
    present = [v for v in values if v is not None]
    return sum(present) if present else None


def _common(values: list[Any]) -> Any:
    """The value all merged records share, else ``None``."""
    first = values[0]
    return first if all(v == first for v in values) else None


def _merge(group: list[dict[str, Any]], side: str | None) -> dict[str, Any]:
    if len(group) == 1:
        return group[0]
    out = dict(group[0])
    starts = [r["flow_start"] for r in group if r["flow_start"] is not None]
    ends = [r["flow_end"] for r in group if r["flow_end"] is not None]
    arrivals = [r["arrived_at"] for r in group if r["arrived_at"] is not None]
    out["flow_start"] = min(starts) if starts else None
    out["flow_end"] = max(ends) if ends else None
    out["arrived_at"] = max(arrivals) if arrivals else None
    out["bytes"] = sum(r["bytes"] for r in group)
    out["packets"] = _total([r["packets"] for r in group])
    out["flows"] = _total([r["flows"] for r in group])
    out["records_merged"] = len(group)
    # A translation is kept only when every merged record agrees on it.
    for name in ("nat_src_address", "nat_dst_address", "exporter_port"):
        out[name] = _common([r[name] for r in group])
    for name in ("nat_src_port", "nat_dst_port"):
        address = name.replace("port", "address")
        out[name] = _common([r[name] for r in group]) if out[address] else None
    if out.get("nat_event") is not None:
        # Events only merge with events; a create and its delete in one
        # window become one row spanning both, type then unknown.
        typed = _common([r.get("nat_event") for r in group])
        out["nat_event"] = NAT_EVENT_UNTYPED if typed is None else typed
    if side is not None:
        ports = [r[f"{side}_port"] for r in group]
        if not all(p == ports[0] for p in ports):
            out[f"{side}_port"] = None
            out[f"nat_{side}_port"] = None
            out["ports_merged"] = True
    return out


def _remote_port(record: dict[str, Any], side: str | None) -> int | None:
    """The outside end's port: the one that is not the venue side."""
    if side == "src":
        return record["dst_port"]
    if side == "dst":
        return record["src_port"]
    return None


def _merges_ports(
    record: dict[str, Any], merge_ports: bool, summarised: frozenset[int]
) -> str | None:
    """Which side's port this record may lose to a merge, if any."""
    side = _venue_side(record["direction"])
    if side is None or merge_ports:
        return side
    if record["protocol"] == _UDP and _remote_port(record, side) in summarised:
        return side
    return None


def prepare_records(
    records: list[dict[str, Any]],
    *,
    store_internal: bool,
    merge_ports: bool,
    summarised_ports: frozenset[int] = frozenset(),
) -> tuple[list[dict[str, Any]], WindowCounts]:
    """One window's records as they will be stored, largest first, and what
    was left out or folded on the way. Nothing is dropped without a count.

    * **Internal** records (both ends inside the venue) are left out unless
      ``store_internal``: they are not traffic to anywhere.
    * Records with the same addresses, ports and protocol are **merged**:
      bytes, packets and flows summed, earliest start, latest end.
    * With ``merge_ports``, records that differ only in the venue-side port
      (a phone's ephemeral port, different on every connection) are merged
      too; that port is then ``None`` and ``ports_merged`` is true. The
      outside end's address and port, which say what was reached, are never
      merged away. Internal and unclassified records have no venue side and
      are only merged when identical.
    * Without ``merge_ports`` (a router kept for the IPDR), UDP records whose
      outside port is in ``summarised_ports`` (NTP) are still port-merged,
      and flagged ``ports_merged`` the same way.
    * NAT-event rows (``nat_event`` not None) only merge with each other."""
    received = len(records)
    internal = 0
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for record in records:
        direction = record["direction"]
        if direction == DIRECTION_INTERNAL and not store_internal:
            internal += 1
            continue
        side = _merges_ports(record, merge_ports, summarised_ports)
        key = (
            direction,
            record["src_address"],
            None if side == "src" else record["src_port"],
            record["dst_address"],
            None if side == "dst" else record["dst_port"],
            record["protocol"],
            record.get("nat_event") is not None,
            side,
        )
        groups.setdefault(key, []).append(record)
    rows = [_merge(group, key[-1]) for key, group in groups.items()]
    rows.sort(key=lambda r: (-r["bytes"], r["src_address"], r["dst_address"]))
    return rows, WindowCounts(
        received=received, internal=internal, merged=received - internal - len(rows)
    )


# ---------------------------------------------------------------------------
# request side
# ---------------------------------------------------------------------------


def _bad_filter(field: str, message: str) -> TrafficFlowError:
    error = TrafficFlowError(
        message,
        code="TRAFFIC_FLOW_BAD_FILTER",
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
    )
    error.data["field"] = field
    return error


def _aware(moment: datetime) -> datetime:
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=UTC)


def resolve_record_range(
    since: datetime | None,
    until: datetime | None,
    *,
    now: datetime,
    retention_days: int,
) -> tuple[datetime, datetime]:
    """The range a request means, or a refusal. Never silently shortened."""
    end = _aware(until) if until else now
    start = (
        _aware(since)
        if since
        else end - timedelta(seconds=DEFAULT_QUERY_WINDOW_SECONDS)
    )
    if start >= end:
        raise TrafficFlowError(
            "since must be before until.",
            code="TRAFFIC_FLOW_BAD_RANGE",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
    longest = min(MAX_RECORD_QUERY_DAYS, retention_days)
    if end - start > timedelta(days=longest):
        raise TrafficFlowError(
            f"The range may not be longer than {longest} days.",
            code="TRAFFIC_FLOW_WINDOW_TOO_LARGE",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
    earliest = now - timedelta(days=retention_days)
    if start < earliest - RETENTION_SLACK:
        error = TrafficFlowError(
            f"Flow records are kept for {retention_days} days. The range may "
            f"not start before {earliest.isoformat(timespec='minutes')}.",
            code="TRAFFIC_FLOW_RANGE_OUTSIDE_RETENTION",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
        error.data["earliest"] = earliest.isoformat()
        raise error
    return start, end


Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def _network_text(network: Network | None) -> str | None:
    if network is None:
        return None
    if network.prefixlen == network.max_prefixlen:
        return str(network.network_address)
    return str(network)


@dataclass(frozen=True, slots=True)
class FlowRecordFilters:
    #: Either end of the flow, before or after translation.
    address: Network | None = None
    src_address: Network | None = None
    dst_address: Network | None = None
    #: Either end's port.
    port: int | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "address": _network_text(self.address),
            "src_address": _network_text(self.src_address),
            "dst_address": _network_text(self.dst_address),
            "port": self.port,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
        }


def _network(field: str, value: str | None) -> Network | None:
    if value is None or not value.strip():
        return None
    try:
        return ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise _bad_filter(
            field, f"{field} must be an IP address or a prefix such as 203.0.113.0/24."
        ) from exc


def _port_filter(field: str, value: int | None) -> int | None:
    if value is not None and not 0 <= value <= 65535:
        raise _bad_filter(field, f"{field} must be between 0 and 65535.")
    return value


def parse_flow_filters(
    *,
    address: str | None = None,
    src_address: str | None = None,
    dst_address: str | None = None,
    port: int | None = None,
    src_port: int | None = None,
    dst_port: int | None = None,
    protocol: int | None = None,
) -> FlowRecordFilters:
    if protocol is not None and not 0 <= protocol <= 255:
        raise _bad_filter("protocol", "protocol must be between 0 and 255.")
    return FlowRecordFilters(
        address=_network("address", address),
        src_address=_network("src_address", src_address),
        dst_address=_network("dst_address", dst_address),
        port=_port_filter("port", port),
        src_port=_port_filter("src_port", src_port),
        dst_port=_port_filter("dst_port", dst_port),
        protocol=protocol,
    )


def _parse_sort(sort: str | None, order: str | None) -> tuple[str, str]:
    key = (sort or "start").strip().lower()
    if key not in SORT_KEYS:
        raise _bad_filter("sort", "sort must be one of: " + ", ".join(SORT_KEYS) + ".")
    way = (order or "desc").strip().lower()
    if way not in ORDERS:
        raise _bad_filter("order", "order must be desc or asc.")
    return key, way


@dataclass(frozen=True, slots=True)
class FlowRecordScope:
    """A venue, a router, or a router of a venue. A customer scope always
    has the venue and the caller's organisation (``CustomerFlowRecordService``
    builds it; a route cannot)."""

    location_id: uuid.UUID | None = None
    router_id: uuid.UUID | None = None
    #: The caller's organisation on the customer route; ``None`` for Master.
    #: Put on every statement over a table that carries it, whatever the
    #: venue check already established.
    organization_id: uuid.UUID | None = None
    #: The hub's tunnel endpoints, for hiding rows stored before they were
    #: marked. Only consulted for a customer scope.
    platform: PlatformEndpoints = NO_PLATFORM_ENDPOINTS

    def conditions(self, model: Any) -> list[Any]:
        out: list[Any] = []
        if self.location_id is not None:
            out.append(model.location_id == self.location_id)
        if self.router_id is not None:
            out.append(model.router_id == self.router_id)
        if self.organization_id is not None and hasattr(model, "organization_id"):
            out.append(model.organization_id == self.organization_id)
        if self.organization_id is not None and hasattr(model, "direction"):
            # A customer never sees the router's tunnel to the platform:
            # neither the rows marked at ingest, nor older rows that match
            # the hub's endpoint now.
            out.append(model.direction != DIRECTION_PLATFORM)
            hidden = self.platform.record_condition(model)
            if hidden is not None:
                out.append(not_(hidden))
        return out


# ---------------------------------------------------------------------------
# statements
# ---------------------------------------------------------------------------

_RECORD = TrafficFlowRecord
_CAP = TrafficFlowRecordCap


def _within(column: Any, network: Network) -> Any:
    return column.op("<<=")(cast(literal(str(network)), CIDR))


def _matching(
    scope: FlowRecordScope,
    filters: FlowRecordFilters,
    *,
    since: datetime,
    until: datetime,
) -> list[Any]:
    """A record is in range by the window it arrived in: that is always
    known, while a flow's own start may not be recorded."""
    conditions: list[Any] = [
        _RECORD.window_start >= since,
        _RECORD.window_start < until,
        *scope.conditions(_RECORD),
    ]
    if filters.address is not None:
        conditions.append(
            or_(
                _within(_RECORD.src_address, filters.address),
                _within(_RECORD.dst_address, filters.address),
                _within(_RECORD.nat_src_address, filters.address),
                _within(_RECORD.nat_dst_address, filters.address),
            )
        )
    if filters.src_address is not None:
        conditions.append(_within(_RECORD.src_address, filters.src_address))
    if filters.dst_address is not None:
        conditions.append(_within(_RECORD.dst_address, filters.dst_address))
    if filters.port is not None:
        conditions.append(
            or_(_RECORD.src_port == filters.port, _RECORD.dst_port == filters.port)
        )
    if filters.src_port is not None:
        conditions.append(_RECORD.src_port == filters.src_port)
    if filters.dst_port is not None:
        conditions.append(_RECORD.dst_port == filters.dst_port)
    if filters.protocol is not None:
        conditions.append(_RECORD.protocol == filters.protocol)
    return conditions


def record_page_statement(
    scope: FlowRecordScope,
    filters: FlowRecordFilters,
    *,
    since: datetime,
    until: datetime,
    sort: str,
    order: str,
    limit: int,
) -> Any:
    # Where the flow's own time is not recorded, its window stands in for
    # ORDERING only; the response still says the time is not recorded.
    column = {
        "start": func.coalesce(_RECORD.flow_start, _RECORD.window_start),
        "end": func.coalesce(_RECORD.flow_end, _RECORD.window_start),
        "src_address": _RECORD.src_address,
        "src_port": _RECORD.src_port,
        "dst_address": _RECORD.dst_address,
        "dst_port": _RECORD.dst_port,
        "protocol": _RECORD.protocol,
        "bytes": _RECORD.bytes,
        "packets": _RECORD.packets,
    }[sort]
    primary = (
        column.asc().nulls_last() if order == "asc" else column.desc().nulls_last()
    )
    return (
        select(_RECORD)
        .where(*_matching(scope, filters, since=since, until=until))
        .order_by(primary, _RECORD.window_start.desc(), _RECORD.id)
        .limit(limit)
    )


def record_totals_statement(
    scope: FlowRecordScope,
    filters: FlowRecordFilters,
    *,
    since: datetime,
    until: datetime,
) -> Any:
    return select(
        func.count(),
        func.coalesce(func.sum(_RECORD.bytes), 0),
        func.coalesce(func.sum(_RECORD.packets), 0),
    ).where(*_matching(scope, filters, since=since, until=until))


def record_bounds_statement(scope: FlowRecordScope) -> Any:
    return select(func.min(_RECORD.window_start), func.max(_RECORD.window_start)).where(
        *scope.conditions(_RECORD)
    )


def capped_days_statement(
    scope: FlowRecordScope, *, since: datetime, until: datetime
) -> Any:
    """Cap rows whose incomplete stretch (from ``capped_at`` to the end of
    that UTC day) overlaps the range."""
    return (
        select(_CAP.router_id, _CAP.day, _CAP.capped_at, _CAP.rows_not_stored)
        .where(
            _CAP.capped_at.is_not(None),
            _CAP.capped_at < until,
            _CAP.day >= since.astimezone(UTC).date(),
            *scope.conditions(_CAP),
        )
        .order_by(_CAP.capped_at)
    )


def storage_counts_statement(
    scope: FlowRecordScope, *, since: datetime, until: datetime
) -> Any:
    """What happened to the collector's records on the UTC days the range
    touches. Counters are kept per router and day, so a range inside a day
    is answered with that whole day's figures (the response says so)."""
    last = (until - timedelta(microseconds=1)).astimezone(UTC).date()
    return select(
        func.coalesce(func.sum(_CAP.rows_received), 0),
        func.coalesce(func.sum(_CAP.rows_stored), 0),
        func.coalesce(func.sum(_CAP.rows_merged), 0),
        func.coalesce(func.sum(_CAP.rows_internal), 0),
        func.coalesce(func.sum(_CAP.rows_not_stored), 0),
    ).where(
        _CAP.day >= since.astimezone(UTC).date(),
        _CAP.day <= last,
        *scope.conditions(_CAP),
    )


def record_delete_statement(cutoff: datetime, *, limit: int) -> Any:
    ids = (
        select(_RECORD.id).where(_RECORD.window_start < cutoff).limit(limit)
    ).scalar_subquery()
    return delete(_RECORD).where(_RECORD.id.in_(ids))


def cap_delete_statement(cutoff: datetime) -> Any:
    return delete(_CAP).where(_CAP.day < cutoff.astimezone(UTC).date())


# ---------------------------------------------------------------------------
# repository
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CapState:
    rows_stored: int = 0
    capped_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class StorageCounts:
    received: int = 0
    stored: int = 0
    merged: int = 0
    internal: int = 0
    over_cap: int = 0


@dataclass(frozen=True, slots=True)
class CappedDay:
    router_id: uuid.UUID
    day: date
    capped_at: datetime
    rows_not_stored: int


@dataclass(frozen=True, slots=True)
class RecordTotals:
    count: int = 0
    bytes: int = 0
    packets: int = 0


@dataclass(frozen=True, slots=True)
class RecordScopeTarget:
    """What a search is about, for the audit row."""

    location_id: uuid.UUID | None
    router_id: uuid.UUID | None
    organization_id: uuid.UUID | None


class FlowRecordRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    # -- write side -------------------------------------------------------
    async def platform_endpoints(self, settings: Any) -> PlatformEndpoints:
        return await load_platform_endpoints(self.session, settings)

    async def cap_state(self, router_id: uuid.UUID, day: date) -> CapState:
        row = (
            await self.session.execute(
                select(_CAP.rows_stored, _CAP.capped_at).where(
                    _CAP.router_id == router_id, _CAP.day == day
                )
            )
        ).first()
        return CapState(int(row[0]), row[1]) if row else CapState()

    async def record_cap(
        self,
        *,
        router_id: uuid.UUID,
        location_id: uuid.UUID | None,
        day: date,
        stored: int,
        not_stored: int,
        capped_at: datetime | None,
        received: int = 0,
        merged: int = 0,
        internal: int = 0,
    ) -> None:
        """Add to the day's counters. ``capped_at`` is kept from the first
        time it is set: "incomplete since" is when storage first stopped."""
        statement = pg_insert(_CAP).values(
            router_id=router_id,
            location_id=location_id,
            day=day,
            rows_stored=stored,
            rows_not_stored=not_stored,
            capped_at=capped_at,
            rows_received=received,
            rows_merged=merged,
            rows_internal=internal,
        )
        statement = statement.on_conflict_do_update(
            constraint="uq_traffic_flow_record_caps_key",
            set_={
                "rows_stored": _CAP.rows_stored + statement.excluded.rows_stored,
                "rows_not_stored": _CAP.rows_not_stored
                + statement.excluded.rows_not_stored,
                "rows_received": _CAP.rows_received + statement.excluded.rows_received,
                "rows_merged": _CAP.rows_merged + statement.excluded.rows_merged,
                "rows_internal": _CAP.rows_internal + statement.excluded.rows_internal,
                "capped_at": func.coalesce(
                    _CAP.capped_at, statement.excluded.capped_at
                ),
            },
        )
        await self.session.execute(statement)

    async def insert_records(self, rows: list[dict[str, Any]]) -> None:
        # Chunked: 23 columns a row, and asyncpg allows 32767 bind values.
        for index in range(0, len(rows), 1000):
            await self.session.execute(
                pg_insert(_RECORD).values(rows[index : index + 1000])
            )

    async def delete_records_before(self, cutoff: datetime, *, limit: int) -> int:
        result = await self.session.execute(
            record_delete_statement(cutoff, limit=limit)
        )
        await self.session.execute(cap_delete_statement(cutoff))
        return int(result.rowcount or 0)

    # -- read side --------------------------------------------------------
    async def target(self, scope: FlowRecordScope) -> RecordScopeTarget | None:
        """The venue or router a search names, with its organisation, or
        ``None`` when it does not exist."""
        if scope.router_id is not None:
            row = (
                await self.session.execute(
                    select(Router.location_id, Router.organization_id).where(
                        Router.id == scope.router_id, Router.is_deleted.is_(False)
                    )
                )
            ).first()
            if row is None:
                return None
            return RecordScopeTarget(
                scope.location_id or row[0], scope.router_id, row[1]
            )
        row = (
            await self.session.execute(
                select(Location.organization_id).where(
                    Location.id == scope.location_id, Location.is_deleted.is_(False)
                )
            )
        ).first()
        if row is None:
            return None
        return RecordScopeTarget(scope.location_id, None, row[0])

    async def page(
        self,
        scope: FlowRecordScope,
        filters: FlowRecordFilters,
        *,
        since: datetime,
        until: datetime,
        sort: str,
        order: str,
        limit: int,
    ) -> list[Any]:
        statement = record_page_statement(
            scope,
            filters,
            since=since,
            until=until,
            sort=sort,
            order=order,
            limit=limit,
        )
        return list((await self.session.execute(statement)).scalars().all())

    async def totals(
        self,
        scope: FlowRecordScope,
        filters: FlowRecordFilters,
        *,
        since: datetime,
        until: datetime,
    ) -> RecordTotals:
        row = (
            await self.session.execute(
                record_totals_statement(scope, filters, since=since, until=until)
            )
        ).one()
        return RecordTotals(int(row[0]), int(row[1]), int(row[2]))

    async def bounds(
        self, scope: FlowRecordScope
    ) -> tuple[datetime | None, datetime | None]:
        oldest, newest = (
            await self.session.execute(record_bounds_statement(scope))
        ).one()
        return oldest, newest

    async def capped_days(
        self, scope: FlowRecordScope, *, since: datetime, until: datetime
    ) -> list[CappedDay]:
        rows = (
            await self.session.execute(
                capped_days_statement(scope, since=since, until=until)
            )
        ).all()
        return [CappedDay(r[0], r[1], r[2], int(r[3])) for r in rows]

    async def storage_counts(
        self, scope: FlowRecordScope, *, since: datetime, until: datetime
    ) -> StorageCounts:
        row = (
            await self.session.execute(
                storage_counts_statement(scope, since=since, until=until)
            )
        ).one()
        return StorageCounts(*(int(value) for value in row))


# ---------------------------------------------------------------------------
# ingest side
# ---------------------------------------------------------------------------


class RecordStore(Protocol):
    async def cap_state(self, router_id: uuid.UUID, day: date) -> CapState: ...

    async def record_cap(self, **kwargs: Any) -> None: ...

    async def insert_records(self, rows: list[dict[str, Any]]) -> None: ...

    async def delete_records_before(self, cutoff: datetime, *, limit: int) -> int: ...


class FlowRecordWriter:
    """Ingest side. ``TrafficFlowIngestService`` calls :meth:`write_window`
    once for each window row it really inserted, so a re-pulled window adds
    no record.

    Writes nothing unless the platform switch is on AND the router's own
    export switch is on. Applies the daily cap; a cut is recorded, never
    silent."""

    def __init__(
        self,
        store: RecordStore,
        settings: Settings,
        *,
        enabled_router_ids: Callable[[], Any],
        platform: PlatformEndpoints = NO_PLATFORM_ENDPOINTS,
        ipdr_port_router_ids: Callable[[], Any] | None = None,
    ) -> None:
        self.store = store
        self.settings = settings
        #: The hub's tunnel endpoints: records to or from them are stored
        #: with ``direction = "platform"``.
        self.platform = platform
        self._enabled_router_ids = enabled_router_ids
        self._enabled: set[uuid.UUID] | None = None
        #: Routers whose export row has ``ipdr_ports`` on: venue-side ports
        #: are kept (NTP aside) whatever ``traffic_flow_record_merge_ports``.
        self._ipdr_port_router_ids = ipdr_port_router_ids
        self._keep_ports: set[uuid.UUID] | None = None

    async def _export_on(self, router_id: uuid.UUID) -> bool:
        if self._enabled is None:
            self._enabled = set(await self._enabled_router_ids())
        return router_id in self._enabled

    async def keeps_ports(self, router_id: uuid.UUID) -> bool:
        if self._ipdr_port_router_ids is None:
            return False
        if self._keep_ports is None:
            self._keep_ports = set(await self._ipdr_port_router_ids())
        return router_id in self._keep_ports

    async def write_window(
        self,
        identity: Mapping[str, Any],
        exporter: str,
        rows: Iterable[Mapping[str, Any]],
    ) -> int:
        """``rows``: the agent's per-flow rows for the window when it sends
        them, otherwise the rollup's rows (see the module docstring)."""
        if not getattr(self.settings, "traffic_flow_records_enabled", False):
            return 0
        router_id: uuid.UUID = identity["router_id"]
        if not await self._export_on(router_id):
            return 0
        received = flow_record_rows(rows, exporter, self.platform)
        if not received:
            return 0
        keep_ports = await self.keeps_ports(router_id)
        records, counts = prepare_records(
            received,
            store_internal=bool(
                getattr(self.settings, "traffic_flow_record_store_internal", False)
            ),
            merge_ports=not keep_ports
            and bool(getattr(self.settings, "traffic_flow_record_merge_ports", True)),
            summarised_ports=SUMMARISED_REMOTE_PORTS if keep_ports else frozenset(),
        )
        window_start: datetime = identity["window_start"]
        day = window_start.astimezone(UTC).date()
        # The cap counts rows as STORED (after merging, without internal
        # records): it guards the disk, and that is what takes the disk.
        cap = max(0, int(self.settings.traffic_flow_record_daily_cap))
        state = await self.store.cap_state(router_id, day)
        room = 0 if state.capped_at is not None else max(0, cap - state.rows_stored)
        # Largest flows first, so what a cut window keeps is its bulk.
        kept = records[:room]
        cut = len(records) - len(kept)
        if kept:
            await self.store.insert_records([{**identity, **row} for row in kept])
        await self.store.record_cap(
            router_id=router_id,
            location_id=identity.get("location_id"),
            day=day,
            stored=len(kept),
            not_stored=cut,
            capped_at=window_start if cut else None,
            received=counts.received,
            merged=counts.merged,
            internal=counts.internal,
        )
        if cut and state.capped_at is None:
            logger.warning(
                "traffic_flow_record_cap_reached",
                extra={
                    "router_id": str(router_id),
                    "day": day.isoformat(),
                    "cap": cap,
                    "window_start": window_start.isoformat(),
                },
            )
        return len(kept)

    async def prune(self, now: datetime) -> int:
        days = max(1, int(self.settings.traffic_flow_record_retention_days))
        return await self.store.delete_records_before(
            now - timedelta(days=days),
            limit=RETENTION_BATCH * FLOW_RECORD_RETENTION_FACTOR,
        )


# ---------------------------------------------------------------------------
# response
# ---------------------------------------------------------------------------


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FlowRecordOut(_Model):
    """One flow. ``null`` in any field means the collector did not record
    it; it is never an empty value and never zero."""

    #: The flow's own first and last packet, or null.
    start: str | None
    end: str | None
    #: When the collector received it (its own clock), or null.
    arrived_at: str | None
    #: The 5-minute collector window the record arrived in. Always present.
    window_start: str
    window_end: str
    src_address: str
    src_port: int | None
    dst_address: str
    dst_port: int | None
    protocol: int | None
    protocol_name: str | None
    #: Translated source and destination ("S. NAT" / "D. NAT"), or null.
    nat_src_address: str | None
    nat_src_port: int | None
    nat_dst_address: str | None
    nat_dst_port: int | None
    bytes: int
    packets: int | None
    #: Protocol and the outside end's port with its IANA label, e.g.
    #: "https (TCP/443)". A port label, never an inspected application.
    application: str | None
    direction: str
    #: "address:port" of the exporter, or the address alone.
    exporter: str
    router_id: str
    #: How many collector records this row stands for. 1 = one record.
    records_merged: int
    #: True: the merged records differed in the venue-side port, which is
    #: therefore null in this row. Show "several", not "not recorded".
    ports_merged: bool


class IncompleteStretch(_Model):
    router_id: str
    #: Records are incomplete from here ...
    since: str
    #: ... to here (the end of that UTC day).
    until: str
    records_not_stored: int


class RecordTotalsOut(_Model):
    bytes: int
    packets: int


class NotStoredOut(_Model):
    #: Both ends inside the venue (a device asking the router's DNS, router
    #: chatter). Left out by rule, not lost by accident.
    internal: int
    #: Rows the daily limit kept out (see ``incomplete``).
    daily_cap: int


class StorageOut(_Model):
    """What happened to the collector's records before the table: counts
    for the UTC days the range touches (counters are kept per day), so the
    screen can say how many were merged and how many were not stored, and
    why. ``records_received == rows_stored + records_merged +
    not_stored.internal + not_stored.daily_cap``."""

    #: First and last UTC day counted.
    from_day: str
    to_day: str
    records_received: int
    rows_stored: int
    #: Records folded into another row. Their bytes, packets and flows are
    #: in that row; nothing of them is lost but the separate line.
    records_merged: int
    not_stored: NotStoredOut
    #: The rules in force NOW (settings); earlier days may have differed.
    internal_records_stored: bool
    ports_merged: bool


class FiltersOut(_Model):
    address: str | None
    src_address: str | None
    dst_address: str | None
    port: int | None
    src_port: int | None
    dst_port: int | None
    protocol: int | None


class FlowRecordSearchResponse(_Model):
    feature_enabled: bool
    #: The flow-record switch (separate from the feature's own).
    records_enabled: bool
    location_id: str | None
    router_id: str | None
    since: str
    until: str
    window_seconds: int
    retention_days: int
    daily_cap: int
    data_oldest: str | None
    data_newest: str | None
    #: True when the daily cap stopped storage inside the range.
    incomplete: bool
    #: "Records incomplete since ...", or null.
    incomplete_message: str | None
    incomplete_stretches: list[IncompleteStretch]
    #: Fields that are null in every returned record: the collector does
    #: not supply them. Show "not recorded", never a dash that reads as none.
    fields_not_recorded: list[str]
    #: What one row is. Fixed text, so no screen has to guess.
    row_meaning: str
    storage: StorageOut
    filters: FiltersOut
    sort: str
    order: str
    limit: int
    total: int
    returned: int
    truncated: bool
    query_ms: int
    totals: RecordTotalsOut
    rows: list[FlowRecordOut]


RESPONSE_MODELS: tuple[type[BaseModel], ...] = (
    FlowRecordSearchResponse,
    FlowRecordOut,
    IncompleteStretch,
    RecordTotalsOut,
    FiltersOut,
    NotStoredOut,
    StorageOut,
)

ROW_MEANING = (
    "One row is the flow records the router exported in one 5-minute window "
    "for one source address, destination address, protocol and outside "
    "port, in one direction, added together. records_merged says how many "
    "records that is. Where they came from different ports on the venue "
    "side, that port is not kept (ports_merged). The two directions of a "
    "conversation are separate rows and are not paired. Records between two "
    "addresses inside the venue are not stored unless the platform is set "
    "to keep them; storage says how many were left out and why."
)

#: Fields that may be "not recorded", in table order.
OPTIONAL_FIELDS = (
    "start",
    "end",
    "src_port",
    "dst_port",
    "protocol",
    "nat_src_address",
    "nat_dst_address",
    "packets",
    "exporter_port",
)

CSV_COLUMNS = (
    "start",
    "end",
    "arrived_at",
    "window_start",
    "window_end",
    "src_address",
    "src_port",
    "dst_address",
    "dst_port",
    "protocol",
    "protocol_name",
    "nat_src_address",
    "nat_src_port",
    "nat_dst_address",
    "nat_dst_port",
    "bytes",
    "packets",
    "application",
    "direction",
    "exporter",
    "router_id",
    "records_merged",
    "ports_merged",
)


#: What a customer's file leaves out: the exporter is the platform's own
#: equipment address, never the venue's to see.
CUSTOMER_CSV_COLUMNS = tuple(name for name in CSV_COLUMNS if name != "exporter")
#: Response fields that are the platform's, not a customer's.
CUSTOMER_HIDDEN_FIELDS = frozenset({"feature_enabled", "records_enabled"})
CUSTOMER_HIDDEN_ROW_FIELDS = frozenset({"exporter"})


def _iso(moment: datetime | None) -> str | None:
    return moment.isoformat() if moment else None


def application_label(
    protocol: int | None, src_port: int | None, dst_port: int | None, direction: str
) -> str | None:
    """Protocol and the service port with its IANA label. The service port
    is the outside end's (the source's on a download, else the
    destination's). ``None`` when the protocol was not recorded."""
    if protocol is None:
        return None
    proto = protocol_name(protocol)
    shown = proto.upper() if proto != "other" else f"Protocol {protocol}"
    port = src_port if direction == DIRECTION_DOWN else dst_port
    if port is None or (port == 0 and proto not in {"tcp", "udp"}):
        return shown
    name = service_name(port)
    return f"{name} ({shown}/{port})" if name else f"{shown}/{port}"


def _record_out(row: Any) -> FlowRecordOut:
    window_end = row.window_start + timedelta(seconds=int(row.window_seconds))
    exporter = (
        f"{row.exporter_address}:{row.exporter_port}"
        if row.exporter_port is not None
        else str(row.exporter_address)
    )
    return FlowRecordOut(
        start=_iso(row.flow_start),
        end=_iso(row.flow_end),
        arrived_at=_iso(row.arrived_at),
        window_start=row.window_start.isoformat(),
        window_end=window_end.isoformat(),
        src_address=str(row.src_address),
        src_port=row.src_port,
        dst_address=str(row.dst_address),
        dst_port=row.dst_port,
        protocol=row.protocol,
        protocol_name=protocol_name(row.protocol) if row.protocol is not None else None,
        nat_src_address=str(row.nat_src_address) if row.nat_src_address else None,
        nat_src_port=row.nat_src_port,
        nat_dst_address=str(row.nat_dst_address) if row.nat_dst_address else None,
        nat_dst_port=row.nat_dst_port,
        bytes=int(row.bytes),
        packets=row.packets,
        application=application_label(
            row.protocol, row.src_port, row.dst_port, row.direction
        ),
        direction=row.direction,
        exporter=exporter,
        router_id=str(row.router_id),
        records_merged=int(getattr(row, "records_merged", 1) or 1),
        ports_merged=bool(getattr(row, "ports_merged", False)),
    )


def _not_recorded(rows: list[Any]) -> list[str]:
    """Optional fields that no returned record carries."""
    if not rows:
        return []
    column = {"start": "flow_start", "end": "flow_end"}

    def absent(row: Any, name: str) -> bool:
        if getattr(row, column.get(name, name)) is not None:
            return False
        # A port merged away is "several", which is not "not recorded".
        merged_port = name in {"src_port", "dst_port"} and getattr(
            row, "ports_merged", False
        )
        return not merged_port

    return [name for name in OPTIONAL_FIELDS if all(absent(row, name) for row in rows)]


def records_csv(rows: list[Any], columns: tuple[str, ...] = CSV_COLUMNS) -> str:
    """One line per record. An empty cell is "not recorded". Every cell is a
    timestamp, an address, a number or a name from a fixed table."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(columns)
    for row in rows:
        data = _record_out(row).model_dump()
        writer.writerow(["" if data[name] is None else data[name] for name in columns])
    return buffer.getvalue()


def _end_of_day(day: date) -> datetime:
    return datetime(day.year, day.month, day.day, tzinfo=UTC) + timedelta(days=1)


def incomplete_message(stretches: list[CappedDay]) -> str | None:
    if not stretches:
        return None
    first = min(s.capped_at for s in stretches)
    lost = sum(s.rows_not_stored for s in stretches)
    return (
        f"Records incomplete since {first.isoformat(timespec='minutes')}: the "
        f"daily limit on stored flow records was reached and {lost} row(s) "
        "in this range were not stored. Totals for the period are in the "
        "venue view, which is not affected."
    )


@dataclass(frozen=True, slots=True)
class CsvExport:
    text: str
    filename: str
    total: int
    rows: int
    truncated: bool
    incomplete_since: str | None


class AuditWriter(Protocol):
    async def create_audit_log_entry(self, **kwargs: Any) -> Any: ...


@dataclass(frozen=True, slots=True)
class _Request:
    target: RecordScopeTarget
    scope: FlowRecordScope
    filters: FlowRecordFilters
    sort: str
    order: str
    since: datetime
    until: datetime
    actor_user_id: uuid.UUID | None


class FlowRecordService:
    def __init__(
        self,
        repository: FlowRecordRepository,
        settings: Settings,
        *,
        audit_writer: AuditWriter,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.repository = repository
        self.settings = settings
        # Not optional: there is no unaudited way to read these records.
        self.audit_writer = audit_writer
        self.now = now

    @property
    def _retention_days(self) -> int:
        return max(1, int(self.settings.traffic_flow_record_retention_days))

    @property
    def _reading(self) -> bool:
        """Records are READ whenever the feature is on, even after the
        record switch is turned off again: what is held stays searchable
        until it ages out."""
        return bool(self.settings.traffic_flow_enabled)

    async def _prepare(
        self,
        *,
        location_id: uuid.UUID | None,
        router_id: uuid.UUID | None,
        since: datetime | None,
        until: datetime | None,
        actor_user_id: uuid.UUID | None,
        sort: str | None,
        order: str | None,
        organization_id: uuid.UUID | None = None,
        **filters: Any,
    ) -> _Request:
        if organization_id is not None and location_id is None:
            # A customer read is always about one venue. Fails closed.
            raise TrafficFlowError(
                "Venue not found.",
                code="TRAFFIC_FLOW_LOCATION_NOT_FOUND",
                status_code=status.HTTP_404_NOT_FOUND,
            )
        if location_id is None and router_id is None:
            raise TrafficFlowError(
                "Give a location_id or a router_id.",
                code="TRAFFIC_FLOW_SCOPE_REQUIRED",
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            )
        parsed = parse_flow_filters(**filters)
        sort_key, sort_order = _parse_sort(sort, order)
        start, end = resolve_record_range(
            since, until, now=self.now(), retention_days=self._retention_days
        )
        scope = FlowRecordScope(
            location_id=location_id,
            router_id=router_id,
            organization_id=organization_id,
            platform=(
                await platform_endpoints_of(self.repository, self.settings)
                if organization_id is not None and self._reading
                else NO_PLATFORM_ENDPOINTS
            ),
        )
        if organization_id is None:
            target = await self.repository.target(scope)
        else:
            # The VENUE decides whose this is. A router_id only narrows
            # inside it: it is never looked up, so a foreign router's
            # existence or organisation can neither leak nor be audited.
            venue = await self.repository.target(
                FlowRecordScope(location_id=location_id)
            )
            target = (
                RecordScopeTarget(location_id, router_id, organization_id)
                if venue is not None and venue.organization_id == organization_id
                else None
            )
        if target is None:
            raise TrafficFlowError(
                "Venue or router not found."
                if organization_id is None
                else "Venue not found.",
                code="TRAFFIC_FLOW_LOCATION_NOT_FOUND",
                status_code=status.HTTP_404_NOT_FOUND,
            )
        return _Request(
            target, scope, parsed, sort_key, sort_order, start, end, actor_user_id
        )

    async def _audit(
        self, request: _Request, *, action: str, what: str, row_count: int, **more: Any
    ) -> None:
        target = request.target
        entity = "location" if target.location_id else "router"
        entity_id = target.location_id or target.router_id
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=request.actor_user_id,
            action=action,
            entity_type=entity,
            entity_id=entity_id,
            description=(
                f"Traffic Lens flow record {what} for {entity} {entity_id}: "
                f"{row_count} record(s)"
            ),
            event_metadata={
                "console": ("customer" if request.scope.organization_id else "master"),
                "router_id": str(target.router_id) if target.router_id else None,
                "since": request.since.isoformat(),
                "until": request.until.isoformat(),
                "filters": request.filters.as_dict(),
                "sort": request.sort,
                "order": request.order,
                "row_count": row_count,
                **more,
            },
            organization_id=target.organization_id,
            location_id=target.location_id,
        )
        logger.info(
            action,
            extra={"entity_id": str(entity_id), "row_count": row_count},
        )

    async def search(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        router_id: uuid.UUID | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        sort: str | None = None,
        order: str | None = None,
        **filters: Any,
    ) -> FlowRecordSearchResponse:
        request = await self._prepare(
            location_id=location_id,
            router_id=router_id,
            since=since,
            until=until,
            actor_user_id=actor_user_id,
            sort=sort,
            order=order,
            **filters,
        )
        rows: list[Any] = []
        totals = RecordTotals()
        capped: list[CappedDay] = []
        counts = StorageCounts()
        oldest: datetime | None = None
        newest: datetime | None = None
        query_ms = 0
        if self._reading:
            where = {"since": request.since, "until": request.until}
            started = time.perf_counter()
            totals = await self.repository.totals(
                request.scope, request.filters, **where
            )
            rows = await self.repository.page(
                request.scope,
                request.filters,
                **where,
                sort=request.sort,
                order=request.order,
                limit=FLOW_RECORD_SEARCH_LIMIT,
            )
            query_ms = int((time.perf_counter() - started) * 1000)
            capped = await self.repository.capped_days(request.scope, **where)
            counts = await self.repository.storage_counts(request.scope, **where)
            oldest, newest = await self.repository.bounds(request.scope)
        await self._audit(
            request,
            action=AUDIT_ACTION_FLOW_RECORDS_SEARCHED,
            what="search",
            row_count=totals.count,
            returned=len(rows),
        )
        return FlowRecordSearchResponse(
            feature_enabled=bool(self.settings.traffic_flow_enabled),
            records_enabled=bool(self.settings.traffic_flow_records_enabled),
            location_id=str(location_id) if location_id else None,
            router_id=str(router_id) if router_id else None,
            since=request.since.isoformat(),
            until=request.until.isoformat(),
            window_seconds=WINDOW_SECONDS,
            retention_days=self._retention_days,
            daily_cap=int(self.settings.traffic_flow_record_daily_cap),
            data_oldest=_iso(oldest),
            data_newest=_iso(newest),
            incomplete=bool(capped),
            incomplete_message=incomplete_message(capped),
            incomplete_stretches=[
                IncompleteStretch(
                    router_id=str(day.router_id),
                    since=day.capped_at.isoformat(),
                    until=_end_of_day(day.day).isoformat(),
                    records_not_stored=day.rows_not_stored,
                )
                for day in capped
            ],
            fields_not_recorded=_not_recorded(rows),
            row_meaning=ROW_MEANING,
            storage=StorageOut(
                from_day=request.since.astimezone(UTC).date().isoformat(),
                to_day=(request.until - timedelta(microseconds=1))
                .astimezone(UTC)
                .date()
                .isoformat(),
                records_received=counts.received,
                rows_stored=counts.stored,
                records_merged=counts.merged,
                not_stored=NotStoredOut(
                    internal=counts.internal, daily_cap=counts.over_cap
                ),
                internal_records_stored=bool(
                    getattr(self.settings, "traffic_flow_record_store_internal", False)
                ),
                ports_merged=bool(
                    getattr(self.settings, "traffic_flow_record_merge_ports", True)
                ),
            ),
            filters=FiltersOut(**request.filters.as_dict()),
            sort=request.sort,
            order=request.order,
            limit=FLOW_RECORD_SEARCH_LIMIT,
            total=totals.count,
            returned=len(rows),
            truncated=totals.count > len(rows),
            query_ms=query_ms,
            totals=RecordTotalsOut(bytes=totals.bytes, packets=totals.packets),
            rows=[_record_out(row) for row in rows],
        )

    async def export_csv(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        router_id: uuid.UUID | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        sort: str | None = None,
        order: str | None = None,
        **filters: Any,
    ) -> CsvExport:
        request = await self._prepare(
            location_id=location_id,
            router_id=router_id,
            since=since,
            until=until,
            actor_user_id=actor_user_id,
            sort=sort,
            order=order,
            **filters,
        )
        rows: list[Any] = []
        total = 0
        capped: list[CappedDay] = []
        if self._reading:
            where = {"since": request.since, "until": request.until}
            total = (
                await self.repository.totals(request.scope, request.filters, **where)
            ).count
            if total:
                rows = await self.repository.page(
                    request.scope,
                    request.filters,
                    **where,
                    sort=request.sort,
                    order=request.order,
                    limit=FLOW_RECORD_CSV_MAX_ROWS,
                )
            capped = await self.repository.capped_days(request.scope, **where)
        await self._audit(
            request,
            action=AUDIT_ACTION_FLOW_RECORDS_EXPORTED,
            what="download",
            row_count=len(rows),
            total=total,
            truncated=total > len(rows),
        )
        stamp = "%Y%m%dT%H%MZ"
        return CsvExport(
            text=records_csv(
                rows,
                CUSTOMER_CSV_COLUMNS if request.scope.organization_id else CSV_COLUMNS,
            ),
            filename=(
                "traffic-lens-flows-"
                f"{request.since.astimezone(UTC).strftime(stamp)}-"
                f"{request.until.astimezone(UTC).strftime(stamp)}.csv"
            ),
            total=total,
            rows=len(rows),
            truncated=total > len(rows),
            incomplete_since=(
                min(day.capped_at for day in capped).isoformat() if capped else None
            ),
        )


# ---------------------------------------------------------------------------
# customer side
# ---------------------------------------------------------------------------


class VenueCheck(Protocol):
    """``TrafficFlowCustomerService.own_location``: the venue belongs to the
    caller's organisation and is one of the caller's own venues, or it
    raises (404 missing or foreign, 403 a sibling venue)."""

    async def own_location(
        self, location_id: uuid.UUID, organization_id: uuid.UUID
    ) -> uuid.UUID: ...


def customer_payload(response: FlowRecordSearchResponse) -> dict[str, Any]:
    """The search response as a customer receives it: without the
    platform's switches and without the exporter (platform equipment)."""
    data = response.model_dump(exclude=set(CUSTOMER_HIDDEN_FIELDS))
    data["rows"] = [
        {k: v for k, v in row.items() if k not in CUSTOMER_HIDDEN_ROW_FIELDS}
        for row in data["rows"]
    ]
    data["fields_not_recorded"] = [
        name for name in data["fields_not_recorded"] if name != "exporter_port"
    ]
    return data


class CustomerFlowRecordService:
    """Flow records for a customer caller: their own venue only.

    Fixed here, never passed by a route: the venue check (organisation and
    the caller's venue grants) before anything is read, the venue and the
    organisation on every statement, and the audit row naming the user and
    the venue. The add-on (``traffic_flow_records``) and the permission are
    the route's guards."""

    def __init__(self, records: FlowRecordService, venues: VenueCheck) -> None:
        self.records = records
        self.venues = venues

    async def _fixed(
        self, location_id: uuid.UUID, organization_id: uuid.UUID
    ) -> dict[str, Any]:
        return {
            "location_id": await self.venues.own_location(location_id, organization_id),
            "organization_id": organization_id,
        }

    async def search(
        self,
        location_id: uuid.UUID,
        *,
        organization_id: uuid.UUID,
        actor_user_id: uuid.UUID,
        **query: Any,
    ) -> dict[str, Any]:
        fixed = await self._fixed(location_id, organization_id)
        return customer_payload(
            await self.records.search(
                **{**query, **fixed, "actor_user_id": actor_user_id}
            )
        )

    async def export_csv(
        self,
        location_id: uuid.UUID,
        *,
        organization_id: uuid.UUID,
        actor_user_id: uuid.UUID,
        **query: Any,
    ) -> CsvExport:
        fixed = await self._fixed(location_id, organization_id)
        return await self.records.export_csv(
            **{**query, **fixed, "actor_user_id": actor_user_id}
        )
