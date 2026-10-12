"""Pure assembly of the venue summary (``GET /platform/traffic-flow/summary``)
from stored windows and service buckets. No I/O.

Two kinds of figure come out of here, and they are not equally good:

* **Services, protocols and the timeline are exact.** They are plain sums of
  ``traffic_flow_service_buckets`` rows, where nothing was dropped (the rest
  of each window is an explicit "other" row per protocol).
* **Devices and destinations are lower bounds.** Each window stores only its
  top N of each, so an address that was just outside the top N in some
  window lost that window's bytes. The response says so in
  ``list_accuracy`` and in the field names (``share_at_least``,
  ``other_bytes_at_most``).

The three lists stay independent: nothing here joins a device to a
destination or to a service.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .constants import (
    IANA_SERVICE_NAMES,
    OTHER_SERVICE_PORT,
    PROTOCOL_BREAKDOWN_KEYS,
    PROTOCOL_ICMP,
    PROTOCOL_NAMES,
    PROTOCOL_TCP,
    PROTOCOL_UDP,
    TIMELINE_STEP_DEFAULT,
    TIMELINE_STEPS,
    TOP_N_STORED,
)

__all__ = [
    "ServiceStepRow",
    "build_summary",
    "empty_summary",
    "protocol_name",
    "service_key",
    "service_name",
    "step_start_of",
    "timeline_step_seconds",
]

_PROTOCOL_NUMBER_BY_KEY: dict[str, int | None] = {
    "tcp": PROTOCOL_TCP,
    "udp": PROTOCOL_UDP,
    "icmp": PROTOCOL_ICMP,
    "other": None,
}


@dataclass(frozen=True, slots=True)
class ServiceStepRow:
    """Service buckets summed into one timeline step by the database."""

    step_start: datetime
    protocol: int
    remote_port: int
    bytes_up: int
    bytes_down: int
    flows: int


def timeline_step_seconds(range_seconds: float) -> int:
    for limit, step in TIMELINE_STEPS:
        if range_seconds <= limit:
            return step
    return TIMELINE_STEP_DEFAULT


def step_start_of(moment: datetime, step_seconds: int) -> datetime:
    """Floor to the step on the epoch grid -- the same expression the
    repository groups service buckets by, so both sides agree."""
    epoch = int(moment.timestamp())
    return datetime.fromtimestamp(epoch - epoch % step_seconds, tz=UTC)


def protocol_name(protocol: int) -> str:
    return PROTOCOL_NAMES.get(protocol, "other")


def service_name(port: int) -> str | None:
    """IANA name for a port, or ``None``. A port label, never an
    application."""
    return IANA_SERVICE_NAMES.get(port)


def service_key(protocol: int, port: int) -> str:
    return f"{protocol}/{port}"


def _share(part: int, whole: int) -> float:
    return round(part / whole, 4) if whole > 0 else 0.0


def _bps(nbytes: int, seconds: int) -> int:
    return int(nbytes * 8 / seconds) if seconds > 0 else 0


def _iso(moment: datetime | None) -> str | None:
    return moment.isoformat() if moment else None


def _list_accuracy() -> dict[str, Any]:
    return {
        "method": "sum_of_per_window_top_n",
        "per_window_top_n": TOP_N_STORED,
        "lower_bound": True,
        "applies_to": ["devices", "destinations"],
    }


def empty_summary(
    *,
    feature_enabled: bool,
    since: datetime,
    until: datetime,
    window_seconds: int,
    step_seconds: int,
    data_oldest: datetime | None,
    data_newest: datetime | None,
) -> dict[str, Any]:
    """The ``measured: false`` shape: nothing was measured in the range, so
    there are no totals at all -- not totals of zero."""
    return {
        "feature_enabled": feature_enabled,
        "measured": False,
        "since": since.isoformat(),
        "until": until.isoformat(),
        "window_seconds": window_seconds,
        "step_seconds": step_seconds,
        "windows": 0,
        "data_oldest": _iso(data_oldest),
        "data_newest": _iso(data_newest),
        "totals": None,
        "services_measured": False,
        "services": {
            "exact": False,
            "windows_measured": 0,
            "items": [],
            "other_bytes": 0,
            "other_share": 0.0,
        },
        "protocols": [],
        "timeline": {"series": [], "steps": []},
        "list_accuracy": _list_accuracy(),
        "devices": {"items": [], "other_bytes_at_most": 0},
        "destinations": {"items": [], "other_bytes_at_most": 0},
    }


def _merge_devices(windows: Iterable[Any]) -> list[dict[str, Any]]:
    """Sum each device's appearances in the per-window top-N lists. Keyed on
    (router, address): the same private address at two routers is two
    devices. The guest match is kept only when it never changed."""
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for window in windows:
        router_id = str(window.router_id)
        for entry in window.top_talkers or []:
            ip = str(entry.get("ip"))
            item = merged.setdefault(
                (router_id, ip),
                {
                    "router_id": router_id,
                    "ip": ip,
                    "bytes_up": 0,
                    "bytes_down": 0,
                    "flows": 0,
                    "_sessions": set(),
                    "_matches": set(),
                },
            )
            item["bytes_up"] += int(entry.get("bytes_up") or 0)
            item["bytes_down"] += int(entry.get("bytes_down") or 0)
            item["flows"] += int(entry.get("flows") or 0)
            item["_matches"].add(str(entry.get("match") or "none"))
            if entry.get("guest_session_id"):
                item["_sessions"].add(str(entry["guest_session_id"]))
    out: list[dict[str, Any]] = []
    for item in merged.values():
        sessions = sorted(item.pop("_sessions"))
        matches = item.pop("_matches")
        if len(sessions) == 1 and matches == {"session"}:
            item["match"], item["guest_session_id"] = "session", sessions[0]
        elif sessions or "ambiguous" in matches:
            # Held by different sessions (or by a session only part of the
            # time) across the range: never pinned on one guest.
            item["match"], item["guest_session_id"] = "ambiguous", None
        else:
            item["match"], item["guest_session_id"] = "none", None
        item["bytes"] = item["bytes_up"] + item["bytes_down"]
        out.append(item)
    out.sort(key=lambda d: (-d["bytes"], d["router_id"], d["ip"]))
    return out


def _merge_destinations(windows: Iterable[Any]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for window in windows:
        for entry in window.top_destinations or []:
            ip = str(entry.get("ip"))
            item = merged.setdefault(
                ip, {"ip": ip, "bytes_up": 0, "bytes_down": 0, "bytes": 0, "flows": 0}
            )
            item["bytes"] += int(entry.get("bytes") or 0)
            item["bytes_up"] += int(entry.get("bytes_up") or 0)
            item["bytes_down"] += int(entry.get("bytes_down") or 0)
            item["flows"] += int(entry.get("flows") or 0)
    return sorted(merged.values(), key=lambda d: (-d["bytes"], d["ip"]))


def _lower_bound_list(
    items: list[dict[str, Any]], *, limit: int, client_bytes: int
) -> dict[str, Any]:
    shown = items[:limit]
    for item in shown:
        item["share_at_least"] = _share(item["bytes"], client_bytes)
    return {
        "items": shown,
        "other_bytes_at_most": max(client_bytes - sum(i["bytes"] for i in shown), 0),
    }


def _protocol_breakdown(by_key: Mapping[str, int]) -> list[dict[str, Any]]:
    whole = sum(by_key.values())
    return [
        {
            "protocol": _PROTOCOL_NUMBER_BY_KEY[key],
            "protocol_name": key,
            "bytes": int(by_key.get(key, 0)),
            "share": _share(int(by_key.get(key, 0)), whole),
        }
        for key in PROTOCOL_BREAKDOWN_KEYS
    ]


def build_summary(
    *,
    windows: Sequence[Any],
    service_rows: Sequence[ServiceStepRow],
    since: datetime,
    until: datetime,
    window_seconds: int,
    step_seconds: int,
    limit: int,
    series: int,
    data_oldest: datetime | None,
    data_newest: datetime | None,
) -> dict[str, Any]:
    """``windows`` are the stored windows in range (any object with the
    ``TrafficFlowWindow`` attributes); ``service_rows`` the service buckets
    of the same range already summed per timeline step."""
    if not windows:
        return empty_summary(
            feature_enabled=True,
            since=since,
            until=until,
            window_seconds=window_seconds,
            step_seconds=step_seconds,
            data_oldest=data_oldest,
            data_newest=data_newest,
        )

    # -- windows: totals and per-step coverage ------------------------------
    steps: dict[datetime, dict[str, Any]] = {}
    seconds_by_start: dict[datetime, int] = {}
    devices_by_start: dict[datetime, int] = {}
    destinations_by_start: dict[datetime, int] = {}
    totals = {
        "bytes_up": 0,
        "bytes_down": 0,
        "bytes_internal": 0,
        "bytes_unclassified": 0,
        "flows": 0,
    }
    windows_measured = 0
    for window in windows:
        up = int(window.bytes_up or 0)
        down = int(window.bytes_down or 0)
        totals["bytes_up"] += up
        totals["bytes_down"] += down
        totals["bytes_internal"] += int(window.bytes_internal or 0)
        totals["bytes_unclassified"] += int(window.bytes_unclassified or 0)
        totals["flows"] += int(window.flows_total or 0)
        measured = bool(window.services_measured)
        windows_measured += 1 if measured else 0
        start = window.window_start
        seconds_by_start[start] = int(window.window_seconds or window_seconds)
        devices_by_start[start] = devices_by_start.get(start, 0) + int(
            window.talker_count or 0
        )
        destinations_by_start[start] = destinations_by_start.get(start, 0) + int(
            window.destination_count or 0
        )
        step = steps.setdefault(
            step_start_of(start, step_seconds),
            {"bytes_up": 0, "bytes_down": 0, "starts": set(), "measured": True},
        )
        step["bytes_up"] += up
        step["bytes_down"] += down
        step["starts"].add(start)
        step["measured"] = step["measured"] and measured
    covered_seconds = sum(seconds_by_start.values())
    client_bytes = totals["bytes_up"] + totals["bytes_down"]

    # -- service buckets: exact sums ----------------------------------------
    by_service: dict[tuple[int, int], dict[str, int]] = {}
    protocol_bytes: dict[str, int] = dict.fromkeys(PROTOCOL_BREAKDOWN_KEYS, 0)
    step_services: dict[datetime, dict[tuple[int, int], int]] = {}
    step_protocols: dict[datetime, dict[str, int]] = {}
    service_bytes_total = 0
    for row in service_rows:
        nbytes = int(row.bytes_up) + int(row.bytes_down)
        service_bytes_total += nbytes
        name = protocol_name(row.protocol)
        protocol_bytes[name] += nbytes
        per_step = step_protocols.setdefault(
            row.step_start, dict.fromkeys(PROTOCOL_BREAKDOWN_KEYS, 0)
        )
        per_step[name] += nbytes
        if row.remote_port == OTHER_SERVICE_PORT:
            continue  # the folded remainder: counted, never listed
        key = (row.protocol, row.remote_port)
        item = by_service.setdefault(key, {"bytes_up": 0, "bytes_down": 0, "flows": 0})
        item["bytes_up"] += int(row.bytes_up)
        item["bytes_down"] += int(row.bytes_down)
        item["flows"] += int(row.flows)
        in_step = step_services.setdefault(row.step_start, {})
        in_step[key] = in_step.get(key, 0) + nbytes

    ranked = sorted(
        by_service.items(),
        key=lambda kv: (-(kv[1]["bytes_up"] + kv[1]["bytes_down"]), kv[0]),
    )

    def _describe(key: tuple[int, int]) -> dict[str, Any]:
        protocol, port = key
        return {
            "protocol": protocol,
            "protocol_name": protocol_name(protocol),
            "port": port,
            "service_name": service_name(port),
        }

    service_items = []
    for key, sums in ranked[:limit]:
        nbytes = sums["bytes_up"] + sums["bytes_down"]
        service_items.append(
            {
                **_describe(key),
                "bytes_up": sums["bytes_up"],
                "bytes_down": sums["bytes_down"],
                "bytes": nbytes,
                "flows": sums["flows"],
                "share": _share(nbytes, service_bytes_total),
                "avg_bps": _bps(nbytes, covered_seconds),
            }
        )
    services_other = max(
        service_bytes_total - sum(i["bytes"] for i in service_items), 0
    )
    all_measured = windows_measured == len(windows)

    # -- timeline -----------------------------------------------------------
    series_keys = [key for key, _sums in ranked[:series]]
    timeline_steps = []
    for start in sorted(steps):
        step = steps[start]
        covered = sum(seconds_by_start[s] for s in step["starts"])
        step_bytes = step["bytes_up"] + step["bytes_down"]
        if step["measured"]:
            in_step = step_services.get(start, {})
            services = {service_key(*key): in_step.get(key, 0) for key in series_keys}
            protocols: dict[str, int] | None = step_protocols.get(
                start, dict.fromkeys(PROTOCOL_BREAKDOWN_KEYS, 0)
            )
        else:
            # Not measured for (part of) this step: no bands, not zero bands.
            services, protocols = {}, None
        timeline_steps.append(
            {
                "start": start.isoformat(),
                "covered_seconds": covered,
                "bytes_up": step["bytes_up"],
                "bytes_down": step["bytes_down"],
                "bps_up": _bps(step["bytes_up"], covered),
                "bps_down": _bps(step["bytes_down"], covered),
                "services_measured": bool(step["measured"]),
                "services": services,
                "other_bytes": max(step_bytes - sum(services.values()), 0),
                "protocols": protocols,
            }
        )

    return {
        "feature_enabled": True,
        "measured": True,
        "since": since.isoformat(),
        "until": until.isoformat(),
        "window_seconds": window_seconds,
        "step_seconds": step_seconds,
        "windows": len(windows),
        "data_oldest": _iso(data_oldest),
        "data_newest": _iso(data_newest),
        "totals": {
            **totals,
            "covered_seconds": covered_seconds,
            "avg_bps_up": _bps(totals["bytes_up"], covered_seconds),
            "avg_bps_down": _bps(totals["bytes_down"], covered_seconds),
            "devices_peak": max(devices_by_start.values(), default=0),
            "destinations_peak": max(destinations_by_start.values(), default=0),
        },
        "services_measured": all_measured,
        "services": {
            "exact": all_measured,
            "windows_measured": windows_measured,
            "items": service_items,
            "other_bytes": services_other,
            "other_share": _share(services_other, service_bytes_total),
        },
        "protocols": _protocol_breakdown(protocol_bytes) if windows_measured else [],
        "timeline": {
            "series": [
                {"key": service_key(*key), **_describe(key)} for key in series_keys
            ],
            "steps": timeline_steps,
        },
        "list_accuracy": _list_accuracy(),
        "devices": _lower_bound_list(
            _merge_devices(windows), limit=limit, client_bytes=client_bytes
        ),
        "destinations": _lower_bound_list(
            _merge_destinations(windows), limit=limit, client_bytes=client_bytes
        ),
    }
