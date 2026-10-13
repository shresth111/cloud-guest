"""Venue-level findings: "is anything odd happening on my network".

Pure functions over rollups that already exist. No I/O, no new table, no
stored state, no notification: a finding is computed when it is read.

Five rules, always all five in the response, in this order. Each answers
one of ``flagged`` / ``clear`` / ``could_not_check`` (with a ``reason``),
never a formatted sentence: ``parts`` holds the pieces a screen puts into
its own words, ``evidence`` the numbers behind them, ``thresholds`` the
constants that decided.

## The privacy boundary

Everything here is about the venue. A finding names **at most one kind of
thing** (``names``): a device, by exactly the identity the top-devices list
already returns; or a destination address; or a service; or nothing. No
finding names a device and a destination together, because no stored row
pairs them and none is added here. ``DEVICE_KEYS`` and ``DESTINATION_KEYS``
are the vocabulary the tests hold every finding to.

Not built, because it would need the pairing: "which device talked to the
listed address", and "which device made the unusual upload". The rules say
that the venue did, and stop.

## Why the thresholds are what they are

A small cafe with three guests must not light up every day. So every
statistical rule has (a) a floor of traffic under which it says "not enough
traffic to judge", (b) an absolute size the flagged thing must reach, and
(c) a comparison with the venue's own retained days, which must be long
enough or the rule says so. The baseline is derived from the last
``BASELINE_DAYS`` days of the venue's own traffic; there is no opening-hours
setting, and every response says ``derived: true``.

Hours and days are UTC. An hour-of-day profile is as good on any clock; a
screen converts the instants it shows.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from enum import StrEnum
from statistics import median
from typing import Any

from .constants import (
    PROTOCOL_ICMP,
    PROTOCOL_ICMPV6,
    PROTOCOL_TCP,
    PROTOCOL_UDP,
    RETENTION_DAYS,
    WINDOW_SECONDS,
)
from .threat_list import ThreatList

__all__ = [
    "BASELINE_DAYS",
    "BASELINE_DAY_MIN_HOURS",
    "BASELINE_MIN_DAYS",
    "DESTINATION_KEYS",
    "DEVICE_KEYS",
    "DOMINANT_DEVICE_MIN_BYTES",
    "DOMINANT_DEVICE_MIN_DEVICES",
    "DOMINANT_DEVICE_SHARE",
    "FINDINGS_MIN_TRAFFIC_BYTES",
    "HOUR_MIN_WINDOWS",
    "KNOWN_BAD_ACT_BYTES",
    "KNOWN_BAD_MIN_BYTES",
    "ORDINARY_SERVICES",
    "QUIET_FACTOR",
    "QUIET_MIN_BYTES",
    "QUIET_MIN_DAYS",
    "QUIET_SHARE_OF_PEAK",
    "RULE_IDS",
    "UNUSUAL_NEW_MIN_PRIOR_DAYS",
    "UNUSUAL_NEW_SERVICE_SHARE",
    "UNUSUAL_SEEN_MIN_BYTES",
    "UNUSUAL_SERVICE_MIN_BYTES",
    "UNUSUAL_SERVICE_SHARE",
    "UNUSUAL_USUAL_DAYS",
    "UPLOAD_HEAVY_FACTOR",
    "UPLOAD_HEAVY_MIN_BYTES",
    "AddressRow",
    "FindingState",
    "HourRow",
    "Reason",
    "ServiceDay",
    "Severity",
    "build_findings",
    "dominant_device",
    "hour_start_of",
    "is_ordinary_service",
    "known_bad_destinations",
    "quiet_hours_traffic",
    "unusual_service",
    "unusual_service_candidates",
    "upload_heavy",
]

_MIB = 1024 * 1024
_GIB = 1024 * _MIB
_HOUR = 3600

# ---------------------------------------------------------------------------
# thresholds
# ---------------------------------------------------------------------------

#: Rules 1 to 4: with less client traffic than this in the period, a rule
#: says "not enough traffic to judge". (Rule 5 is a match, not a statistic.)
FINDINGS_MIN_TRAFFIC_BYTES = 200 * _MIB

#: The venue's own baseline: its retained days ending at the period's end.
BASELINE_DAYS = RETENTION_DAYS
#: A day counts towards the baseline when it has data in this many hours.
BASELINE_DAY_MIN_HOURS = 6
#: Fewer baseline days than this: "could not be checked", not "clear".
BASELINE_MIN_DAYS = 4
#: An hour counts in the hour-of-day profile when this many of its twelve
#: 5-minute windows arrived. A half-measured hour is not a quiet hour.
HOUR_MIN_WINDOWS = 10

#: Rule 1. An hour's upload is flagged at this many times the venue's
#: typical busiest upload hour (the median of its daily peaks) ...
UPLOAD_HEAVY_FACTOR = 3.0
#: ... and only when the hour's upload is at least this much.
UPLOAD_HEAVY_MIN_BYTES = 1 * _GIB

#: Rule 2. An hour of the day is "normally quiet" when, leaving out its
#: single busiest retained day, every other day's traffic in that hour was
#: at most this share of the venue's typical busiest hour ...
QUIET_SHARE_OF_PEAK = 0.05
#: ... over at least this many such days.
QUIET_MIN_DAYS = 4
#: Traffic in a normally quiet hour is flagged from this size ...
QUIET_MIN_BYTES = 500 * _MIB
#: ... when it is also this many times the most seen there on the other days.
QUIET_FACTOR = 5.0

#: Rule 3. The top device's share of the period's traffic ("at least": the
#: list is a lower bound) is flagged from here ...
DOMINANT_DEVICE_SHARE = 0.60
#: ... when at least this many devices were online at once (with three
#: guests, one of them having most of the traffic is an ordinary day) ...
DOMINANT_DEVICE_MIN_DEVICES = 5
#: ... and the period carried at least this much.
DOMINANT_DEVICE_MIN_BYTES = 1 * _GIB

#: Rule 4. A service outside ``ORDINARY_SERVICES`` that this venue does not
#: usually have is flagged from this share of the period's traffic ...
UNUSUAL_SERVICE_SHARE = 0.25
#: ... or from this share when it was never seen at the venue before ...
UNUSUAL_NEW_SERVICE_SHARE = 0.10
#: ... and only when the service carried at least this much.
UNUSUAL_SERVICE_MIN_BYTES = 500 * _MIB
#: "Usual for this venue": seen on at least this many retained days.
UNUSUAL_USUAL_DAYS = 3
#: A day counts as "seen" from this much traffic on the service.
UNUSUAL_SEEN_MIN_BYTES = 1 * _MIB
#: "New" needs this many measured days before the first sighting.
UNUSUAL_NEW_MIN_PRIOR_DAYS = 3

#: Rule 5. A listed address with less traffic than this is counted in
#: ``evidence.ignored_small`` and not flagged (a few stray packets).
KNOWN_BAD_MIN_BYTES = 10_000
#: From this much traffic to listed addresses the finding is ``act``.
KNOWN_BAD_ACT_BYTES = 1 * _MIB

#: Evidence rows listed per finding.
EVIDENCE_ITEMS = 5

#: Ordinary services, never "unusual": (protocol, outside port), or
#: (protocol, None) for a whole protocol. Deliberately short. Web, DNS,
#: QUIC, NTP, mail, the common VPN ports and the common calling ports.
ORDINARY_SERVICES: frozenset[tuple[int, int | None]] = frozenset(
    {
        # web and QUIC
        (PROTOCOL_TCP, 80),
        (PROTOCOL_TCP, 443),
        (PROTOCOL_TCP, 8080),
        (PROTOCOL_TCP, 8443),
        (PROTOCOL_UDP, 443),
        # DNS (plain, over TLS) and NTP
        (PROTOCOL_TCP, 53),
        (PROTOCOL_UDP, 53),
        (PROTOCOL_TCP, 853),
        (PROTOCOL_UDP, 853),
        (PROTOCOL_UDP, 123),
        # mail
        (PROTOCOL_TCP, 25),
        (PROTOCOL_TCP, 110),
        (PROTOCOL_TCP, 143),
        (PROTOCOL_TCP, 465),
        (PROTOCOL_TCP, 587),
        (PROTOCOL_TCP, 993),
        (PROTOCOL_TCP, 995),
        # common VPNs: IKE, IPsec NAT-T, OpenVPN, L2TP, PPTP, WireGuard,
        # and the tunnel protocols themselves (GRE, ESP, AH)
        (PROTOCOL_UDP, 500),
        (PROTOCOL_UDP, 4500),
        (PROTOCOL_UDP, 1194),
        (PROTOCOL_TCP, 1194),
        (PROTOCOL_UDP, 1701),
        (PROTOCOL_TCP, 1723),
        (PROTOCOL_UDP, 51820),
        (47, None),
        (50, None),
        (51, None),
        # calling and messaging: STUN/TURN, SIP, XMPP, push
        (PROTOCOL_UDP, 3478),
        (PROTOCOL_TCP, 3478),
        (PROTOCOL_UDP, 3479),
        (PROTOCOL_UDP, 3480),
        (PROTOCOL_UDP, 3481),
        (PROTOCOL_UDP, 5349),
        (PROTOCOL_TCP, 5349),
        (PROTOCOL_UDP, 5060),
        (PROTOCOL_TCP, 5060),
        (PROTOCOL_TCP, 5061),
        (PROTOCOL_TCP, 5222),
        (PROTOCOL_TCP, 5223),
        (PROTOCOL_TCP, 5228),
        (PROTOCOL_UDP, 19302),
        (PROTOCOL_UDP, 19305),
        (PROTOCOL_UDP, 8801),
        # ping
        (PROTOCOL_ICMP, None),
        (PROTOCOL_ICMPV6, None),
    }
)

#: Keys that identify a device, and keys that identify a destination. No
#: finding may carry one of each (module doc; asserted by the tests).
DEVICE_KEYS: frozenset[str] = frozenset(
    {"device", "ip", "router_id", "guest_session_id", "mac", "mac_address", "guest_id"}
)
DESTINATION_KEYS: frozenset[str] = frozenset(
    {"address", "remote_address", "destination", "list_entry"}
)


class FindingState(StrEnum):
    FLAGGED = "flagged"
    CLEAR = "clear"
    COULD_NOT_CHECK = "could_not_check"


class Severity(StrEnum):
    """``info``: worth knowing. ``look``: worth a look. ``act``: do
    something. Only a flagged finding has one."""

    INFO = "info"
    LOOK = "look"
    ACT = "act"


class Reason(StrEnum):
    """Why a rule could not be checked. A stable code; the screen words it."""

    FEATURE_OFF = "feature_off"
    NOT_MEASURED = "not_measured"
    NOT_ENOUGH_TRAFFIC = "not_enough_traffic"
    BASELINE_TOO_SHORT = "baseline_too_short"
    NO_QUIET_HOURS = "no_quiet_hours"
    TOO_FEW_DEVICES = "too_few_devices"
    NO_DEVICE_LIST = "no_device_list"
    SERVICES_NOT_MEASURED = "services_not_measured"
    DESTINATIONS_NOT_MEASURED = "destinations_not_measured"
    LIST_UNAVAILABLE = "list_unavailable"
    LIST_STALE = "list_stale"
    WITHHELD_SMALL_VENUE = "withheld_small_venue"


RULE_UPLOAD_HEAVY = "upload_heavy"
RULE_QUIET_HOURS = "quiet_hours_traffic"
RULE_DOMINANT_DEVICE = "dominant_device"
RULE_UNUSUAL_SERVICE = "unusual_service"
RULE_KNOWN_BAD = "known_bad_destinations"

#: The response's order.
RULE_IDS: tuple[str, ...] = (
    RULE_UPLOAD_HEAVY,
    RULE_QUIET_HOURS,
    RULE_DOMINANT_DEVICE,
    RULE_UNUSUAL_SERVICE,
    RULE_KNOWN_BAD,
)

#: What kind of thing each rule may name. Fixed per rule, not per result.
_NAMES: dict[str, str] = {
    RULE_UPLOAD_HEAVY: "nothing",
    RULE_QUIET_HOURS: "nothing",
    RULE_DOMINANT_DEVICE: "device",
    RULE_UNUSUAL_SERVICE: "service",
    RULE_KNOWN_BAD: "destination",
}


# ---------------------------------------------------------------------------
# inputs
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class HourRow:
    """The venue's client traffic in one UTC hour, summed from its windows.
    ``windows`` is how many distinct 5-minute windows arrived in the hour
    (0 to 12), ``windows_measured`` how many of them carried service data.
    No address of any kind."""

    start: datetime
    bytes_up: int
    bytes_down: int
    windows: int
    windows_measured: int = 0

    @property
    def bytes(self) -> int:
        return self.bytes_up + self.bytes_down


@dataclass(frozen=True, slots=True)
class ServiceDay:
    """One service's traffic at the venue on one UTC day. No address."""

    day: date
    protocol: int
    port: int
    bytes: int


@dataclass(frozen=True, slots=True)
class AddressRow:
    """One outside address's traffic at the venue over the period, summed
    from destination buckets. Venue-level: there is no device in the table
    it comes from."""

    address: str
    bytes_up: int
    bytes_down: int
    flows: int
    windows: int

    @property
    def bytes(self) -> int:
        return self.bytes_up + self.bytes_down


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def hour_start_of(moment: datetime) -> datetime:
    epoch = int(moment.timestamp())
    return datetime.fromtimestamp(epoch - epoch % _HOUR, tz=UTC)


def is_ordinary_service(protocol: int, port: int) -> bool:
    return (protocol, port) in ORDINARY_SERVICES or (
        protocol,
        None,
    ) in ORDINARY_SERVICES


def _finding(
    rule_id: str,
    state: FindingState,
    *,
    reason: Reason | None = None,
    severity: Severity | None = None,
    parts: Mapping[str, Any] | None = None,
    evidence: Mapping[str, Any] | None = None,
    thresholds: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "id": rule_id,
        "state": state.value,
        "reason": reason.value if reason else None,
        "severity": severity.value
        if severity and state is FindingState.FLAGGED
        else None,
        "names": _NAMES[rule_id],
        "parts": dict(parts) if parts and state is FindingState.FLAGGED else None,
        "evidence": dict(evidence or {}),
        "thresholds": dict(thresholds),
    }


def _period_hours(
    hours: Sequence[HourRow], since: datetime, until: datetime
) -> list[HourRow]:
    """The hours that touch the period. An hour is judged whole, so the
    first one may begin up to an hour before ``since``; evidence gives each
    hour's own start and end."""
    first = hour_start_of(since)
    return [h for h in hours if first <= h.start < until]


def _baseline_days(hours: Sequence[HourRow]) -> dict[date, list[HourRow]]:
    """Days with enough hours of data to speak for a day."""
    by_day: dict[date, list[HourRow]] = {}
    for hour in hours:
        by_day.setdefault(hour.start.date(), []).append(hour)
    return {
        day: rows for day, rows in by_day.items() if len(rows) >= BASELINE_DAY_MIN_HOURS
    }


def _hour_item(hour: HourRow) -> dict[str, Any]:
    return {
        "start": hour.start.isoformat(),
        "end": (hour.start + timedelta(seconds=_HOUR)).isoformat(),
        "bytes_up": hour.bytes_up,
        "bytes_down": hour.bytes_down,
        "bytes": hour.bytes,
    }


# ---------------------------------------------------------------------------
# rule 1: upload-heavy hour
# ---------------------------------------------------------------------------

_UPLOAD_THRESHOLDS: dict[str, Any] = {
    "min_period_bytes": FINDINGS_MIN_TRAFFIC_BYTES,
    "min_upload_bytes": UPLOAD_HEAVY_MIN_BYTES,
    "times_typical": UPLOAD_HEAVY_FACTOR,
    "baseline_min_days": BASELINE_MIN_DAYS,
}


def upload_heavy(
    hours: Sequence[HourRow], *, since: datetime, until: datetime
) -> dict[str, Any]:
    """An hour whose upload is far above the venue's own typical busiest
    upload hour. Possible causes a screen may list: a backup, a large file
    being sent, a device seeding files, data leaving that should not. It
    names no device and no destination."""
    period = _period_hours(hours, since, until)
    if not period:
        return _finding(
            RULE_UPLOAD_HEAVY,
            FindingState.COULD_NOT_CHECK,
            reason=Reason.NOT_MEASURED,
            thresholds=_UPLOAD_THRESHOLDS,
        )
    period_bytes = sum(h.bytes for h in period)
    days = _baseline_days(hours)
    evidence: dict[str, Any] = {
        "period_bytes": period_bytes,
        "period_bytes_up": sum(h.bytes_up for h in period),
        "baseline_days": len(days),
        "derived": True,
    }
    if period_bytes < FINDINGS_MIN_TRAFFIC_BYTES:
        return _finding(
            RULE_UPLOAD_HEAVY,
            FindingState.COULD_NOT_CHECK,
            reason=Reason.NOT_ENOUGH_TRAFFIC,
            evidence=evidence,
            thresholds=_UPLOAD_THRESHOLDS,
        )
    if len(days) < BASELINE_MIN_DAYS:
        return _finding(
            RULE_UPLOAD_HEAVY,
            FindingState.COULD_NOT_CHECK,
            reason=Reason.BASELINE_TOO_SHORT,
            evidence=evidence,
            thresholds=_UPLOAD_THRESHOLDS,
        )
    typical = int(median(max(h.bytes_up for h in rows) for rows in days.values()))
    evidence["typical_busiest_hour_bytes_up"] = typical
    bar = max(UPLOAD_HEAVY_MIN_BYTES, UPLOAD_HEAVY_FACTOR * typical)
    flagged = sorted(
        (h for h in period if h.bytes_up >= bar),
        key=lambda h: (-h.bytes_up, h.start),
    )
    evidence["hours_checked"] = len(period)
    evidence["hours_flagged"] = len(flagged)
    if not flagged:
        evidence["busiest_hour_bytes_up"] = max(h.bytes_up for h in period)
        return _finding(
            RULE_UPLOAD_HEAVY,
            FindingState.CLEAR,
            evidence=evidence,
            thresholds=_UPLOAD_THRESHOLDS,
        )

    def _times(hour: HourRow) -> float | None:
        return round(hour.bytes_up / typical, 1) if typical > 0 else None

    evidence["items"] = [
        {**_hour_item(h), "times_typical": _times(h)} for h in flagged[:EVIDENCE_ITEMS]
    ]
    top = flagged[0]
    return _finding(
        RULE_UPLOAD_HEAVY,
        FindingState.FLAGGED,
        severity=Severity.LOOK,
        parts={
            "start": top.start.isoformat(),
            "end": (top.start + timedelta(seconds=_HOUR)).isoformat(),
            "bytes_up": top.bytes_up,
            "typical_bytes_up": typical,
            "times_typical": _times(top),
            "hours": len(flagged),
        },
        evidence=evidence,
        thresholds=_UPLOAD_THRESHOLDS,
    )


# ---------------------------------------------------------------------------
# rule 2: traffic while the venue is normally quiet
# ---------------------------------------------------------------------------

_QUIET_THRESHOLDS: dict[str, Any] = {
    "min_period_bytes": FINDINGS_MIN_TRAFFIC_BYTES,
    "min_bytes": QUIET_MIN_BYTES,
    "times_usual": QUIET_FACTOR,
    "quiet_share_of_busiest_hour": QUIET_SHARE_OF_PEAK,
    "quiet_min_days": QUIET_MIN_DAYS,
    "baseline_min_days": BASELINE_MIN_DAYS,
}


def _quiet_profile(
    hours: Sequence[HourRow], typical_peak: int
) -> tuple[dict[int, int], bool]:
    """Hour of day (UTC) -> the most traffic seen there on a normal day, for
    the hours that are normally quiet. Also: did any hour of the day have
    enough days to be judged at all.

    "Normally" leaves out each hour's single busiest day, so one odd night
    does not stop that hour from being quiet -- it is the night to flag."""
    by_hour: dict[int, list[int]] = {}
    for hour in hours:
        if hour.windows >= HOUR_MIN_WINDOWS:
            by_hour.setdefault(hour.start.hour, []).append(hour.bytes)
    quiet: dict[int, int] = {}
    judged = False
    for hour_of_day, values in by_hour.items():
        rest = sorted(values)[:-1]
        if len(rest) < QUIET_MIN_DAYS:
            continue
        judged = True
        if rest[-1] <= QUIET_SHARE_OF_PEAK * typical_peak:
            quiet[hour_of_day] = rest[-1]
    return quiet, judged


def quiet_hours_traffic(
    hours: Sequence[HourRow], *, since: datetime, until: datetime
) -> dict[str, Any]:
    """Traffic in an hour of the day when this venue is normally quiet.
    The quiet hours are derived from the venue's own retained days; there is
    no opening-hours setting. Names no device and no destination."""
    period = _period_hours(hours, since, until)
    if not period:
        return _finding(
            RULE_QUIET_HOURS,
            FindingState.COULD_NOT_CHECK,
            reason=Reason.NOT_MEASURED,
            thresholds=_QUIET_THRESHOLDS,
        )
    period_bytes = sum(h.bytes for h in period)
    days = _baseline_days(hours)
    evidence: dict[str, Any] = {
        "period_bytes": period_bytes,
        "baseline_days": len(days),
        "derived": True,
    }
    if period_bytes < FINDINGS_MIN_TRAFFIC_BYTES:
        return _finding(
            RULE_QUIET_HOURS,
            FindingState.COULD_NOT_CHECK,
            reason=Reason.NOT_ENOUGH_TRAFFIC,
            evidence=evidence,
            thresholds=_QUIET_THRESHOLDS,
        )
    if len(days) < BASELINE_MIN_DAYS:
        return _finding(
            RULE_QUIET_HOURS,
            FindingState.COULD_NOT_CHECK,
            reason=Reason.BASELINE_TOO_SHORT,
            evidence=evidence,
            thresholds=_QUIET_THRESHOLDS,
        )
    typical_peak = int(median(max(h.bytes for h in rows) for rows in days.values()))
    quiet, judged = _quiet_profile(hours, typical_peak)
    evidence["typical_busiest_hour_bytes"] = typical_peak
    evidence["quiet_hours_utc"] = sorted(quiet)
    if not judged:
        return _finding(
            RULE_QUIET_HOURS,
            FindingState.COULD_NOT_CHECK,
            reason=Reason.BASELINE_TOO_SHORT,
            evidence=evidence,
            thresholds=_QUIET_THRESHOLDS,
        )
    if not quiet:
        # A venue that is busy round the clock has no quiet time to watch.
        return _finding(
            RULE_QUIET_HOURS,
            FindingState.COULD_NOT_CHECK,
            reason=Reason.NO_QUIET_HOURS,
            evidence=evidence,
            thresholds=_QUIET_THRESHOLDS,
        )
    in_quiet = [h for h in period if h.start.hour in quiet]
    flagged = sorted(
        (
            h
            for h in in_quiet
            if h.bytes >= QUIET_MIN_BYTES
            and h.bytes >= QUIET_FACTOR * quiet[h.start.hour]
        ),
        key=lambda h: (-h.bytes, h.start),
    )
    evidence["quiet_hours_in_period"] = len(in_quiet)
    evidence["hours_flagged"] = len(flagged)
    if not flagged:
        return _finding(
            RULE_QUIET_HOURS,
            FindingState.CLEAR,
            evidence=evidence,
            thresholds=_QUIET_THRESHOLDS,
        )
    evidence["items"] = [
        {**_hour_item(h), "usual_at_most_bytes": quiet[h.start.hour]}
        for h in flagged[:EVIDENCE_ITEMS]
    ]
    top = flagged[0]
    return _finding(
        RULE_QUIET_HOURS,
        FindingState.FLAGGED,
        severity=Severity.LOOK,
        parts={
            "start": top.start.isoformat(),
            "end": (top.start + timedelta(seconds=_HOUR)).isoformat(),
            "bytes": top.bytes,
            "usual_at_most_bytes": quiet[top.start.hour],
            "hours": len(flagged),
            "baseline_days": len(days),
        },
        evidence=evidence,
        thresholds=_QUIET_THRESHOLDS,
    )


# ---------------------------------------------------------------------------
# rule 3: one device dominating
# ---------------------------------------------------------------------------

_DEVICE_THRESHOLDS: dict[str, Any] = {
    "min_period_bytes": DOMINANT_DEVICE_MIN_BYTES,
    "share": DOMINANT_DEVICE_SHARE,
    "min_devices": DOMINANT_DEVICE_MIN_DEVICES,
}

#: The device identity, exactly as the top-devices list returns it to a
#: customer (``service._CUSTOMER_DEVICE_FIELDS`` minus the volumes).
_DEVICE_IDENTITY = ("router_id", "ip", "match", "guest_session_id")


def dominant_device(summary: Mapping[str, Any]) -> dict[str, Any]:
    """The top device's share of the period, from the summary's existing
    lower-bound device list -- the same figure and the same "at least".
    ``summary`` is ``build_summary``'s output. Names a device; no
    destination and no service appear in this finding."""
    totals = summary.get("totals")
    if not summary.get("measured") or not totals:
        return _finding(
            RULE_DOMINANT_DEVICE,
            FindingState.COULD_NOT_CHECK,
            reason=Reason.NOT_MEASURED,
            thresholds=_DEVICE_THRESHOLDS,
        )
    period_bytes = int(totals["bytes_up"]) + int(totals["bytes_down"])
    devices_peak = int(totals.get("devices_peak") or 0)
    evidence: dict[str, Any] = {
        "period_bytes": period_bytes,
        "devices_at_once": devices_peak,
        "lower_bound": True,
    }
    if period_bytes < DOMINANT_DEVICE_MIN_BYTES:
        return _finding(
            RULE_DOMINANT_DEVICE,
            FindingState.COULD_NOT_CHECK,
            reason=Reason.NOT_ENOUGH_TRAFFIC,
            evidence=evidence,
            thresholds=_DEVICE_THRESHOLDS,
        )
    if devices_peak < DOMINANT_DEVICE_MIN_DEVICES:
        return _finding(
            RULE_DOMINANT_DEVICE,
            FindingState.COULD_NOT_CHECK,
            reason=Reason.TOO_FEW_DEVICES,
            evidence=evidence,
            thresholds=_DEVICE_THRESHOLDS,
        )
    items = (summary.get("devices") or {}).get("items") or []
    if not items:
        return _finding(
            RULE_DOMINANT_DEVICE,
            FindingState.COULD_NOT_CHECK,
            reason=Reason.NO_DEVICE_LIST,
            evidence=evidence,
            thresholds=_DEVICE_THRESHOLDS,
        )
    top = items[0]
    share = float(top.get("share_at_least") or 0.0)
    evidence["top_share_at_least"] = share
    evidence["top_bytes_at_least"] = int(top.get("bytes") or 0)
    if share < DOMINANT_DEVICE_SHARE:
        return _finding(
            RULE_DOMINANT_DEVICE,
            FindingState.CLEAR,
            evidence=evidence,
            thresholds=_DEVICE_THRESHOLDS,
        )
    return _finding(
        RULE_DOMINANT_DEVICE,
        FindingState.FLAGGED,
        severity=Severity.INFO,
        parts={
            "share_at_least": share,
            "bytes_at_least": int(top.get("bytes") or 0),
            "device": {key: top.get(key) for key in _DEVICE_IDENTITY},
        },
        evidence=evidence,
        thresholds=_DEVICE_THRESHOLDS,
    )


# ---------------------------------------------------------------------------
# rule 4: a service that is unusual for this venue
# ---------------------------------------------------------------------------

_SERVICE_THRESHOLDS: dict[str, Any] = {
    "min_period_bytes": FINDINGS_MIN_TRAFFIC_BYTES,
    "min_service_bytes": UNUSUAL_SERVICE_MIN_BYTES,
    "share": UNUSUAL_SERVICE_SHARE,
    "share_when_new": UNUSUAL_NEW_SERVICE_SHARE,
    "usual_days": UNUSUAL_USUAL_DAYS,
    "new_min_prior_days": UNUSUAL_NEW_MIN_PRIOR_DAYS,
    "baseline_min_days": BASELINE_MIN_DAYS,
}


def unusual_service_candidates(summary: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Services of the period that are big enough and not ordinary: the
    only ones whose history is worth reading."""
    items = (summary.get("services") or {}).get("items") or []
    return [
        item
        for item in items
        if not is_ordinary_service(int(item["protocol"]), int(item["port"]))
        and int(item["bytes"]) >= UNUSUAL_SERVICE_MIN_BYTES
        and float(item["share"]) >= UNUSUAL_NEW_SERVICE_SHARE
    ]


def _measured_days(hours: Sequence[HourRow]) -> list[date]:
    """Days on which services were recorded in enough hours."""
    by_day: dict[date, int] = {}
    for hour in hours:
        if hour.windows_measured > 0:
            by_day[hour.start.date()] = by_day.get(hour.start.date(), 0) + 1
    return sorted(d for d, n in by_day.items() if n >= BASELINE_DAY_MIN_HOURS)


def unusual_service(
    summary: Mapping[str, Any],
    history: Sequence[ServiceDay],
    hours: Sequence[HourRow],
) -> dict[str, Any]:
    """A protocol and port, outside the short list of ordinary services,
    that is new for this venue or carries a large share without being usual
    here. "Unusual for this venue" -- never "malicious": a port is a label,
    not an application. ``history`` is the candidates' traffic per retained
    day. Names a service; no device and no destination."""
    totals = summary.get("totals")
    if not summary.get("measured") or not totals:
        return _finding(
            RULE_UNUSUAL_SERVICE,
            FindingState.COULD_NOT_CHECK,
            reason=Reason.NOT_MEASURED,
            thresholds=_SERVICE_THRESHOLDS,
        )
    services = summary.get("services") or {}
    period_bytes = int(totals["bytes_up"]) + int(totals["bytes_down"])
    evidence: dict[str, Any] = {
        "period_bytes": period_bytes,
        "windows": int(summary.get("windows") or 0),
        "windows_measured": int(services.get("windows_measured") or 0),
        "derived": True,
    }
    if not evidence["windows_measured"]:
        return _finding(
            RULE_UNUSUAL_SERVICE,
            FindingState.COULD_NOT_CHECK,
            reason=Reason.SERVICES_NOT_MEASURED,
            evidence=evidence,
            thresholds=_SERVICE_THRESHOLDS,
        )
    if period_bytes < FINDINGS_MIN_TRAFFIC_BYTES:
        return _finding(
            RULE_UNUSUAL_SERVICE,
            FindingState.COULD_NOT_CHECK,
            reason=Reason.NOT_ENOUGH_TRAFFIC,
            evidence=evidence,
            thresholds=_SERVICE_THRESHOLDS,
        )
    measured_days = _measured_days(hours)
    evidence["baseline_days"] = len(measured_days)
    if len(measured_days) < BASELINE_MIN_DAYS:
        return _finding(
            RULE_UNUSUAL_SERVICE,
            FindingState.COULD_NOT_CHECK,
            reason=Reason.BASELINE_TOO_SHORT,
            evidence=evidence,
            thresholds=_SERVICE_THRESHOLDS,
        )
    seen: dict[tuple[int, int], set[date]] = {}
    for row in history:
        if row.bytes >= UNUSUAL_SEEN_MIN_BYTES:
            seen.setdefault((row.protocol, row.port), set()).add(row.day)
    flagged: list[dict[str, Any]] = []
    for item in unusual_service_candidates(summary):
        key = (int(item["protocol"]), int(item["port"]))
        days_seen = seen.get(key, set())
        if len(days_seen) >= UNUSUAL_USUAL_DAYS:
            continue  # usual for this venue, whatever its share
        share = float(item["share"])
        first = min(days_seen) if days_seen else None
        prior = len([d for d in measured_days if first is None or d < first])
        new = first is not None and prior >= UNUSUAL_NEW_MIN_PRIOR_DAYS
        if share >= UNUSUAL_SERVICE_SHARE or new:
            flagged.append(
                {
                    "protocol": key[0],
                    "protocol_name": item.get("protocol_name"),
                    "port": key[1],
                    "service_name": item.get("service_name"),
                    "bytes": int(item["bytes"]),
                    "bytes_up": int(item.get("bytes_up") or 0),
                    "bytes_down": int(item.get("bytes_down") or 0),
                    "share": share,
                    "why": "new" if new else "large_share",
                    "days_seen": len(days_seen),
                    "first_seen_day": first.isoformat() if first else None,
                }
            )
    evidence["services_flagged"] = len(flagged)
    if not flagged:
        return _finding(
            RULE_UNUSUAL_SERVICE,
            FindingState.CLEAR,
            evidence=evidence,
            thresholds=_SERVICE_THRESHOLDS,
        )
    flagged.sort(key=lambda s: (-s["bytes"], s["protocol"], s["port"]))
    evidence["items"] = flagged[:EVIDENCE_ITEMS]
    top = flagged[0]
    return _finding(
        RULE_UNUSUAL_SERVICE,
        FindingState.FLAGGED,
        severity=Severity.LOOK,
        parts={
            "protocol": top["protocol"],
            "protocol_name": top["protocol_name"],
            "port": top["port"],
            "service_name": top["service_name"],
            "share": top["share"],
            "bytes": top["bytes"],
            "why": top["why"],
            "services": len(flagged),
            "baseline_days": len(measured_days),
        },
        evidence=evidence,
        thresholds=_SERVICE_THRESHOLDS,
    )


# ---------------------------------------------------------------------------
# rule 5: known-bad destinations
# ---------------------------------------------------------------------------

_KNOWN_BAD_THRESHOLDS: dict[str, Any] = {
    "min_address_bytes": KNOWN_BAD_MIN_BYTES,
    "act_bytes": KNOWN_BAD_ACT_BYTES,
}


def known_bad_destinations(
    rows: Sequence[AddressRow],
    threat: ThreatList,
    *,
    now: datetime,
    windows: int,
    windows_measured: int,
    windows_withheld: int = 0,
    min_devices: int = 0,
) -> dict[str, Any]:
    """The venue's outside addresses matched against the public list.
    ``rows`` already honour the small-venue rule when ``min_devices`` is
    set (windows with too few devices contributed nothing). Names
    destinations; there is no device in the rows, so none can appear."""
    described = threat.describe(now)
    evidence: dict[str, Any] = {
        "list": {
            "name": described["name"],
            "date": described["date"],
            "entries": described["entries"],
        },
        "windows": windows,
        "windows_measured": windows_measured,
        "lower_bound": True,
    }
    if min_devices > 0:
        evidence["min_devices"] = min_devices
        evidence["windows_withheld"] = windows_withheld

    def _cannot(reason: Reason) -> dict[str, Any]:
        return _finding(
            RULE_KNOWN_BAD,
            FindingState.COULD_NOT_CHECK,
            reason=reason,
            evidence=evidence,
            thresholds=_KNOWN_BAD_THRESHOLDS,
        )

    if not threat.available:
        return _cannot(Reason.LIST_UNAVAILABLE)
    if threat.is_stale(now):
        return _cannot(Reason.LIST_STALE)
    if windows <= 0:
        return _cannot(Reason.NOT_MEASURED)
    if windows_measured <= 0:
        return _cannot(Reason.DESTINATIONS_NOT_MEASURED)
    if min_devices > 0 and windows_withheld >= windows:
        # Every window had too few devices: the venue's destinations would
        # in effect be one person's. Not checked, and said so.
        return _cannot(Reason.WITHHELD_SMALL_VENUE)

    matched: list[dict[str, Any]] = []
    ignored = 0
    for row in rows:
        entry = threat.match(row.address)
        if entry is None:
            continue
        if row.bytes < KNOWN_BAD_MIN_BYTES:
            ignored += 1
            continue
        matched.append(
            {
                "address": row.address,
                "bytes_up": row.bytes_up,
                "bytes_down": row.bytes_down,
                "bytes": row.bytes,
                "flows": row.flows,
                "windows": row.windows,
                "list_entry": entry.cidr,
                "reference": entry.reference,
            }
        )
    evidence["addresses_checked"] = len(rows)
    evidence["addresses_matched"] = len(matched)
    evidence["ignored_small"] = ignored
    if not matched:
        return _finding(
            RULE_KNOWN_BAD,
            FindingState.CLEAR,
            evidence=evidence,
            thresholds=_KNOWN_BAD_THRESHOLDS,
        )
    matched.sort(key=lambda m: (-m["bytes"], m["address"]))
    total = sum(m["bytes"] for m in matched)
    evidence["matched_bytes"] = total
    evidence["items"] = matched[:EVIDENCE_ITEMS]
    top = matched[0]
    return _finding(
        RULE_KNOWN_BAD,
        FindingState.FLAGGED,
        severity=Severity.ACT if total >= KNOWN_BAD_ACT_BYTES else Severity.LOOK,
        parts={
            "addresses": len(matched),
            "bytes_at_least": total,
            "address": top["address"],
            "list_name": described["name"],
            "list_date": described["date"],
        },
        evidence=evidence,
        thresholds=_KNOWN_BAD_THRESHOLDS,
    )


# ---------------------------------------------------------------------------
# the response
# ---------------------------------------------------------------------------


def _all_could_not(reason: Reason) -> list[dict[str, Any]]:
    return [
        _finding(rule_id, FindingState.COULD_NOT_CHECK, reason=reason, thresholds={})
        for rule_id in RULE_IDS
    ]


def build_findings(
    *,
    feature_enabled: bool,
    location_id: str,
    summary: Mapping[str, Any] | None,
    hours: Sequence[HourRow],
    service_history: Sequence[ServiceDay],
    addresses: Sequence[AddressRow],
    threat: ThreatList,
    now: datetime,
    since: datetime,
    until: datetime,
    baseline_since: datetime,
    windows_measured: int = 0,
    windows_withheld: int = 0,
    min_devices: int = 0,
) -> dict[str, Any]:
    """The five findings for one venue and period. ``summary`` is
    ``build_summary``'s output for the same venue and period (``None`` when
    the platform switch is off and nothing was read)."""
    measured = bool(summary and summary.get("measured"))
    if not feature_enabled:
        findings = _all_could_not(Reason.FEATURE_OFF)
    elif not measured or summary is None:
        findings = _all_could_not(Reason.NOT_MEASURED)
    else:
        findings = [
            upload_heavy(hours, since=since, until=until),
            quiet_hours_traffic(hours, since=since, until=until),
            dominant_device(summary),
            unusual_service(summary, service_history, hours),
            known_bad_destinations(
                addresses,
                threat,
                now=now,
                windows=int(summary.get("windows") or 0),
                windows_measured=windows_measured,
                windows_withheld=windows_withheld,
                min_devices=min_devices,
            ),
        ]
    period = {"since": since.isoformat(), "until": until.isoformat()}
    for finding in findings:
        finding["period"] = dict(period)
    counts = {state.value: 0 for state in FindingState}
    for finding in findings:
        counts[finding["state"]] += 1
    out: dict[str, Any] = {
        "feature_enabled": feature_enabled,
        "location_id": location_id,
        "measured": measured,
        "since": period["since"],
        "until": period["until"],
        "window_seconds": WINDOW_SECONDS,
        "windows": int(summary.get("windows") or 0) if summary else 0,
        "data_oldest": summary.get("data_oldest") if summary else None,
        "data_newest": summary.get("data_newest") if summary else None,
        "baseline": {
            "since": baseline_since.isoformat(),
            "until": until.isoformat(),
            "days": BASELINE_DAYS,
            "derived": True,
            "timezone": "UTC",
        },
        "counts": counts,
        "findings": findings,
        "threat_list": threat.describe(now),
        "notifications": False,
    }
    if min_devices > 0:
        out["min_devices"] = min_devices
        out["windows_withheld"] = windows_withheld
    return out
