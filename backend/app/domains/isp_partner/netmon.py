"""NETMON-2 (ADDENDUM_06) pure helpers: WAN interface choice, series
downsampling, the "can't read this router" state and its fix hint.

Hints are partner-facing: they never name the management tunnel, WireGuard
or a VPN (QA-023). ``FORBIDDEN_HINT_WORDS`` is checked by the tests.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

RANGES: dict[str, timedelta] = {
    "day": timedelta(days=1),
    "week": timedelta(days=7),
    "month": timedelta(days=30),
}
MAX_POINTS = 120
#: A router silent for longer than this counts as offline.
OFFLINE_AFTER = timedelta(minutes=10)
FORBIDDEN_HINT_WORDS = ("tunnel", "wireguard", "wg0", "vpn", "peer")

#: Interface names that usually carry the uplink, most likely first.
_WAN_HINTS = ("wan", "pppoe-out", "lte", "ether1", "sfp1", "combo1")


def pick_wan(series: dict[str, list[dict[str, Any]]]) -> tuple[str | None, str]:
    """(interface, basis). No WAN role is stored for a router, so: a name
    that usually is the uplink, else the busiest interface."""
    if not series:
        return None, "none"
    names = {n.lower(): n for n in series}
    for hint in _WAN_HINTS:
        for low, real in names.items():
            if low == hint or low.startswith(hint):
                return real, "name"
    busiest = max(
        series,
        key=lambda n: sum(
            (p.get("in_mbps") or 0) + (p.get("out_mbps") or 0) for p in series[n]
        ),
    )
    return busiest, "busiest"


def downsample(
    points: list[dict[str, Any]], *, since: datetime, until: datetime
) -> list[dict]:
    """Average into at most MAX_POINTS equal buckets (in/out Mbps). Empty
    buckets are left out, so a polling gap shows as a gap, not a slope."""
    if not points:
        return []
    width = (until - since) / MAX_POINTS
    buckets: dict[int, list[dict[str, Any]]] = {}
    for p in points:
        at = datetime.fromisoformat(p["at"])
        at = at if at.tzinfo else at.replace(tzinfo=UTC)
        if at < since or at > until:
            continue
        i = min(MAX_POINTS - 1, int((at - since) / width))
        buckets.setdefault(i, []).append(p)
    out = []
    for i in sorted(buckets):
        ps = buckets[i]
        out.append(
            {
                "at": (since + width * i + width / 2).isoformat(),
                "in_mbps": round(sum(p["in_mbps"] for p in ps) / len(ps), 3),
                "out_mbps": round(sum(p["out_mbps"] for p in ps) / len(ps), 3),
            }
        )
    return out


def readability(
    *,
    status: str | None,
    last_seen_at: datetime | None,
    snmp_enabled: bool,
    snmp_last_poll_status: str | None,
    has_series: bool,
    now: datetime,
) -> tuple[bool, str | None, str | None]:
    """(readable, reason, hint)."""
    if status in ("pending_provisioning", "provisioning") or last_seen_at is None:
        return (
            False,
            "not_set_up",
            "This router has not finished setup. Open it and run the setup script, "
            "then check back in a few minutes.",
        )
    seen = last_seen_at if last_seen_at.tzinfo else last_seen_at.replace(tzinfo=UTC)
    if status == "offline" or now - seen > OFFLINE_AFTER:
        return (
            False,
            "offline",
            "The router has not reported recently. Check that it has power and an "
            "internet connection at the venue; it reappears here on its own once it "
            "is back.",
        )
    if not snmp_enabled:
        return (
            False,
            "monitoring_off",
            "Traffic history needs monitoring switched on for this router. Ask Wyfy "
            "Guest support to enable it, or open the router and use Read now for a "
            "live reading.",
        )
    if snmp_last_poll_status and snmp_last_poll_status not in ("ok", "success"):
        return (
            False,
            "poll_failed",
            "The last traffic reading failed. If the router was changed recently, "
            "re-run its setup script; otherwise wait for the next reading.",
        )
    if not has_series:
        return (
            True,
            "no_data_yet",
            "No traffic readings in this range yet.",
        )
    return True, None, None


__all__ = [
    "FORBIDDEN_HINT_WORDS",
    "MAX_POINTS",
    "RANGES",
    "downsample",
    "pick_wan",
    "readability",
]
