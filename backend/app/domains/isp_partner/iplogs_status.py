"""IPLOGS-SELFSERVE: pure status rules for one router's IP logs.

Three pipes, each judged on what actually ARRIVED, never on what was meant:

* ``syslog``  -- the router's own syslog lines (``device_log_events``,
  source ``syslog``), attributed by the router's management address;
* ``flows``   -- connection records (``traffic_flow_records``);
* ``nat``     -- records carrying a translation (NAT source address or a NAT
  event), the rows the CGNAT lookup and LEA trace match on.

States of one pipe: ``receiving`` / ``silent`` (arrived once, not lately) /
``awaiting_first`` (set up, nothing yet) / ``not_set_up`` / ``collector_off``
(this server is not collecting that pipe at all -- said plainly, so an empty
IPDR page is never read as "the router is broken").

Every hint is in partner wording: "management connection", never the
technology behind it.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timedelta

RECEIVING = "receiving"
SILENT = "silent"
AWAITING_FIRST = "awaiting_first"
NOT_SET_UP = "not_set_up"
COLLECTOR_OFF = "collector_off"

#: Overall states (one per router card).
LOGS_ARRIVING = "logs_arriving"
WAITING = "waiting"
OVERALL_NOT_SET_UP = "not_set_up"
OFFLINE = "offline"
OVERALL_SILENT = "silent"
NEEDS_LINK = "needs_link"
NOT_SUPPORTED = "not_supported"
#: [POSTFIX-1] D12: at least one pipe arrives and another set-up pipe has
#: stopped or never started. Before this the card read "Logs arriving"
#: (green) as soon as ANY pipe arrived, so system logs alone hid that the
#: connection logs / NAT rows (what IPDR, CGNAT and LEA need) were not.
PARTIAL = "partial"

OVERALL_LABEL: dict[str, str] = {
    LOGS_ARRIVING: "Logs arriving",
    WAITING: "Set up, waiting for the first log line",
    OVERALL_NOT_SET_UP: "Not set up",
    OFFLINE: "Router offline",
    OVERALL_SILENT: "No logs lately",
    NEEDS_LINK: "Finish the setup script first",
    NOT_SUPPORTED: "Not supported on this device",
    PARTIAL: "Some logs are not arriving",
}

#: Partner names of the pipes, for the partial headline.
PIPE_LABEL: dict[str, str] = {
    "syslog": "System logs",
    "flows": "Connection logs",
    "nat": "NAT translations",
}
_LAGGING_WORD: dict[str, str] = {SILENT: "stopped", AWAITING_FIRST: "not arriving yet"}

SYSLOG_STALE = timedelta(minutes=60)
#: Flow windows close every 5 minutes and are pulled after a grace period.
FLOW_STALE = timedelta(minutes=20)

_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def pipe_state(
    *,
    collector_on: bool,
    set_up: bool,
    last_at: datetime | None,
    now: datetime,
    stale_after: timedelta,
) -> str:
    if not collector_on:
        return COLLECTOR_OFF
    if last_at is not None and now - last_at <= stale_after:
        return RECEIVING
    if last_at is not None:
        return SILENT
    return AWAITING_FIRST if set_up else NOT_SET_UP


def overall_state(
    *,
    blocker: str | None,
    router_online: bool,
    pipes: dict[str, str],
) -> str:
    if blocker == "not_mikrotik":
        return NOT_SUPPORTED
    states = set(pipes.values())
    if RECEIVING in states:
        return PARTIAL if lagging_pipes(pipes) else LOGS_ARRIVING
    if blocker == "needs_link":
        return NEEDS_LINK
    if not router_online:
        return OFFLINE
    if SILENT in states:
        return OVERALL_SILENT
    if AWAITING_FIRST in states:
        return WAITING
    return OVERALL_NOT_SET_UP


def lagging_pipes(pipes: dict[str, str]) -> list[str]:
    """Pipes that were set up but are not arriving (stopped, or never
    started), in card order. A pipe that is not set up or not collected on
    this server is not lagging: those have their own state and warning."""
    return [
        name
        for name in ("syslog", "flows", "nat")
        if pipes.get(name) in (SILENT, AWAITING_FIRST)
    ]


def state_label(overall: str, pipes: dict[str, str]) -> str:
    """The card headline. For ``partial`` it names the pipes that are not
    arriving ("Some logs are not arriving: Connection logs stopped, NAT
    translations stopped"), so a green card never hides a stopped pipe."""
    if overall != PARTIAL:
        return OVERALL_LABEL[overall]
    parts = [
        f"{PIPE_LABEL[name]} {_LAGGING_WORD[pipes[name]]}"
        for name in lagging_pipes(pipes)
    ]
    return f"{OVERALL_LABEL[PARTIAL]}: {', '.join(parts)}"


def is_non_public(address: str | None) -> bool:
    """Private, CGNAT (100.64/10), link-local or loopback: an address the
    internet never sees as this subscriber's."""
    if not address:
        return False
    try:
        ip = ipaddress.ip_address(str(address).split("/", 1)[0])
    except ValueError:
        return False
    return bool(
        ip.is_private
        or ip.is_link_local
        or ip.is_loopback
        or (ip.version == 4 and ip in _CGNAT)
    )


@dataclass(frozen=True)
class Warning_:
    code: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message}


def warnings_for(
    *,
    routeros_version: str | None,
    public_ip: str | None,
    translated_ips: list[str],
    clock_offset_seconds: float | None,
    tag_mismatch_lines: int,
    untagged_lines: int,
    flows_receiving: bool,
    nat_events_seen: bool,
    collector_flows_on: bool,
) -> list[dict[str, str]]:
    out: list[Warning_] = []
    major = (routeros_version or "").strip().split(".", 1)[0]
    if major.isdigit() and int(major) < 7:
        out.append(
            Warning_(
                "routeros_6",
                f"This router runs RouterOS {routeros_version}. System logs work, "
                "but connection logs (IPDR, CGNAT lookup) need RouterOS 7. "
                "Upgrade in System > Packages > Check For Updates.",
            )
        )
    private_translated = sorted({ip for ip in translated_ips if is_non_public(ip)})
    if private_translated:
        out.append(
            Warning_(
                "double_nat",
                "The translated address this router reports is private "
                f"({', '.join(private_translated[:3])}). The router sits behind "
                "another NAT device, usually the ISP modem, so IPDR and CGNAT "
                "lookups show that private address, not the public IP. Put the "
                "modem in bridge mode or give the router the public IP.",
            )
        )
    elif is_non_public(public_ip):
        out.append(
            Warning_(
                "double_nat",
                f"This router's internet address is private ({public_ip}). It "
                "probably sits behind the ISP modem, so IPDR would show a "
                "private translated address. Put the modem in bridge mode or "
                "give the router the public IP.",
            )
        )
    if clock_offset_seconds is not None and abs(clock_offset_seconds) > 120:
        minutes = round(abs(clock_offset_seconds) / 60)
        out.append(
            Warning_(
                "clock_off",
                f"The router's clock is off by about {minutes} min, so its log "
                "times are wrong. The IP logs script switches NTP on; check that "
                "outbound UDP 123 is not blocked.",
            )
        )
    if tag_mismatch_lines:
        out.append(
            Warning_(
                "tag_mismatch",
                f"{tag_mismatch_lines} log lines in the last 24 h came from this "
                "router's address with another router's tag, so they were not "
                "shown. Paste this router's IP logs script again.",
            )
        )
    if untagged_lines:
        out.append(
            Warning_(
                "untagged",
                f"{untagged_lines} log lines in the last hour arrived without the "
                "Wyfy tag. They are still matched by address; paste the IP logs "
                "script again to add the tag.",
            )
        )
    if not collector_flows_on:
        out.append(
            Warning_(
                "flows_not_collected",
                "Connection logs (IPDR, CGNAT lookup, LEA trace) are not being "
                "collected on this server yet. System logs still work. Ask Wyfy "
                "support to switch connection logs on.",
            )
        )
    elif flows_receiving and not nat_events_seen:
        out.append(
            Warning_(
                "no_nat_events",
                "Connections are arriving but without NAT events, so translated "
                "ports are derived, not reported. Upgrade RouterOS and paste the "
                "IP logs script again.",
            )
        )
    return [w.as_dict() for w in out]
