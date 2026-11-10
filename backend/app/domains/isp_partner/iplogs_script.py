"""IPLOGS-SELFSERVE: the one paste script that turns on IP logs on a MikroTik.

What the router needs for the ISP's IP logs (NetLogs, IPDR, CGNAT lookup,
LEA trace), in one script the ISP pastes AFTER the setup script:

1. a router name without spaces (a name with spaces breaks the syslog tag);
2. the clock on IST + NTP (log times are the router's own clock);
3. remote syslog to the platform's collector (``device_logs``);
4. ``/ip traffic-flow`` IPFIX export with the NAT fields and NAT events, to
   the platform's flow collector (``traffic_flow``), RouterOS 7 only.

The VALUES come from the two canonical modules and nowhere else:
``device_logs.routeros.desired_config`` (action + rules) and
``traffic_flow.routeros.desired_config`` (settings, IPFIX fields, target).
Only the RENDERING is new, for one reason measured on CHR (see the clock
chunk in the FE ``RouterDetailTabs.tsx``): RouterOS resolves property names
when it PARSES a line, not when it runs it. A console line that names
``bsd-syslog=`` fails on 7.18+ and one that names ``remote-log-format=`` fails
on older releases -- whichever branch of an ``:if`` would have run -- and an
``.rsc`` import is parsed whole, so one such line rejects the entire file.
Every version-dependent command is therefore a string compiled at run time
with ``[[:parse "..."]]`` inside ``:do {} on-error={}``, where a refusal IS
catchable. Commands every release understands stay literal.

Each line is a complete program on its own: the RouterOS terminal runs each
entered line separately, so no line relies on a ``:local`` set by another.

Interpolated values are only IP addresses, port numbers, the 8-hex tag and
the router name reduced to ``[A-Za-z0-9_-]``; all are validated here before
rendering. Nothing in the script names the management connection's
technology (partner wording rule).
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from dataclasses import dataclass

from app.domains.device_logs.constants import ROUTEROS_ACTION_NAME, ROUTEROS_TOPICS
from app.domains.device_logs.routeros import (
    RemoteLoggingConfig,
    modern_action_row,
)
from app.domains.device_logs.routeros import (
    desired_config as syslog_desired_config,
)
from app.domains.traffic_flow.routeros import (
    TrafficFlowTarget,
    target_identity,
)
from app.domains.traffic_flow.routeros import (
    desired_config as flow_desired_config,
)

__all__ = [
    "CLOCK_NTP_SERVERS",
    "CLOCK_TIME_ZONE",
    "IpLogsTargets",
    "deferred",
    "render_disable_script",
    "render_enable_script",
    "safe_identity",
]

#: Same values as the setup script's clock chunk (FE ``RouterDetailTabs``).
CLOCK_TIME_ZONE = "Asia/Kolkata"
CLOCK_NTP_SERVERS: tuple[str, str] = ("216.239.35.0", "162.159.200.1")

_V7 = '([:pick [/system resource get version] 0 2] = "7.")'
_NOT_V7 = '([:pick [/system resource get version] 0 2] != "7.")'
_SAFE = re.compile(r"[^A-Za-z0-9_-]+")


def safe_identity(name: str | None, router_id: uuid.UUID) -> str:
    """The router name reduced to ``[A-Za-z0-9_-]``, at most 32 chars; a
    name with nothing usable left becomes ``wyfy-<8 hex>``."""
    cleaned = _SAFE.sub("-", name or "").strip("-")[:32].strip("-")
    return cleaned or f"wyfy-{router_id.hex[:8]}"


def deferred(command: str) -> str:
    """``command`` compiled at run time: ``[[:parse "..."]]``. Escapes the
    three characters a RouterOS string treats specially; a ``?`` would open
    the terminal's help, so it is refused rather than escaped."""
    if "?" in command:
        raise ValueError("a RouterOS console line cannot carry '?'")
    body = command.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$")
    return f'[[:parse "{body}"]]'


def _args(row: dict[str, str]) -> str:
    return " ".join(f"{k}={v}" for k, v in row.items())


@dataclass(frozen=True)
class IpLogsTargets:
    """Where one router sends, validated. ``source_address`` is the router's
    own management-connection address: both collectors attribute a router by
    exactly that source address."""

    router_id: uuid.UUID
    router_name: str | None
    source_address: str
    syslog_host: str
    syslog_port: int
    flow_host: str
    flow_port: int

    def __post_init__(self) -> None:
        for value in (self.source_address, self.syslog_host, self.flow_host):
            ipaddress.ip_address(value)
        for port in (self.syslog_port, self.flow_port):
            if not 1 <= int(port) <= 65535:
                raise ValueError(f"port out of range: {port}")

    def syslog(self) -> RemoteLoggingConfig:
        return syslog_desired_config(
            router_id=self.router_id,
            tunnel_ip=self.source_address,
            remote_host=self.syslog_host,
            remote_port=int(self.syslog_port),
        )

    def flow_target(self) -> TrafficFlowTarget:
        return TrafficFlowTarget(
            collector_address=self.flow_host,
            collector_port=int(self.flow_port),
            source_address=self.source_address,
        )


def _v7_only(command: str) -> str:
    return f":if {_V7} do={{ {deferred(command)} }}"


def _identity_lines(t: IpLogsTargets) -> list[str]:
    name = safe_identity(t.router_name, t.router_id)
    return [
        "# 1. Router name: a name with spaces breaks the log tag, "
        "so spaces are replaced",
        ':if ([:typeof [:find [/system identity get name] " "]] != "nil") do={ '
        f'/system identity set name="{name}"; '
        f':put "  Router name had spaces, now: {name}" }}',
    ]


def _clock_lines() -> list[str]:
    servers = ",".join(CLOCK_NTP_SERVERS)
    v7 = deferred(f"/system ntp client set enabled=yes servers={servers}")
    v6 = deferred(
        "/system ntp client set enabled=yes "
        f"primary-ntp={CLOCK_NTP_SERVERS[0]} secondary-ntp={CLOCK_NTP_SERVERS[1]}"
    )
    return [
        "# 2. Clock: log times are the router's own clock",
        "/system clock set time-zone-autodetect=no "
        f"time-zone-name={CLOCK_TIME_ZONE}",
        f":do {{ {v7} }} on-error={{ :do {{ {v6} }} on-error={{ "
        ':put "  WARNING: NTP could not be switched on. '
        'Set it in System > NTP Client." } }',
    ]


def _syslog_lines(t: IpLogsTargets) -> list[str]:
    config = t.syslog()
    legacy = deferred(f"/system logging action add {_args(config.action_row())}")
    modern = deferred(
        f"/system logging action add {_args(modern_action_row(config.action_row()))}"
    )
    name = ROUTEROS_ACTION_NAME
    topics_on = deferred(
        f"/system logging action set [find name={name}] add-topics-string=yes"
    )
    lines = [
        f"# 3. System logs to {config.remote_host}:{config.remote_port}",
        f":do {{ /system logging remove [find action={name}] }} on-error={{}}",
        f":do {{ /system logging action remove [find name={name}] }} on-error={{}}",
        # 7.18+ first (remote-log-format), then the older bsd-syslog=yes. If
        # both are refused the paste stops loudly instead of looking done.
        f':do {{ {modern}; :put "  System logs: RouterOS 7.18+ format" }} '
        f'on-error={{ :do {{ {legacy}; :put "  System logs: older RouterOS format" }} '
        'on-error={ :put "  FAILED: the router refused the remote logging action"; '
        ':error "wyfy: remote logging refused" } }',
        # PROV-FIX D6: RouterOS 7.25.1 writes add-topics-string=no on a new
        # action, so the topic list never reaches the collector. Where the
        # property exists it is switched on; where it does not, the parse is
        # refused and caught (same deferral as the dialect pick above).
        f":do {{ {topics_on} }} on-error={{}}",
    ]
    lines.extend(f"/system logging add {_args(row)}" for row in config.rule_rows())
    return lines


def _flow_lines(t: IpLogsTargets) -> list[str]:
    base = flow_desired_config(t.flow_target(), nat_events=False)
    full = flow_desired_config(t.flow_target(), nat_events=True)
    nat_only = {k: v for k, v in full.ipfix.items() if k not in base.ipfix}
    identity = target_identity(t.flow_host, t.flow_port)
    where = " and ".join(f"{k}={v}" for k, v in identity.items())
    target = _args(dict(base.target or {}))
    return [
        f"# 4. Connection logs (IPFIX + NAT) to {t.flow_host}:{t.flow_port}, "
        "RouterOS 7 only",
        f":if {_NOT_V7} do={{ :put "
        '"  SKIPPED connection logs: RouterOS 7 is needed (System > Packages > '
        'Check For Updates)" }',
        _v7_only(
            f":if ([:len [/ip traffic-flow target find where {where}]] = 0) "
            f"do={{ /ip traffic-flow target add {target} }}"
        ),
        _v7_only(f"/ip traffic-flow target set [find where {where}] {target}"),
        _v7_only(f"/ip traffic-flow ipfix set {_args(dict(base.ipfix))}"),
        # NAT events are newer than the rest of the IPFIX field set: a refusal
        # is a warning (translated ports are then derived), never a stop.
        f":if {_V7} do={{ :do {{ "
        f"{deferred(f'/ip traffic-flow ipfix set {_args(nat_only)}')} }} "
        'on-error={ :put "  WARNING: this RouterOS cannot send NAT events. '
        'Upgrade RouterOS for exact translated ports." } }',
        _v7_only(f"/ip traffic-flow set {_args(dict(base.settings))}"),
    ]


def _readback_lines(t: IpLogsTargets) -> list[str]:
    identity = target_identity(t.flow_host, t.flow_port)
    where = " and ".join(f"{k}={v}" for k, v in identity.items())
    return [
        "# 5. Read back, and one test line so the console shows it arriving",
        f':put ("  System log rules: " . [:len [/system logging find '
        f'action={ROUTEROS_ACTION_NAME}]] . " (expected {len(ROUTEROS_TOPICS)})")',
        _v7_only(
            ':put ("  Connection log targets: " . '
            f"[:len [/ip traffic-flow target find where {where}]] . "
            '" (expected 1)")'
        ),
        ':log info "wyfy: IP logs set up"',
        ':put "=== Done. Open this router in Wyfy: '
        'IP logs turns green within 5 minutes. ==="',
    ]


def render_enable_script(t: IpLogsTargets) -> list[str]:
    """The paste script, one RouterOS console line per item."""
    return [
        "# Wyfy Guest: turn on IP logs. Paste AFTER the setup script, "
        "in the router terminal.",
        ':put "=== Wyfy IP logs ==="',
        *_identity_lines(t),
        *_clock_lines(),
        *_syslog_lines(t),
        *_flow_lines(t),
        *_readback_lines(t),
    ]


def render_disable_script(t: IpLogsTargets) -> list[str]:
    """Undo: our syslog action + rules, our flow target only (a venue's own
    collector is never touched), export off only if no target is left."""
    identity = target_identity(t.flow_host, t.flow_port)
    where = " and ".join(f"{k}={v}" for k, v in identity.items())
    name = ROUTEROS_ACTION_NAME
    return [
        "# Wyfy Guest: turn off IP logs on this router.",
        f":do {{ /system logging remove [find action={name}] }} on-error={{}}",
        f":do {{ /system logging action remove [find name={name}] }} on-error={{}}",
        _v7_only(f"/ip traffic-flow target remove [find where {where}]"),
        _v7_only(
            ":if ([:len [/ip traffic-flow target find]] = 0) do={ "
            "/ip traffic-flow set enabled=no }"
        ),
        ':put "=== Wyfy IP logs removed ==="',
    ]
