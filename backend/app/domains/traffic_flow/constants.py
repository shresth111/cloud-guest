"""Constants for the traffic flow domain."""

from __future__ import annotations

from enum import StrEnum

#: ``comment`` on the one ``/ip traffic-flow target`` row the platform owns.
#: The device writer finds its row by this, and the renderer's add-guard
#: keys on it, so it must never change without a migration plan for routers
#: already carrying the old marker.
TRAFFIC_FLOW_TARGET_MARKER = "wyfy-traffic-flow"

#: Section header in ``render_network_config`` output.
TRAFFIC_FLOW_SECTION_HEADER = "# --- Traffic Flow (CloudGuest-managed) ---"

#: The collector aggregates into windows of exactly this length (nfacctd
#: ``print_refresh_time`` / ``print_history`` in ops/netflow/nfacctd.conf).
WINDOW_SECONDS = 300

#: Entries kept per list per stored window. DESIGN.md §5 sizes the table on 10.
TOP_N_STORED = 10

#: Services (protocol + remote port) kept per stored window as their own
#: rows in ``traffic_flow_service_buckets``. Everything below the cut is
#: folded into one explicit "other" row per protocol, so sums over the table
#: are exact and the protocol breakdown is too.
TOP_SERVICES_STORED = 50

#: ``remote_port`` of an "other" row. Not a port any flow can carry.
OTHER_SERVICE_PORT = -1

#: ``/ip traffic-flow cache-entries``. RouterOS's default depends on the
#: board's memory (4k only on the smallest), and 4k may overflow at about 50
#: guests (RESEARCH.md §0.2). 16k pending hardware check H5.
ROUTEROS_CACHE_ENTRIES = "16k"

#: A router whose newest window ended at least this long ago reads
#: ``silent`` in the fleet status (PRODUCT.md M1: "nothing for an hour").
SILENT_AFTER_SECONDS = 3600

#: ``GET /summary`` limits.
MAX_QUERY_WINDOW_DAYS = 7
DEFAULT_QUERY_WINDOW_SECONDS = 3600
DEFAULT_LIST_LIMIT = 10
MAX_LIST_LIMIT = 50
DEFAULT_TIMELINE_SERIES = 8
MAX_TIMELINE_SERIES = 12

#: Timeline step by range length: (range up to N seconds, step seconds).
TIMELINE_STEPS: tuple[tuple[int, int], ...] = (
    (6 * 3600, 300),
    (24 * 3600, 900),
)
TIMELINE_STEP_DEFAULT = 3600

#: IP protocol numbers the breakdown names; everything else is "other".
PROTOCOL_TCP = 6
PROTOCOL_UDP = 17
PROTOCOL_ICMP = 1
PROTOCOL_ICMPV6 = 58
PROTOCOL_NAMES: dict[int, str] = {
    PROTOCOL_TCP: "tcp",
    PROTOCOL_UDP: "udp",
    PROTOCOL_ICMP: "icmp",
    PROTOCOL_ICMPV6: "icmp",
}
PROTOCOL_BREAKDOWN_KEYS: tuple[str, ...] = ("tcp", "udp", "icmp", "other")

#: Collector spellings of a protocol (pmacct prints names unless told
#: otherwise) -> IP protocol number.
PROTOCOL_NUMBERS_BY_NAME: dict[str, int] = {
    "tcp": PROTOCOL_TCP,
    "udp": PROTOCOL_UDP,
    "icmp": PROTOCOL_ICMP,
    "ipv6-icmp": PROTOCOL_ICMPV6,
    "icmpv6": PROTOCOL_ICMPV6,
    "gre": 47,
    "esp": 50,
    "ah": 51,
    "sctp": 132,
    "igmp": 2,
    "ipip": 4,
    "ipv6": 41,
}

#: IANA service names for ports worth naming (Service Name and Transport
#: Protocol Port Number Registry). A PORT LABEL, never an application: 443
#: is "https" whatever runs over it. Unlisted ports have no name.
IANA_SERVICE_NAMES: dict[int, str] = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    67: "bootps",
    68: "bootpc",
    80: "http",
    110: "pop3",
    123: "ntp",
    143: "imap",
    161: "snmp",
    443: "https",
    445: "microsoft-ds",
    465: "submissions",
    500: "isakmp",
    554: "rtsp",
    587: "submission",
    853: "domain-s",
    993: "imaps",
    995: "pop3s",
    1194: "openvpn",
    1701: "l2tp",
    1723: "pptp",
    3389: "ms-wbt-server",
    3478: "stun",
    4500: "ipsec-nat-t",
    5060: "sip",
    5061: "sips",
    5222: "xmpp-client",
    5353: "mdns",
    8080: "http-alt",
}

#: A router whose newest window is older than this reads ``stale``.
STALE_AFTER_SECONDS = 900

#: Stored windows are deleted after this many days (DESIGN.md §5/§7). Ops
#: data, not the legal connection record -- that is guest_sessions.
RETENTION_DAYS = 7
RETENTION_BATCH = 5000

#: Windows requested from the hub agent per pull (one hour).
MAX_WINDOWS_PER_PULL = 12

TASK_RUN_TRAFFIC_FLOW_PULL_SWEEP = (
    "app.domains.traffic_flow.tasks.run_traffic_flow_pull_sweep"
)
TRAFFIC_FLOW_PULL_SWEEP_INTERVAL_SECONDS = 300.0

#: Timeout for one call to the hub's flow agent.
AGENT_TIMEOUT_SECONDS = 15.0


class TrafficFlowSource(StrEnum):
    """Where a stored window came from. A wire contract the Master view
    labels by name. Only flow-exporting devices may ever be ``*_ipfix``;
    a vendor statistic from Omada or Instant On gets its own member when it
    is built (DESIGN.md §3) and is never labelled NetFlow."""

    MIKROTIK_IPFIX = "mikrotik_ipfix"


class RouterFlowState(StrEnum):
    """Per-router state in the Master overview, most-blocking first."""

    DISABLED = "disabled"  # Settings.traffic_flow_enabled is false
    NOT_ALLOWLISTED = "not_allowlisted"  # windows exist but export is not switched on
    COLLECTOR_UNREACHABLE = "collector_unreachable"  # last pull from the hub failed
    NO_WINDOWS = "no_windows"  # nothing received in the period
    STALE = "stale"  # newest window older than STALE_AFTER_SECONDS
    OK = "ok"


class FlowState(StrEnum):
    """Per-router state in the fleet status (``GET /status``), most-blocking
    first. Never a bare zero: a router that was switched on and has sent
    nothing is ``awaiting_first_data`` -- unknown -- not "no traffic"."""

    FEATURE_OFF = "feature_off"
    UNSUPPORTED_VENDOR = "unsupported_vendor"
    NOT_CONFIGURED = "not_configured"
    AWAITING_FIRST_DATA = "awaiting_first_data"
    RECEIVING = "receiving"
    SILENT = "silent"


class BlockerCode(StrEnum):
    """Why export cannot be applied to a router right now."""

    FEATURE_OFF = "FEATURE_OFF"
    UNSUPPORTED_VENDOR = "UNSUPPORTED_VENDOR"
    NO_TUNNEL = "NO_TUNNEL"
    ROUTEROS_VERSION = "ROUTEROS_VERSION"
    NO_API_CREDENTIALS = "NO_API_CREDENTIALS"


class TalkerMatch(StrEnum):
    """How a talker IP was matched to a guest session for its window."""

    SESSION = "session"  # exactly one overlapping session on this router
    AMBIGUOUS = "ambiguous"  # several sessions held this IP in the window
    NONE = "none"  # no session -- staff/IoT device, router WAN, or an unrecorded IP
