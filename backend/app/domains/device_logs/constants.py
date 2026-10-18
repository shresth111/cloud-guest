"""Device Logs constants. Strings here are wire contracts with the
frontend (attribution/source/vendor values) or with RouterOS (the action
name and tag prefix the writer and the paste script both key on)."""

from __future__ import annotations

from enum import StrEnum

#: The ``/system logging action`` name. Unique on RouterOS, so it is the
#: action's identity; the rules have no unique key and are keyed on
#: ``action=<this>``. Letters only: RouterOS action names reject most
#: punctuation.
ROUTEROS_ACTION_NAME = "wyfysyslog"

#: Every message from a configured router starts with ``wyfy-<8 hex>``.
TAG_PREFIX = "wyfy-"
TAG_HEX_LENGTH = 8

#: Topics sent remotely, one ``/system logging`` rule each. ``info`` already
#: covers hotspot/dhcp/system/firewall(log=yes)/wireguard info lines;
#: ``debug`` is never sent.
ROUTEROS_TOPICS: tuple[str, ...] = ("critical", "error", "warning", "info")

#: ``local5``: lets the collector tell our stream apart from anything else.
ROUTEROS_SYSLOG_FACILITY = "local5"

#: Longest message stored in Postgres. The raw archive keeps the full line.
MAX_MESSAGE_LENGTH = 2000

#: Longest batch the ingest endpoint accepts in one request. Vector's HTTP
#: sink batches by size/time; anything larger is a misconfigured collector.
MAX_INGEST_BATCH = 1000

#: Viewer page size bounds.
DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 500

#: Viewer windows the UI offers; the API accepts any range up to this.
#: Master viewer only -- it reads across every tenant.
MAX_QUERY_WINDOW_DAYS = 31

#: Customer NetLogs: one organization, so the full two-year retention is
#: queryable (monthly partitions keep a narrow range cheap).
CUSTOMER_MAX_QUERY_WINDOW_DAYS = 730

#: Most rows one CSV export streams. An export that would exceed it is cut
#: and says so in its last line -- never silently truncated.
CUSTOMER_EXPORT_MAX_ROWS = 100_000

#: Rows per round trip while streaming an export.
CUSTOMER_EXPORT_CHUNK = 2_000

#: Routers listed in the summary's "top routers".
SUMMARY_TOP_ROUTERS = 10

#: Partition naming: ``device_log_events_pYYYYMM`` and the catch-all.
PARTITION_PREFIX = "device_log_events_p"
DEFAULT_PARTITION = "device_log_events_default"

#: Celery task name for the nightly partition maintenance.
TASK_DEVICE_LOGS_PARTITION_MAINTENANCE = (
    "app.domains.device_logs.tasks.run_partition_maintenance"
)

#: A configured router that has sent nothing for this long reads "silent".
SILENT_AFTER_MINUTES = 60

INGEST_SECRET_HEADER = "X-Device-Logs-Secret"


class LogVendor(StrEnum):
    MIKROTIK = "mikrotik"
    # Later: OMADA = "omada", ARUBA_INSTANT_ON = "aruba_instant_on"


class LogSource(StrEnum):
    SYSLOG = "syslog"
    # Later: INSTANT_ON_ALERTS = "instant_on_alerts" -- NOT syslog; Instant
    # On APs cannot send syslog.


class Attribution(StrEnum):
    #: Source IP matched exactly one router's tunnel address.
    TUNNEL_IP = "tunnel_ip"
    #: Attributed by tunnel IP, but the message's wyfy- tag names a different
    #: router: the hub is SNATing or a router was re-tunnelled.
    TAG_MISMATCH = "tag_mismatch"
    #: No (or more than one) tunnel address matched. Never attributed from
    #: the tag alone -- it is plain text anyone can write.
    UNATTRIBUTED = "unattributed"
    #: Written by the platform itself (RADIUS decision, portal sign-in
    #: failure); the tenant comes from the authenticated NAS's router or the
    #: login's own venue, not from a source IP.
    SERVER = "server"


class ReceivingState(StrEnum):
    """Per-router state the viewer shows. Never a bare zero."""

    FEATURE_OFF = "feature_off"
    NOT_CONFIGURED = "not_configured"
    #: Configured, but no message has ever arrived -- unknown, not "quiet".
    AWAITING_FIRST_MESSAGE = "awaiting_first_message"
    RECEIVING = "receiving"
    SILENT = "silent"


class LogCategory(StrEnum):
    """What a line is about. Wire contract with the customer NetLogs page.
    NULL in the table means "stored before classification existed and not
    backfilled yet" -- the API reports it as ``other``."""

    DHCP = "dhcp"
    HOTSPOT_AUTH = "hotspot_auth"
    RADIUS = "radius"
    FIREWALL = "firewall"
    #: Reserved: DNS query logging is deliberately NOT collected (volume and
    #: guest privacy). Kept in the vocabulary so the column's value set is
    #: stable if that decision changes.
    DNS = "dns"
    SYSTEM = "system"
    WIRELESS = "wireless"
    OTHER = "other"


class LogStatus(StrEnum):
    """Outcome of the event, where the line states one. NULL otherwise --
    never a guessed ``success``."""

    SUCCESS = "success"
    FAILURE = "failure"
    ACCEPT = "accept"
    REJECT = "reject"
    BLOCKED = "blocked"
    ALLOWED = "allowed"
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    RELEASED = "released"


#: Where a row came from. ``syslog`` is the router; the other two are
#: written by the platform itself (``LogSource`` extension).
SERVER_SOURCE_RADIUS = "radius_server"
SERVER_SOURCE_PORTAL = "captive_portal"
SERVER_VENDOR = "wyfy"


SEVERITY_NAMES: dict[int, str] = {
    0: "emergency",
    1: "alert",
    2: "critical",
    3: "error",
    4: "warning",
    5: "notice",
    6: "info",
    7: "debug",
}


#: Matching window for linking a MAC-carrying router event (DHCP) to a guest
#: session (see ``session_events``): from this long before the session
#: started (a phone gets its DHCP lease when it joins the WiFi, before the
#: guest finishes the portal) until this long after it ended (the lease is
#: released when the phone leaves).
GUEST_EVENT_LEAD_MINUTES = 10
GUEST_EVENT_TRAIL_MINUTES = 10
#: The same for IP-only events (hotspot sign-in/out). These happen at the
#: session's own start/end -- the router signing the guest in IS what starts
#: the RADIUS session -- so only clock skew is allowed. A wide window here
#: would make every IP that DHCP hands to the next guest ambiguous.
GUEST_EVENT_IP_SKEW_MINUTES = 2

#: Most events returned for one session.
MAX_SESSION_DEVICE_EVENTS = 200
