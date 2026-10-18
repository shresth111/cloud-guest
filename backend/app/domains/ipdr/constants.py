"""IPDR constants: the column set, permission keys, audit actions, limits.

See ``~/wyfy-ops/ipdr/DESIGN.md`` and this package's ``__init__`` docstring.
"""

from __future__ import annotations

from datetime import timedelta
from zoneinfo import ZoneInfo

IST = ZoneInfo("Asia/Kolkata")

#: The Indian ISP / CERT-In IPDR columns, in order, minus "Address" (owner
#: decision 2026-10-18). Do not reorder or rename: downstream tools match
#: on these exact headers.
IPDR_COLUMNS: tuple[str, ...] = (
    "Time Stamp (IST)",
    "Name of Person/Organization",
    "Contact No.",
    "Alternate Contact No.",
    "E-mail Address",
    "User ID for Internet Access",
    "Source IP Address",
    "Source Port",
    "Translated IP Address",
    "Translated Port",
    "Static/Dynamic IP Address Allocation",
    "Destination IP Address",
    "Destination Port",
    "Protocol",
    "IST Start Time & Date of IP Allocation",
    "IST End Time & Date of IP Allocation",
    "Total Online Time",
    "Source MAC Address/IMEI/Device ID",
)
#: Appended after the 18 standard columns only on request
#: (``include_provenance=true``), so the standard file stays standard.
PROVENANCE_COLUMNS: tuple[str, ...] = ("Translated Address Source", "User Match")

#: The value of "User ID for Internet Access" when no session matched.
UNKNOWN_USER = "unknown"
#: Guests get their address from the venue's DHCP.
ALLOCATION_DYNAMIC = "Dynamic"

# -- translation provenance ---------------------------------------------------
#: Observed: the exporter's own translation (IPFIX NAT event / post-NAT
#: source that differs from the source).
TRANSLATION_NAT_EVENT = "nat_event"
#: The router's public address and the flow's own source port.
TRANSLATION_DERIVED = "derived"
#: Derived, and another guest on the same router used the same (protocol,
#: source port, destination, destination port) at the same time, or the
#: source port is a fixed-port protocol's: masquerade remaps every guest
#: after the first, so the derived port is wrong for some of them.
TRANSLATION_AMBIGUOUS = "ambiguous"
TRANSLATION_NONE = "none"
#: Source ports that protocols use as fixed ports (NTP, SIP, STUN, IKE NAT-T)
#: plus every port below 1024.
FIXED_SOURCE_PORTS = frozenset({3478, 4500, 5060, 5061})
FIXED_SOURCE_PORT_BELOW = 1024
#: Records of one 5-tuple are one connection while the gap between them is
#: at most this (inactive-flow-timeout 15 s + slack; NAT-RESEARCH.md s.5).
STITCH_GAP = timedelta(seconds=20)

# -- timestamp provenance -----------------------------------------------------
TS_FROM_FLOW = "flow"
TS_FROM_WINDOW = "window"

# -- RBAC ---------------------------------------------------------------------
IPDR_READ = "ipdr.read"
IPDR_EXPORT = "ipdr.export"

# -- audit --------------------------------------------------------------------
AUDIT_ACTION_IPDR_LISTED = "ipdr_listed"
AUDIT_ACTION_IPDR_EXPORTED = "ipdr_exported"
#: Written when the stream ends, with the real row count.
AUDIT_ACTION_IPDR_EXPORT_COMPLETED = "ipdr_export_completed"

# -- limits -------------------------------------------------------------------
#: The longest range one list or export may cover.
MAX_RANGE_DAYS = 730
DEFAULT_LIST_WINDOW = timedelta(hours=24)
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200
#: Days one list page may open before it returns with a continuation
#: cursor, so a long filtered search never ties up a worker.
MAX_DAYS_PER_PAGE = 31
EXPORT_MAX_ROWS = 1_000_000
#: A live (not yet archived) day is rebuilt at most this often per process.
LIVE_CACHE_SECONDS = 300
LIVE_CACHE_ENTRIES = 64

# -- coverage of one day ------------------------------------------------------
COVERAGE_ARCHIVED = "archived"
COVERAGE_LIVE = "live"
COVERAGE_MISSING = "missing"

# -- storage ------------------------------------------------------------------
STORE_S3 = "s3"
STORE_LOCAL = "local"
ARCHIVE_FORMAT_VERSION = "v1"

# -- subjects indexed per day file -------------------------------------------
SUBJECT_PHONE = "phone"
SUBJECT_USER = "user"
SUBJECT_MAC = "mac"
SUBJECT_IP = "ip"
SUBJECT_KINDS: tuple[str, ...] = (
    SUBJECT_PHONE,
    SUBJECT_USER,
    SUBJECT_MAC,
    SUBJECT_IP,
)

# -- celery -------------------------------------------------------------------
TASK_IPDR_DAILY_BUILD = "app.domains.ipdr.tasks.run_daily_build"
BEAT_IPDR_DAILY_BUILD = "ipdr-daily-build"
