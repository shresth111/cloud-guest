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
    NOT_ALLOWLISTED = "not_allowlisted"  # windows exist but router not in the allowlist
    COLLECTOR_UNREACHABLE = "collector_unreachable"  # last pull from the hub failed
    NO_WINDOWS = "no_windows"  # nothing received in the period
    STALE = "stale"  # newest window older than STALE_AFTER_SECONDS
    OK = "ok"


class TalkerMatch(StrEnum):
    """How a talker IP was matched to a guest session for its window."""

    SESSION = "session"  # exactly one overlapping session on this router
    AMBIGUOUS = "ambiguous"  # several sessions held this IP in the window
    NONE = "none"  # no session -- staff/IoT device, router WAN, or an unrecorded IP
