"""Constants for the Network Diagnostics domain.

Plain module constants, not ``Settings``/``Organization.settings``
fields -- mirrors ``app.domains.isp.constants``'s own "no new Settings
fields" discipline; per-organization tunability is a real future seam,
not implemented in this first pass.
"""

from __future__ import annotations

from enum import StrEnum


class DiagnosticType(StrEnum):
    """Which real RouterOS tool a :class:`~.models.DiagnosticRun` used."""

    PING = "ping"
    TRACEROUTE = "traceroute"


class DiagnosticStatus(StrEnum):
    """The real, honest outcome of one diagnostic execution -- ``FAILED``
    covers both a genuine device-connection failure and a completed-but-
    unreachable-target result (see ``service.py``'s own module docstring:
    every attempt is recorded, never silently dropped)."""

    SUCCESS = "success"
    FAILED = "failed"


# Real RouterOS /tool/ping parameters -- mirrors
# app.domains.isp.constants.ISP_PING_COUNT/ISP_PING_TIMEOUT_SECONDS
# exactly (same real defaults, independently named since this domain is
# router-generic, not WAN-link-specific).
DEFAULT_PING_COUNT = 5
DEFAULT_PING_TIMEOUT_SECONDS = 10

# Real RouterOS /tool traceroute parameters. RouterOS's own default
# max-hops is 30 (matching traditional Unix traceroute); a lower default
# here keeps a single admin-triggered request bounded and fast.
DEFAULT_TRACEROUTE_MAX_HOPS = 15
DEFAULT_TRACEROUTE_TIMEOUT_SECONDS = 15

# ============================================================================
# Bounds on what one request may ask the device to do
# ============================================================================
#
# These were 50 / 64 / 60 / 120 and are deliberately lowered. RouterOS's
# own /tool/ping emits roughly one reply per second, so `count` is very
# nearly "seconds this request will run for" -- a count of 50 was a
# ~50-second HTTP request holding one of the process's small number of
# device-I/O threads (see service.py's own "one blocking thread per run"
# note). Ten packets is the standard size of a real diagnostic ping, keeps
# a run comfortably inside any plausible reverse-proxy read timeout, and
# still shows intermittent loss clearly.
#
# MAX_TRACEROUTE_MAX_HOPS is RouterOS's own (and traditional Unix
# traceroute's own) default ceiling of 30. Sixty-four hops is beyond any
# real internet path and only ever bought a longer-running request.
MAX_PING_COUNT = 10
MAX_TRACEROUTE_MAX_HOPS = 30

# The caller-supplied deadline for one run, in seconds. Unlike before,
# this is now a REAL bound: service.py wraps the adapter call in
# asyncio.wait_for (see NetworkDiagnosticsService._execute). Previously
# both values were accepted by the API and then discarded -- the gateway's
# own ping docstring says so outright -- so the API documented a control
# that did nothing.
MAX_PING_TIMEOUT_SECONDS = 30
MAX_TRACEROUTE_TIMEOUT_SECONDS = 60

# The RouterOS API connect/read timeout, applied to the socket itself
# (librouteros passes it to socket.create_connection, which makes it both
# the connect timeout AND the per-recv timeout for the life of the
# session). Deliberately NOT the caller's own timeout_seconds: a caller
# asking for a 60-second traceroute deadline should not also be asking us
# to wait 60 seconds to discover that an unreachable router is
# unreachable. Kept at the value the DiagnosticsCredentials dataclass
# already defaulted to, now stated once, here, rather than being an
# invisible dataclass default.
DEVICE_CONNECT_TIMEOUT_SECONDS = 10

# ============================================================================
# Abuse controls (both Redis-backed)
# ============================================================================
#
# A diagnostic runs a real network command against a caller-chosen
# destination from the customer's own router, i.e. from the customer's own
# ISP allocation. Unlike every other RBAC-gated read in this domain, doing
# it repeatedly has a real external cost -- to the destination, and to the
# venue whose address appears in the destination's logs. RBAC answers "may
# this person run a diagnostic"; it does not answer "how often". These two
# limits do, and they are deliberately two rather than one, mirroring the
# same two-bucket reasoning app.middleware.rate_limit already documents
# for /captive-portal/resolve:
#
# * The per-router cooldown is the fairness/self-protection control. It
#   stops two admins racing each other, a double-submitted form, or a
#   retry loop from queueing runs on one device faster than they complete,
#   and it is what keeps a single router (and a single one of the
#   process's few device-I/O threads) from being monopolised. Ten seconds
#   is just longer than a default five-packet ping actually takes on the
#   device, so back-to-back runs are throttled to roughly the rate they
#   can genuinely complete at, while a human clicking "run again" after
#   reading the result is never blocked.
#
# * The per-organization window is the real volume control, and it is the
#   one that bounds outbound traffic. A cooldown alone does not: an
#   organization with fifty routers could still sustain five runs a second
#   by rotating routers, which is exactly the "a key the caller chooses is
#   a key the caller can rotate" failure the captive-portal limiter
#   documents. The window is keyed on the organization, which the caller
#   cannot rotate (CurrentOrganization validates membership).
#
# 120 runs/hour is generous for the real use: an admin actively debugging
# one site runs perhaps twenty or thirty diagnostics in a sitting, so this
# is roughly four times a busy human and still hard-caps a script at two
# runs a minute sustained.
DIAGNOSTIC_COOLDOWN_SECONDS = 10
DIAGNOSTIC_COOLDOWN_REDIS_KEY_TEMPLATE = "network_diagnostics:cooldown:{router_id}"

DIAGNOSTIC_ORG_MAX_RUNS_PER_WINDOW = 120
DIAGNOSTIC_ORG_RATE_LIMIT_WINDOW_SECONDS = 3600
DIAGNOSTIC_ORG_RATE_LIMIT_REDIS_KEY_TEMPLATE = (
    "network_diagnostics:rate:{organization_id}"
)

# ============================================================================
# Retention
# ============================================================================
#
# diagnostic_runs is append-only and, until this sweep, had no TTL, no
# purge job and (see above) no rate limit -- an authenticated customer
# could grow it without bound, one JSONB blob per row.
#
# Ninety days is chosen against the actual use the history serves: a venue
# investigating "the WiFi is slow every Friday evening" needs to compare
# this week against previous weeks, and a quarter covers a full seasonal
# pattern plus the billing cycle a complaint usually arrives inside. It is
# also long enough that the sweep is never what loses evidence during an
# open support ticket. Shorter (30 days) would break the recurring-problem
# comparison that is the feature's whole point; longer buys nothing a
# venue operator has ever asked for and grows a table nobody reads past
# the first page of.
#
# Rows are DELETEd, not soft-deleted. The soft-delete columns BaseModel
# brings are meaningless here (this domain has never called soft_delete,
# and a retention sweep whose whole purpose is to stop unbounded growth
# cannot leave the rows in the table).
DIAGNOSTIC_RUN_RETENTION_DAYS = 90

# Daily. The sweep deletes at most one day's accumulation in the steady
# state, so a shorter cadence would be pure overhead; a longer one would
# let the table drift past the window it advertises.
DIAGNOSTIC_RUN_RETENTION_SWEEP_INTERVAL_SECONDS = 86_400

# Deleted in bounded batches rather than one unbounded statement: the very
# first run after this ships has an entire un-purged history to remove,
# and a single DELETE over it would hold one long transaction and its
# locks against a table live requests write to. The per-run cap means a
# very large backlog drains over several nightly runs instead of one long
# one -- the sweep logs when it stops at the cap, so that is visible
# rather than silent.
DIAGNOSTIC_RUN_RETENTION_DELETE_BATCH_SIZE = 1_000
DIAGNOSTIC_RUN_RETENTION_MAX_BATCHES_PER_RUN = 100

TASK_RUN_DIAGNOSTIC_RUN_RETENTION_SWEEP = (
    "app.domains.network_diagnostics.tasks.run_diagnostic_run_retention_sweep"
)

__all__ = [
    "DiagnosticType",
    "DiagnosticStatus",
    "DEFAULT_PING_COUNT",
    "DEFAULT_PING_TIMEOUT_SECONDS",
    "DEFAULT_TRACEROUTE_MAX_HOPS",
    "DEFAULT_TRACEROUTE_TIMEOUT_SECONDS",
    "MAX_PING_COUNT",
    "MAX_TRACEROUTE_MAX_HOPS",
    "MAX_PING_TIMEOUT_SECONDS",
    "MAX_TRACEROUTE_TIMEOUT_SECONDS",
    "DEVICE_CONNECT_TIMEOUT_SECONDS",
    "DIAGNOSTIC_COOLDOWN_SECONDS",
    "DIAGNOSTIC_COOLDOWN_REDIS_KEY_TEMPLATE",
    "DIAGNOSTIC_ORG_MAX_RUNS_PER_WINDOW",
    "DIAGNOSTIC_ORG_RATE_LIMIT_WINDOW_SECONDS",
    "DIAGNOSTIC_ORG_RATE_LIMIT_REDIS_KEY_TEMPLATE",
    "DIAGNOSTIC_RUN_RETENTION_DAYS",
    "DIAGNOSTIC_RUN_RETENTION_SWEEP_INTERVAL_SECONDS",
    "DIAGNOSTIC_RUN_RETENTION_DELETE_BATCH_SIZE",
    "DIAGNOSTIC_RUN_RETENTION_MAX_BATCHES_PER_RUN",
    "TASK_RUN_DIAGNOSTIC_RUN_RETENTION_SWEEP",
]
