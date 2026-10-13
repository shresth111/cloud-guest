"""Enumerations and state-transition graphs for the Queue Management
Engine domain.

Stored as plain ``String`` columns on the ORM models, never native
PostgreSQL enum types -- the same reason every other domain in this
codebase documents: adding a new value is a purely additive ``StrEnum``
member, never an ``ALTER TYPE`` migration.
"""

from __future__ import annotations

from enum import StrEnum

# ============================================================================
# Queue profile
# ============================================================================


class QueueType(StrEnum):
    """The RouterOS queueing mechanism a :class:`~.models.QueueProfile`
    maps onto -- see ``device_adapters.py``'s own module docstring for
    exactly which real MikroTik command each maps to.

    * ``SIMPLE`` -- ``/queue simple`` -- a flat, per-target rate limit. The
      right choice for the overwhelming majority of guest/device/session
      queues.
    * ``PCQ`` -- Per-Connection-Queue, RouterOS's own fair-sharing queue
      type (``/queue type`` with ``kind=pcq``, referenced by a
      ``/queue tree`` entry) -- shares one aggregate rate limit fairly
      across many dynamically-created sub-streams (e.g. one "guest Wi-Fi"
      pool shared fairly per active guest, rather than each guest getting
      its own static simple queue).
    * ``TREE`` -- ``/queue tree`` -- hierarchical queueing (parent/child
      rate limits, e.g. an organization-wide ceiling with per-location
      children beneath it), requires upstream mangle marks.
    """

    SIMPLE = "simple"
    PCQ = "pcq"
    TREE = "tree"


# RouterOS priority range is 1 (highest) to 8 (lowest) on both simple
# queues and queue trees -- a real device constraint, not an arbitrary
# platform choice.
MIN_QUEUE_PRIORITY = 1
MAX_QUEUE_PRIORITY = 8
DEFAULT_QUEUE_PRIORITY = 8

# A QueueProfile rate of 0 kbps means "unlimited" -- mirrors RouterOS's own
# real semantics (a simple queue's max-limit of 0 disables the limit
# entirely), not a platform-invented convention.
UNLIMITED_RATE_KBPS = 0


# ============================================================================
# Queue assignment: target + lifecycle
# ============================================================================


class QueueTargetType(StrEnum):
    """What a :class:`~.models.QueueAssignment` attaches to -- a new,
    purpose-built polymorphic discriminator (mirrors
    ``app.domains.policy.models.PolicyAssignment.scope_type``'s own
    "scope_type + nullable scope_id, not a real FK" shape), not a reuse of
    ``app.domains.rbac.enums.ScopeType`` -- guest/voucher/device/session
    are not RBAC scopes.

    ``GUEST_TEAM`` is the brief's own "Guest Group" -- this codebase already
    has a real, named "grouped guest access" concept
    (``app.domains.guest_teams.models.GuestTeam``), so this reuses that
    domain's own name rather than inventing a second one.
    """

    ORGANIZATION = "organization"
    LOCATION = "location"
    ROUTER = "router"
    GUEST_TEAM = "guest_team"
    GUEST = "guest"
    VOUCHER = "voucher"
    DEVICE = "device"
    SESSION = "session"


# Target types that describe a concrete, single device a queue is actually
# pushed to -- QueueAssignment.router_id is required for these (the router
# the device push targets). ORGANIZATION/LOCATION assignments are a
# default/fallback tier (mirrors PolicyAssignment's own global/organization/
# location tiers) resolved against when a more specific assignment doesn't
# exist yet -- never pushed to a device directly themselves, so router_id
# stays NULL for them. See validators.validate_target for the exact rule.
DEVICE_BOUND_TARGET_TYPES: frozenset[QueueTargetType] = frozenset(
    {
        QueueTargetType.ROUTER,
        QueueTargetType.GUEST_TEAM,
        QueueTargetType.GUEST,
        QueueTargetType.VOUCHER,
        QueueTargetType.DEVICE,
        QueueTargetType.SESSION,
    }
)


class QueueStatus(StrEnum):
    """Lifecycle of a :class:`~.models.QueueAssignment`.

    * ``PENDING`` -- created, not yet pushed to any device.
    * ``ACTIVE`` -- successfully applied on the target router via a real
      :class:`~.device_adapters.BaseQueueAdapter` call.
    * ``DISABLED`` -- an admin manually turned it off (``disable_queue``) --
      the live queue is removed from the router, but the row (and its
      rate/profile choice) is kept for a later ``enable_queue`` re-apply.
    * ``SUSPENDED`` -- temporarily inactive because its
      :class:`~.models.QueueSchedule` window is not currently in effect
      (e.g. a "Night Mode" queue during the day) -- reachable only for a
      schedule-bound assignment, and reversible the moment the window
      reopens, without any admin action. Reachable directly from
      ``PENDING`` too: the very first ``apply_queue`` call against a
      schedule-bound assignment created while its window happens to be
      closed goes straight to ``SUSPENDED``, never touching the device at
      all -- not only ``ACTIVE -> SUSPENDED`` once a window that was open
      later closes.
    * ``EXPIRED`` -- terminal. Reached either by an explicit expiry
      (``expires_at`` elapsed) or by being superseded by a "Move Queue"
      operation (a **new** ``QueueAssignment`` row, never a mutation of
      this one -- mirrors ``ConfigVersion``'s/``ProvisionJob``'s own "new
      row, not mutate" convention; see
      ``models.QueueAssignment.superseded_by_assignment_id``).
    """

    PENDING = "pending"
    ACTIVE = "active"
    DISABLED = "disabled"
    SUSPENDED = "suspended"
    EXPIRED = "expired"


QUEUE_STATUS_TRANSITIONS: dict[QueueStatus, frozenset[QueueStatus]] = {
    QueueStatus.PENDING: frozenset(
        {
            QueueStatus.ACTIVE,
            QueueStatus.DISABLED,
            QueueStatus.SUSPENDED,
            QueueStatus.EXPIRED,
        }
    ),
    QueueStatus.ACTIVE: frozenset(
        {QueueStatus.DISABLED, QueueStatus.SUSPENDED, QueueStatus.EXPIRED}
    ),
    QueueStatus.DISABLED: frozenset({QueueStatus.ACTIVE, QueueStatus.EXPIRED}),
    QueueStatus.SUSPENDED: frozenset({QueueStatus.ACTIVE, QueueStatus.EXPIRED}),
    QueueStatus.EXPIRED: frozenset(),
}

# Statuses a live device push (apply_queue) is legal from.
APPLICABLE_QUEUE_STATUSES: frozenset[QueueStatus] = frozenset(
    {QueueStatus.PENDING, QueueStatus.DISABLED, QueueStatus.SUSPENDED}
)

# Statuses a device removal (remove_queue / disable_queue) is legal from.
REMOVABLE_QUEUE_STATUSES: frozenset[QueueStatus] = frozenset({QueueStatus.ACTIVE})


# ============================================================================
# Queue schedules (time-based policies)
# ============================================================================


class QueueScheduleType(StrEnum):
    """The reusable time-window shapes named in the module brief. Every
    type stores its own real window fields on
    :class:`~.models.QueueSchedule` (``days_of_week``/``start_time``/
    ``end_time`` for recurring windows, ``specific_dates`` for
    ``HOLIDAY``) -- see that model's own docstring for exactly which
    fields each type uses."""

    OFFICE_HOURS = "office_hours"
    NIGHT_MODE = "night_mode"
    WEEKEND = "weekend"
    HOLIDAY = "holiday"
    CUSTOM = "custom"


# ============================================================================
# Queue templates (site-persona bundles)
# ============================================================================


class QueueTemplatePersona(StrEnum):
    """The reusable, named site-persona bundles the module brief lists --
    each composes an existing :class:`~.models.QueueProfile` (and,
    optionally, a default :class:`~.models.QueueSchedule`), never
    duplicating either."""

    HOTEL_GUEST = "hotel_guest"
    VIP_GUEST = "vip_guest"
    STAFF = "staff"
    CORPORATE = "corporate"
    STUDENT = "student"
    PREMIUM = "premium"
    TRIAL = "trial"
    UNLIMITED = "unlimited"


# ============================================================================
# Celery task wiring (see tasks.py)
# ============================================================================

TASK_SWEEP_SCHEDULE_TRANSITIONS = (
    "app.domains.queue_management.tasks.sweep_schedule_transitions"
)

# Fired by the Policy router after a bandwidth-policy version publish --
# re-resolves every live (ACTIVE) session queue assignment in each location
# the published policy is mapped to, so a venue that just raised a speed
# sees it reach guests who are already connected (see
# ``QueueManagementService.reapply_active_sessions_for_location``).
TASK_REAPPLY_POLICY_ASSIGNMENTS = (
    "app.domains.queue_management.tasks.reapply_policy_assignments"
)

# Every 5 minutes -- a schedule window boundary (e.g. "Night Mode" starting
# at 22:00) should flip within a few minutes of the real clock time, not
# be discovered only on the next admin action. Shorter than
# provisioning_engine's own 15-second queue-drain cadence (that one reacts
# to a human-triggered "start now" click; this one reacts to a clock
# boundary nobody is actively watching in real time) but far shorter than
# every other read-model-recomputation sweep in this codebase's own Beat
# schedule.
SCHEDULE_SWEEP_INTERVAL_SECONDS = 300.0


TASK_RELEASE_ENDED_SESSION_QUEUES = (
    "app.domains.queue_management.tasks.release_ended_session_queues"
)

# Every 2 minutes. A session's ``/queue simple`` row has no lifetime of its
# own on the router: nothing there removes it when the guest's session ends,
# and RouterOS applies the FIRST matching row for an address, so a row left
# behind keeps deciding the speed of whoever holds that address next. The
# login path already retires a previous holder's row when the next guest
# signs in on the same address, so this cadence is not what protects the
# next guest -- it bounds how long a dead session's row stays on the device
# and how long its assignment keeps reading ACTIVE.
RELEASE_ENDED_SESSION_QUEUES_INTERVAL_SECONDS = 120.0

# An assignment younger than this is never judged. ``assign_guest_queue``
# runs in the worker and can create the assignment before the login
# request that enqueued it has committed the session row (see
# ``guest.tasks._assign_guest_queue_async``), so "no live session with this
# id" is briefly true of a guest who is signing in right now.
RELEASE_ENDED_SESSION_QUEUES_GRACE_SECONDS = 300.0


TASK_BACKFILL_UNASSIGNED_SESSION_QUEUES = (
    "app.domains.queue_management.tasks.backfill_unassigned_session_queues"
)

# Every 5 minutes. This is the net under the login's own queue task, not the
# thing that normally gives a guest their speed, so it does not need the
# release sweep's cadence: it only ever finds work after a router failed to
# answer three times in a row. And where a router is still not answering,
# each run costs one connection timeout on the device-I/O queue -- once
# every five minutes is a cost worth paying to notice the router is back,
# once every two is not.
BACKFILL_UNASSIGNED_SESSION_QUEUES_INTERVAL_SECONDS = 300.0

# A session younger than this is not looked at. The login's own task
# (``guest.tasks.assign_guest_queue``) may still be working on it: up to
# three retries thirty seconds apart, each of which can spend a full
# connection timeout before failing -- about two and a half minutes at
# worst. Five minutes is clear of that with room to spare, and is the same
# figure the release sweep waits before judging a new assignment.
BACKFILL_UNASSIGNED_SESSION_QUEUES_MIN_AGE_SECONDS = 300.0

# The most sessions one run tries to write a queue for -- device attempts,
# not sessions examined. Each is a fresh RouterOS API connection on the
# shared device-I/O queue; this bounds a run to well under its own interval
# even when every write is slow. Overridable per deployment
# (``Settings.guest_queue_backfill_max_per_run``).
BACKFILL_UNASSIGNED_SESSION_QUEUES_MAX_PER_RUN = 25

# How many unassigned sessions one run reads. Much larger than the cap
# above on purpose: sessions that can never be given a queue (an address
# that is not on the venue's LAN, a controller-run venue) are skipped at no
# cost and must not crowd out the ones that can.
BACKFILL_UNASSIGNED_SESSION_QUEUES_SCAN_LIMIT = 1000


# The name of every per-assignment ``/queue simple`` row is this followed by
# the assignment's id. It is also how a guest session's new row finds the
# rows it replaces on the device (``device_adapters.BaseQueueAdapter
# .create_simple_queue``'s ``supersede_name_prefix``).
GUEST_QUEUE_NAME_PREFIX = "cloudguest-"

# A session with no queue assignment is sent its speed in the RADIUS reply
# instead (``QueueManagementService.rate_limit_reply_for_authorize``), but
# not while it is younger than this. The hotspot authorizes a second or two
# after the sign-in that enqueued the session's queue write, and that write
# -- three tries thirty seconds apart, each able to spend a whole connection
# timeout -- may still be on its way. Answering with a rate then gives the
# guest a dynamic hotspot queue *and*, moments later, this platform's own:
# two rows for one address, which is the fault this fallback must not bring
# back.
RADIUS_RATE_FALLBACK_MIN_SESSION_AGE_SECONDS = 150.0

# After a policy re-apply in which some guest's write failed, the task runs
# again this many seconds later (up to its own ``max_retries``). A re-apply
# is idempotent -- a guest already at the published rate costs no device
# call -- so the repeat only does the work that was left.
REAPPLY_POLICY_ASSIGNMENTS_RETRY_SECONDS = 30


# ---------------------------------------------------------------------------
# A venue's total speed cap (``BandwidthPolicyRules.venue_*_rate_kbps``)
# ---------------------------------------------------------------------------
#
# One parent ``/queue simple`` per router, targeting the guest subnet, with
# every guest's own per-session row under it. The name carries the first
# eight characters of the location id, like the per-session rows carry
# their assignment id: enough to tell two venues' rows apart on a router
# somebody is reading by hand, and a name this platform can find again
# without keeping a device id for it.
VENUE_QUEUE_NAME_PREFIX = "cloudguest-venue-"

# Written on the parent row so a person looking at the router can tell it
# is the platform's and what it is for.
VENUE_QUEUE_COMMENT = "cloudguest: venue total speed cap -- managed by the platform"

# Target types the REST API no longer accepts a new assignment for. They
# were always saved and never enforced: nothing reads an ORGANIZATION or
# LOCATION row, and a ROUTER row was pushed with an empty ``target``. A
# venue's total cap is the policy's ``venue_*_rate_kbps`` now, not a row of
# one of these types. Existing rows are left alone.
UNENFORCED_QUEUE_TARGET_TYPES: frozenset[QueueTargetType] = frozenset(
    {
        QueueTargetType.ORGANIZATION,
        QueueTargetType.LOCATION,
        QueueTargetType.ROUTER,
    }
)

__all__ = [
    "QueueType",
    "VENUE_QUEUE_NAME_PREFIX",
    "GUEST_QUEUE_NAME_PREFIX",
    "RADIUS_RATE_FALLBACK_MIN_SESSION_AGE_SECONDS",
    "REAPPLY_POLICY_ASSIGNMENTS_RETRY_SECONDS",
    "VENUE_QUEUE_COMMENT",
    "UNENFORCED_QUEUE_TARGET_TYPES",
    "MIN_QUEUE_PRIORITY",
    "MAX_QUEUE_PRIORITY",
    "DEFAULT_QUEUE_PRIORITY",
    "UNLIMITED_RATE_KBPS",
    "QueueTargetType",
    "DEVICE_BOUND_TARGET_TYPES",
    "QueueStatus",
    "QUEUE_STATUS_TRANSITIONS",
    "APPLICABLE_QUEUE_STATUSES",
    "REMOVABLE_QUEUE_STATUSES",
    "QueueScheduleType",
    "QueueTemplatePersona",
    "TASK_SWEEP_SCHEDULE_TRANSITIONS",
    "TASK_REAPPLY_POLICY_ASSIGNMENTS",
    "TASK_RELEASE_ENDED_SESSION_QUEUES",
    "RELEASE_ENDED_SESSION_QUEUES_INTERVAL_SECONDS",
    "RELEASE_ENDED_SESSION_QUEUES_GRACE_SECONDS",
    "TASK_BACKFILL_UNASSIGNED_SESSION_QUEUES",
    "BACKFILL_UNASSIGNED_SESSION_QUEUES_INTERVAL_SECONDS",
    "BACKFILL_UNASSIGNED_SESSION_QUEUES_MIN_AGE_SECONDS",
    "BACKFILL_UNASSIGNED_SESSION_QUEUES_MAX_PER_RUN",
    "BACKFILL_UNASSIGNED_SESSION_QUEUES_SCAN_LIMIT",
    "SCHEDULE_SWEEP_INTERVAL_SECONDS",
]
