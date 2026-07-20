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

# Every 5 minutes -- a schedule window boundary (e.g. "Night Mode" starting
# at 22:00) should flip within a few minutes of the real clock time, not
# be discovered only on the next admin action. Shorter than
# provisioning_engine's own 15-second queue-drain cadence (that one reacts
# to a human-triggered "start now" click; this one reacts to a clock
# boundary nobody is actively watching in real time) but far shorter than
# every other read-model-recomputation sweep in this codebase's own Beat
# schedule.
SCHEDULE_SWEEP_INTERVAL_SECONDS = 300.0


__all__ = [
    "QueueType",
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
    "SCHEDULE_SWEEP_INTERVAL_SECONDS",
]
