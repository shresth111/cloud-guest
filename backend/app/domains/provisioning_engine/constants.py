"""Enumerations and state-transition graphs for the Provisioning Engine
domain.

Stored as plain ``String`` columns on the ORM models, never native
PostgreSQL enum types -- the same reason every other domain in this
codebase documents: adding a new value is a purely additive ``StrEnum``
member, never an ``ALTER TYPE`` migration.
"""

from __future__ import annotations

from enum import StrEnum

# ============================================================================
# Provision job lifecycle
# ============================================================================


class ProvisionJobStatus(StrEnum):
    """Lifecycle of a :class:`~.models.ProvisionJob` -- the top-level,
    end-to-end orchestration run for one router.

    * ``PENDING`` -- created, not yet queued for a worker.
    * ``QUEUED`` -- queued (durable Postgres row + Redis wake-up signal,
      mirroring ``app.domains.router_provisioning``'s own
      ``ProvisioningJob``/Redis dispatch split).
    * ``RUNNING`` -- the worker picked it up; the ``DISCOVER`` step is in
      progress.
    * ``VALIDATING`` -- the ``VALIDATE`` step is in progress.
    * ``CONFIGURING`` -- the ``GENERATE_CONFIG``/``PUSH_CONFIG`` steps are
      in progress.
    * ``VERIFYING`` -- the ``VERIFY_CONFIG``/``HEALTH_CHECK``/
      ``REGISTER_MONITORING`` steps are in progress.
    * ``SUCCESS`` -- every step succeeded.
    * ``FAILED`` -- terminal on this row -- a retry is a **new**
      :class:`~.models.ProvisionJob` row (``retry_of_job_id`` set), never a
      mutation back to a non-terminal status on this one, mirroring
      ``ConfigVersion``'s/``PolicyVersion``'s own "new row, not mutate"
      convention already established elsewhere in this codebase.
    * ``ROLLED_BACK`` -- reached only when a *separate* rollback job
      (``is_rollback=True``, ``rollback_of_job_id`` pointing back at this
      one) succeeds -- mirrors ``ConfigVersionStatus``'s own identical
      ``APPLIED -> ROLLED_BACK`` "superseded by a later rollback" edge.
    * ``CANCELLED`` -- terminal, reachable from any non-terminal status via
      ``cancel_job``.
    """

    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    VALIDATING = "validating"
    CONFIGURING = "configuring"
    VERIFYING = "verifying"
    SUCCESS = "success"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    CANCELLED = "cancelled"


PROVISION_JOB_STATUS_TRANSITIONS: dict[
    ProvisionJobStatus, frozenset[ProvisionJobStatus]
] = {
    ProvisionJobStatus.PENDING: frozenset(
        {ProvisionJobStatus.QUEUED, ProvisionJobStatus.CANCELLED}
    ),
    ProvisionJobStatus.QUEUED: frozenset(
        {ProvisionJobStatus.RUNNING, ProvisionJobStatus.CANCELLED}
    ),
    ProvisionJobStatus.RUNNING: frozenset(
        {
            ProvisionJobStatus.VALIDATING,
            ProvisionJobStatus.FAILED,
            ProvisionJobStatus.CANCELLED,
        }
    ),
    ProvisionJobStatus.VALIDATING: frozenset(
        {
            ProvisionJobStatus.CONFIGURING,
            ProvisionJobStatus.FAILED,
            ProvisionJobStatus.CANCELLED,
        }
    ),
    ProvisionJobStatus.CONFIGURING: frozenset(
        {
            ProvisionJobStatus.VERIFYING,
            ProvisionJobStatus.FAILED,
            ProvisionJobStatus.CANCELLED,
        }
    ),
    ProvisionJobStatus.VERIFYING: frozenset(
        {
            ProvisionJobStatus.SUCCESS,
            ProvisionJobStatus.FAILED,
            ProvisionJobStatus.CANCELLED,
        }
    ),
    ProvisionJobStatus.SUCCESS: frozenset({ProvisionJobStatus.ROLLED_BACK}),
    ProvisionJobStatus.FAILED: frozenset(),
    ProvisionJobStatus.ROLLED_BACK: frozenset(),
    ProvisionJobStatus.CANCELLED: frozenset(),
}

# Job statuses a job may be cancelled from -- every non-terminal one.
CANCELLABLE_JOB_STATUSES: frozenset[ProvisionJobStatus] = frozenset(
    {
        ProvisionJobStatus.PENDING,
        ProvisionJobStatus.QUEUED,
        ProvisionJobStatus.RUNNING,
        ProvisionJobStatus.VALIDATING,
        ProvisionJobStatus.CONFIGURING,
        ProvisionJobStatus.VERIFYING,
    }
)

# Job statuses eligible for a retry -- only a genuinely finished failure.
RETRYABLE_JOB_STATUSES: frozenset[ProvisionJobStatus] = frozenset(
    {ProvisionJobStatus.FAILED}
)

# Job statuses eligible for a rollback -- only a genuinely successful,
# not-yet-rolled-back job.
ROLLBACKABLE_JOB_STATUSES: frozenset[ProvisionJobStatus] = frozenset(
    {ProvisionJobStatus.SUCCESS}
)


# ============================================================================
# Provision step sequence
# ============================================================================


class ProvisionStepType(StrEnum):
    """One stage within a :class:`~.models.ProvisionJob`'s real, ordered
    sequence -- see ``PROVISION_STEP_SEQUENCE`` below for the canonical
    order the job runner creates/executes these in, matching the module
    brief's own flow diagram exactly (Discover -> Validate -> Generate
    Configuration -> Push Configuration -> Verify Configuration -> Health
    Check -> Monitoring Registration -> Provision Success)."""

    DISCOVER = "discover"
    VALIDATE = "validate"
    GENERATE_CONFIG = "generate_config"
    PUSH_CONFIG = "push_config"
    VERIFY_CONFIG = "verify_config"
    HEALTH_CHECK = "health_check"
    REGISTER_MONITORING = "register_monitoring"


# The canonical, ordered step sequence every forward ProvisionJob runs.
# "Provision Success" (the brief's own final flow-diagram node) is not a
# step -- it is the job's own terminal ProvisionJobStatus.SUCCESS, reached
# once every step below has succeeded.
PROVISION_STEP_SEQUENCE: tuple[ProvisionStepType, ...] = (
    ProvisionStepType.DISCOVER,
    ProvisionStepType.VALIDATE,
    ProvisionStepType.GENERATE_CONFIG,
    ProvisionStepType.PUSH_CONFIG,
    ProvisionStepType.VERIFY_CONFIG,
    ProvisionStepType.HEALTH_CHECK,
    ProvisionStepType.REGISTER_MONITORING,
)

# Which ProvisionJobStatus a given step belongs under -- see
# ProvisionJobStatus's own docstring for the full write-up.
STEP_TYPE_TO_JOB_STATUS: dict[ProvisionStepType, ProvisionJobStatus] = {
    ProvisionStepType.DISCOVER: ProvisionJobStatus.RUNNING,
    ProvisionStepType.VALIDATE: ProvisionJobStatus.VALIDATING,
    ProvisionStepType.GENERATE_CONFIG: ProvisionJobStatus.CONFIGURING,
    ProvisionStepType.PUSH_CONFIG: ProvisionJobStatus.CONFIGURING,
    ProvisionStepType.VERIFY_CONFIG: ProvisionJobStatus.VERIFYING,
    ProvisionStepType.HEALTH_CHECK: ProvisionJobStatus.VERIFYING,
    ProvisionStepType.REGISTER_MONITORING: ProvisionJobStatus.VERIFYING,
}


class ProvisionStepStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    # Reached by every not-yet-started step of a job that was cancelled
    # mid-flight, rather than leaving them PENDING forever.
    SKIPPED = "skipped"


PROVISION_STEP_STATUS_TRANSITIONS: dict[
    ProvisionStepStatus, frozenset[ProvisionStepStatus]
] = {
    ProvisionStepStatus.PENDING: frozenset(
        {ProvisionStepStatus.RUNNING, ProvisionStepStatus.SKIPPED}
    ),
    ProvisionStepStatus.RUNNING: frozenset(
        {ProvisionStepStatus.SUCCEEDED, ProvisionStepStatus.FAILED}
    ),
    ProvisionStepStatus.SUCCEEDED: frozenset(),
    ProvisionStepStatus.FAILED: frozenset(),
    ProvisionStepStatus.SKIPPED: frozenset(),
}


# ============================================================================
# Provision templates
# ============================================================================


class ProvisionSiteType(StrEnum):
    """The reusable ``ProvisionTemplate`` "package" categories named in the
    module brief -- each bundles a ``ConfigTemplate`` (the actual device
    script, composed from ``app.domains.router_provisioning``, never
    duplicated) with DHCP/DNS/hotspot/WireGuard/firewall/NTP/logging
    presets and an optional default ``Policy`` (composed from
    ``app.domains.policy``, likewise never duplicated)."""

    HOTEL = "hotel"
    APARTMENT = "apartment"
    CORPORATE = "corporate"
    HOSPITAL = "hospital"
    SCHOOL = "school"
    AIRPORT = "airport"
    RESTAURANT = "restaurant"
    CAFE = "cafe"


# ============================================================================
# Provision log level
# ============================================================================


class ProvisionLogLevel(StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


# ============================================================================
# Queue / retry / rollback defaults
# ============================================================================

# Redis transport key -- a plain list, pushed with LPUSH, drained by
# app.domains.provisioning_engine.tasks's real Celery worker task. Mirrors
# app.domains.router_provisioning.constants.PROVISIONING_QUEUE_REDIS_KEY's
# identical "Postgres is truth, Redis is a wake-up signal" split, given its
# own, distinct queue key since ProvisionJob is a different row shape than
# router_provisioning's own ProvisioningJob.
PROVISION_ENGINE_QUEUE_REDIS_KEY = "cloudguest:provisioning_engine:queue"

DEFAULT_MAX_JOB_RETRIES = 3

# ============================================================================
# Celery task wiring (see tasks.py)
# ============================================================================

TASK_DRAIN_PROVISION_QUEUE = (
    "app.domains.provisioning_engine.tasks.drain_provision_queue"
)

# Deliberately much shorter than every other Beat-scheduled sweep in this
# codebase (session timeout: 300s, analytics rolling: 900s, renewal/invoice
# sweeps: hourly/daily) -- those all tolerate a coarse staleness window on
# read-model-style recomputation; this one is instead draining a real,
# user-triggered "start provisioning now" request (POST /provision/start),
# where a human is plausibly watching the dashboard's progress bar for it
# to move. 15 seconds is a real, bounded latency budget for that UX, not a
# tight poll loop -- Celery Beat's own per-tick overhead at this cadence is
# negligible next to the actual provisioning work (real device I/O) each
# drained job goes on to perform.
PROVISION_QUEUE_DRAIN_INTERVAL_SECONDS = 15.0

# Bounds how many queued jobs a single Beat tick will drain -- protects one
# worker tick from running unboundedly long if the queue has a large
# backlog, the same "don't let one tick own the worker forever" reasoning
# ``app.core.celery_app``'s own ``task_soft_time_limit`` documents. A
# backlog deeper than this is simply finished across the next tick(s), 15
# seconds later -- never dropped.
PROVISION_QUEUE_DRAIN_BATCH_SIZE = 50

# ============================================================================
# Router device health poll sweep -- pull-based, real device I/O (see
# device_adapters.MikroTikProvisionAdapter.health_check), distinct from
# app.domains.router_agent's push-based heartbeat (a device-initiated
# liveness signal with its own arrival-triggered recording, not something a
# sweep drives). See service.run_router_health_poll_sweep's own docstring.
# ============================================================================

TASK_RUN_ROUTER_HEALTH_POLL_SWEEP = (
    "app.domains.provisioning_engine.tasks.run_router_health_poll_sweep"
)

# The real per-router fan-out leaf task ``TASK_RUN_ROUTER_HEALTH_POLL_SWEEP``
# (the Beat-scheduled coordinator) dispatches one of per router, instead of
# polling every router sequentially, in-process, itself -- see
# ``tasks.poll_single_router_health``'s own docstring for the full
# scale-readiness write-up (a single sequential loop over every router, each
# a real ~10s-timeout RouterOS API round trip, could exceed this sweep's own
# interval once the router fleet is large enough, causing overlapping/
# queued coordinator runs forever).
TASK_POLL_SINGLE_ROUTER_HEALTH = (
    "app.domains.provisioning_engine.tasks.poll_single_router_health"
)

# Raised from an original 300s (5 minutes): defense in depth, not the real
# fix (fan-out + the lock below is) -- gives real-world device-timeout
# variance (some fraction of a large router fleet legitimately taking the
# full ~10s per-router timeout to answer or time out) more headroom before
# a slow tick could ever butt up against the next one, even after fan-out
# removes the sequential-loop bottleneck that made the original 300s
# genuinely too tight at scale.
ROUTER_HEALTH_POLL_SWEEP_INTERVAL_SECONDS = 600.0

# Redis SETNX-style overlap-prevention lock (mirrors this codebase's
# existing ``redis.set(key, "1", nx=True, ex=...)`` idiom -- see
# ``app.domains.analytics.dashboard_audit.DashboardAuditThrottle``'s/
# ``app.domains.billing.service._should_write_dashboard_audit``'s identical
# pattern) guarding only the *coordinator* task's own listing+dispatch
# phase (a DB query plus N cheap ``.delay()`` calls) -- not the fanned-out
# per-router leaf tasks' own, independent run times, which Celery's queue
# already lets run concurrently across worker slots without blocking the
# next Beat tick. This is the real "skip starting a new sweep tick if a
# previous one for this job is still running" backstop the fan-out design
# still needs: it protects against overlapping *coordinator* invocations
# (e.g. Beat restarting mid-tick, a manual trigger racing a scheduled one),
# not against a slow router -- a slow router only ever delays its own leaf
# task, never the coordinator or any other router's leaf task.
ROUTER_HEALTH_POLL_SWEEP_LOCK_REDIS_KEY = (
    "provisioning_engine:router_health_poll_sweep:lock"
)

# A generous ceiling for the coordinator's own listing+dispatch phase
# (expected to take low seconds even for a large router fleet -- it is one
# DB query plus N in-memory ``.delay()`` calls, no device I/O) -- not tied
# to ``ROUTER_HEALTH_POLL_SWEEP_INTERVAL_SECONDS`` above, since gating the
# lock's release on the *leaf* tasks' own device-I/O-bound completion would
# defeat the purpose of fan-out (the next tick would still have to wait for
# the slowest single router). The coordinator always explicitly releases
# this lock in a ``finally`` once dispatch completes; this TTL is purely
# the crash-safety backstop (e.g. a worker killed mid-dispatch) so the lock
# can never wedge the sweep off indefinitely.
ROUTER_HEALTH_POLL_SWEEP_LOCK_TTL_SECONDS = 300

__all__ = [
    "ProvisionJobStatus",
    "PROVISION_JOB_STATUS_TRANSITIONS",
    "CANCELLABLE_JOB_STATUSES",
    "RETRYABLE_JOB_STATUSES",
    "ROLLBACKABLE_JOB_STATUSES",
    "ProvisionStepType",
    "PROVISION_STEP_SEQUENCE",
    "STEP_TYPE_TO_JOB_STATUS",
    "ProvisionStepStatus",
    "PROVISION_STEP_STATUS_TRANSITIONS",
    "ProvisionSiteType",
    "ProvisionLogLevel",
    "PROVISION_ENGINE_QUEUE_REDIS_KEY",
    "DEFAULT_MAX_JOB_RETRIES",
    "TASK_DRAIN_PROVISION_QUEUE",
    "PROVISION_QUEUE_DRAIN_INTERVAL_SECONDS",
    "PROVISION_QUEUE_DRAIN_BATCH_SIZE",
    "TASK_RUN_ROUTER_HEALTH_POLL_SWEEP",
    "TASK_POLL_SINGLE_ROUTER_HEALTH",
    "ROUTER_HEALTH_POLL_SWEEP_INTERVAL_SECONDS",
    "ROUTER_HEALTH_POLL_SWEEP_LOCK_REDIS_KEY",
    "ROUTER_HEALTH_POLL_SWEEP_LOCK_TTL_SECONDS",
]
