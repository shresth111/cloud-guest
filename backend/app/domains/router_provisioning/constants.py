"""Enumerations, state-transition graphs, and small constants for the Router
Provisioning domain.

There is no dedicated ``enums.py`` in this module (unlike
``app.domains.router.enums``) -- the module's required-file list names
``constants.py`` instead, so every ``StrEnum`` plus the two explicit
transition graphs (mirroring ``app.domains.router.enums
.ROUTER_STATUS_TRANSITIONS``'s documented pattern exactly) live here.

Stored as plain ``String`` columns on the ORM models, never native
PostgreSQL enum types, for the same reason every other domain in this
codebase documents: adding a new value never requires an ``ALTER TYPE``
migration.
"""

from __future__ import annotations

import re
from enum import StrEnum

# ============================================================================
# Config template placeholder syntax
# ============================================================================

# The one supported placeholder syntax for ``ConfigTemplate.template_content``:
# ``{{variable_name}}`` (optional surrounding whitespace, e.g. ``{{ name }}``
# also matches). Deliberately the simplest possible text-substitution scheme
# -- no conditionals, loops, or filters -- since RouterOS config scripts are
# rendered as flat text and every variable resolves to a flat string (see
# ``ConfigVariable.value``'s own "Text, not JSONB" decision in models.py).
# A variable name is a valid Python-identifier-like token: letters, digits,
# underscore, not starting with a digit.
TEMPLATE_PLACEHOLDER_PATTERN = re.compile(r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}")


# ============================================================================
# Config variable scope
# ============================================================================


class ConfigVariableScope(StrEnum):
    """The scope a :class:`~.models.ConfigVariable` row applies at.

    Deliberately a **new, narrower** enum rather than reusing
    ``app.domains.rbac.enums.ScopeType`` directly: ``ScopeType`` also has
    ``GLOBAL``/``DEVICE`` members that make no sense here (a variable is
    never assigned at ``DEVICE`` scope in this module, and "global" is
    expressed differently -- see below), and exposing those irrelevant
    values through this domain's own request schemas would be misleading.
    The string *values* are deliberately kept identical to ``ScopeType``'s
    corresponding members (``"organization"``/``"location"``/``"router"``)
    so the two remain trivially cross-referenced if ever needed.

    A "global default" variable (the lowest-precedence tier in the
    resolution order -- see ``RouterProvisioningService.resolve_variables``)
    is **not** a fourth enum member. It is simply an ``ORGANIZATION``-scope
    row with ``organization_id IS NULL`` -- exactly mirroring
    ``ConfigTemplate``'s own ``organization_id IS NULL`` == "system
    template, available to every tenant" convention.
    """

    ORGANIZATION = "organization"
    LOCATION = "location"
    ROUTER = "router"


# ============================================================================
# Config version lifecycle
# ============================================================================


class ConfigVersionStatus(StrEnum):
    """Lifecycle status of an immutable :class:`~.models.ConfigVersion` row.

    * ``DRAFT`` -- created (by ``assign_profile`` or ``rollback_to_version``)
      but never yet submitted for application.
    * ``PENDING_APPLY`` -- ``apply_version`` was called: a
      :class:`~.models.ProvisioningJob` now exists for this version and is
      queued/running. See ``docs/router_provisioning/FLOW.md`` for why
      ``apply_version`` itself never jumps straight to ``APPLIED`` -- there
      is no live device in this sandbox to confirm the push succeeded, only
      ``complete_provisioning_job`` (the seam a real ``router_agent`` would
      call back through) may make that assertion.
    * ``APPLIED`` -- the associated job succeeded. ``applied_at`` is set.
    * ``FAILED`` -- the associated job failed. May be re-submitted via
      ``apply_version`` (``FAILED -> PENDING_APPLY`` is a legal retry edge).
    * ``ROLLED_BACK`` -- terminal. This version was itself the router's
      current applied config at the moment a *different* version (one
      created via ``rollback_to_version``, i.e. carrying a
      ``rollback_of_version_id``) became ``APPLIED`` in its place. An
      ordinary forward config push does **not** push the previously-applied
      version into this state -- see ``FLOW.md`` for the full reasoning.
    """

    DRAFT = "draft"
    PENDING_APPLY = "pending_apply"
    APPLIED = "applied"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


CONFIG_VERSION_STATUS_TRANSITIONS: dict[
    ConfigVersionStatus, frozenset[ConfigVersionStatus]
] = {
    ConfigVersionStatus.DRAFT: frozenset({ConfigVersionStatus.PENDING_APPLY}),
    ConfigVersionStatus.PENDING_APPLY: frozenset(
        {ConfigVersionStatus.APPLIED, ConfigVersionStatus.FAILED}
    ),
    ConfigVersionStatus.APPLIED: frozenset({ConfigVersionStatus.ROLLED_BACK}),
    ConfigVersionStatus.FAILED: frozenset({ConfigVersionStatus.PENDING_APPLY}),
    ConfigVersionStatus.ROLLED_BACK: frozenset(),
}


# ============================================================================
# Router enrollment (device-initiated, pre-Router-record) lifecycle
# ============================================================================


class EnrollmentStatus(StrEnum):
    """Lifecycle of a device-initiated :class:`~.models.RouterEnrollmentRequest`,
    submitted before any admin-side ``Router`` record exists."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


ENROLLMENT_STATUS_TRANSITIONS: dict[EnrollmentStatus, frozenset[EnrollmentStatus]] = {
    EnrollmentStatus.PENDING: frozenset(
        {EnrollmentStatus.APPROVED, EnrollmentStatus.REJECTED}
    ),
    EnrollmentStatus.APPROVED: frozenset(),
    EnrollmentStatus.REJECTED: frozenset(),
}


# ============================================================================
# Provisioning queue: job type + status
# ============================================================================


class ProvisioningJobType(StrEnum):
    """The set of device-affecting actions this module's queue supports.
    Executing any of these against a *real* device is
    ``app.domains.router_agent``'s job (a future module) -- this module only
    manages the durable job record and its status/history."""

    INITIAL_CONFIG = "initial_config"
    CONFIG_PUSH = "config_push"
    BACKUP = "backup"
    RESTORE = "restore"
    FACTORY_RESET = "factory_reset"


class ProvisioningJobStatus(StrEnum):
    """Lifecycle of a :class:`~.models.ProvisioningJob` row.

    * ``QUEUED`` -- durable record created, job id pushed onto the Redis
      transport queue.
    * ``RUNNING`` -- a (real, future) worker picked up the job.
    * ``SUCCEEDED`` / ``FAILED`` -- terminal, except ``FAILED`` may be
      retried (``FAILED -> QUEUED``) while ``attempts < max_attempts``.
    """

    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


PROVISIONING_JOB_STATUS_TRANSITIONS: dict[
    ProvisioningJobStatus, frozenset[ProvisioningJobStatus]
] = {
    ProvisioningJobStatus.QUEUED: frozenset({ProvisioningJobStatus.RUNNING}),
    ProvisioningJobStatus.RUNNING: frozenset(
        {ProvisioningJobStatus.SUCCEEDED, ProvisioningJobStatus.FAILED}
    ),
    ProvisioningJobStatus.FAILED: frozenset({ProvisioningJobStatus.QUEUED}),
    ProvisioningJobStatus.SUCCEEDED: frozenset(),
}

DEFAULT_MAX_JOB_ATTEMPTS = 3

# Redis transport: a plain list, pushed with LPUSH, meant to be drained with
# BRPOP/RPOP by a future worker (app.domains.router_agent). Postgres
# (``provisioning_jobs``) remains the durable source of truth for status and
# history; Redis is purely the dispatch/wake-up signal -- see
# ``docs/router_provisioning/FLOW.md`` for the full split rationale.
PROVISIONING_QUEUE_REDIS_KEY = "cloudguest:router_provisioning:queue"

# Generated router-secret-rotation credential length (bytes of entropy before
# urlsafe-base64 encoding), matching the same order of magnitude
# ``app.domains.router.service._TOKEN_BYTES`` uses for provisioning tokens.
ROTATED_SECRET_BYTES = 24


# ============================================================================
# Router event log
# ============================================================================


class RouterEventType(StrEnum):
    """Device-history event kinds recorded to :class:`~.models.RouterEvent`.

    See module docstring / ``docs/router_provisioning/DATABASE.md`` for why
    this is a separate table from RBAC's ``audit_log_entries`` rather than a
    reuse of it.
    """

    ENROLLMENT_SUBMITTED = "enrollment_submitted"
    ENROLLMENT_APPROVED = "enrollment_approved"
    ENROLLMENT_REJECTED = "enrollment_rejected"
    CONFIG_VERSION_DRAFTED = "config_version_drafted"
    PROVISIONING_QUEUED = "provisioning_queued"
    CONFIG_APPLIED = "config_applied"
    CONFIG_APPLY_FAILED = "config_apply_failed"
    BACKUP_CREATED = "backup_created"
    RESTORE_QUEUED = "restore_queued"
    RESTORE_COMPLETED = "restore_completed"
    RESTORE_FAILED = "restore_failed"
    FACTORY_RESET_QUEUED = "factory_reset_queued"
    FACTORY_RESET_COMPLETED = "factory_reset_completed"
    FACTORY_RESET_FAILED = "factory_reset_failed"
    SECRET_ROTATED = "secret_rotated"
    HEALTH_SNAPSHOT_RECORDED = "health_snapshot_recorded"


__all__ = [
    "TEMPLATE_PLACEHOLDER_PATTERN",
    "ConfigVariableScope",
    "ConfigVersionStatus",
    "CONFIG_VERSION_STATUS_TRANSITIONS",
    "EnrollmentStatus",
    "ENROLLMENT_STATUS_TRANSITIONS",
    "ProvisioningJobType",
    "ProvisioningJobStatus",
    "PROVISIONING_JOB_STATUS_TRANSITIONS",
    "DEFAULT_MAX_JOB_ATTEMPTS",
    "PROVISIONING_QUEUE_REDIS_KEY",
    "ROTATED_SECRET_BYTES",
    "RouterEventType",
]
