"""Lightweight, in-process domain events for the Router Provisioning module.

These are plain, frozen dataclasses constructed by ``RouterProvisioningService``
methods and consumed *directly, synchronously* by that same service's own
``_record_event``/``_audit`` helpers (see ``service.py``) -- there is no
event bus, no publish/subscribe registry, and no async dispatch. This is
deliberately the simplest thing that could work: a typed, self-documenting
value object per notable lifecycle transition, used as the single place that
both writes a ``RouterEvent`` history row and (for the subset judged
"significant", see module docstring in ``models.py``) an RBAC
``audit_log_entries`` row, so the two call sites can never drift out of sync
with each other.

Not part of the public API surface -- nothing outside this module's own
``service.py`` constructs or reads these.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class RouterEnrollmentSubmitted:
    enrollment_id: uuid.UUID
    serial_number: str
    mac_address: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class RouterEnrollmentApproved:
    enrollment_id: uuid.UUID
    router_id: uuid.UUID
    organization_id: uuid.UUID
    location_id: uuid.UUID
    approved_by_user_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class RouterEnrollmentRejected:
    enrollment_id: uuid.UUID
    rejected_by_user_id: uuid.UUID
    reason: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class ConfigVersionDrafted:
    router_id: uuid.UUID
    config_version_id: uuid.UUID
    version_number: int
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class ProvisioningJobEnqueued:
    router_id: uuid.UUID
    job_id: uuid.UUID
    job_type: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class ConfigVersionApplied:
    router_id: uuid.UUID
    config_version_id: uuid.UUID
    job_id: uuid.UUID
    is_rollback: bool
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class ConfigVersionApplyFailed:
    router_id: uuid.UUID
    config_version_id: uuid.UUID
    job_id: uuid.UUID
    error_message: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class RouterBackupCreated:
    router_id: uuid.UUID
    backup_version_id: uuid.UUID
    job_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class RouterRestoreCompleted:
    router_id: uuid.UUID
    backup_version_id: uuid.UUID
    new_version_id: uuid.UUID
    job_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class RouterFactoryResetCompleted:
    router_id: uuid.UUID
    job_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class RouterSecretRotated:
    router_id: uuid.UUID
    rotated_by_user_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class RouterHealthSnapshotRecorded:
    router_id: uuid.UUID
    snapshot_id: uuid.UUID
    health_status: str | None
    occurred_at: datetime = field(default_factory=_now)


__all__ = [
    "RouterEnrollmentSubmitted",
    "RouterEnrollmentApproved",
    "RouterEnrollmentRejected",
    "ConfigVersionDrafted",
    "ProvisioningJobEnqueued",
    "ConfigVersionApplied",
    "ConfigVersionApplyFailed",
    "RouterBackupCreated",
    "RouterRestoreCompleted",
    "RouterFactoryResetCompleted",
    "RouterSecretRotated",
    "RouterHealthSnapshotRecorded",
]
