"""Enumerations and managed-comment prefixes for router discovery snapshots.

Plain ``StrEnum`` string values stored in ``String`` columns (never a
native Postgres enum type) -- the same "new value is an additive registry
entry, never a migration" posture
``app.domains.provisioning_engine.constants`` / ``app.domains.otp.constants``
already document.
"""

from __future__ import annotations

from enum import StrEnum

# Comment prefixes that mark a RouterOS object as managed by this platform.
# Detection is prefix-based and case-sensitive against the raw ``comment``
# field on interfaces / bridges / firewall / NAT / DHCP / etc.
MANAGED_COMMENT_PREFIXES: tuple[str, ...] = (
    "WYFYGUEST-",
    "cloudguest-",
)

PLAN_ENGINE_VERSION = "wave1-1"
DEFAULT_GUEST_BRIDGE_NAME = "WYFYGUEST-bridge-guest"


class SnapshotTrigger(StrEnum):
    """Why a snapshot was captured."""

    WIZARD_DISCOVERY = "wizard_discovery"
    PRE_APPLY = "pre_apply"
    MANUAL = "manual"
    SCHEDULED = "scheduled"


class SnapshotStatus(StrEnum):
    """Completeness of one discovery capture.

    * ``complete`` -- every requested section returned rows (or empty lists)
      with no per-section errors.
    * ``partial`` -- at least one section failed (missing package / menu)
      but enough state was captured to persist and evaluate.
    * ``failed`` -- the device could not be reached at all, or collection
      aborted before any useful sections were written.
    """

    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


class CompatibilityOverall(StrEnum):
    """Aggregate result of the Wave 1 compatibility evaluator.

    Ordered from best to worst for roll-up: a single ``BLOCKED`` check
    wins over ``ERROR`` / ``WARNING`` / ``PASS``.
    """

    PASS = "PASS"
    WARNING = "WARNING"
    ERROR = "ERROR"
    BLOCKED = "BLOCKED"


class CompatibilityCheckStatus(StrEnum):
    """Per-check status inside a compatibility report."""

    PASS = "PASS"
    WARNING = "WARNING"
    ERROR = "ERROR"
    BLOCKED = "BLOCKED"


class VerificationScope(StrEnum):
    WAN = "wan"
    FINAL = "final"
    PLAN_STEP = "plan_step"


class WanVerificationOverall(StrEnum):
    """Per-WAN uplink verification result (P7)."""

    ONLINE = "ONLINE"
    OFFLINE = "OFFLINE"
    ERROR = "ERROR"
    DISABLED = "DISABLED"


class VerificationCheckStatus(StrEnum):
    PASS = "PASS"
    WARNING = "WARNING"
    ERROR = "ERROR"
    BLOCKED = "BLOCKED"


class PlanStatus(StrEnum):
    DRAFT = "draft"
    BLOCKED = "blocked"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    RENDERING = "rendering"
    APPLYING = "applying"
    APPLIED = "applied"
    FAILED = "failed"
    SUPERSEDED = "superseded"
    REJECTED = "rejected"


class InterfaceAvailabilityStatus(StrEnum):
    """Per-port suitability for guest Wi-Fi assignment (P10)."""

    RECOMMENDED = "RECOMMENDED"
    AVAILABLE = "AVAILABLE"
    IN_USE = "IN_USE"
    WAN = "WAN"
    BRIDGE_MEMBER = "BRIDGE_MEMBER"
    DISABLED = "DISABLED"
    UNAVAILABLE = "UNAVAILABLE"


class PlanActionType(StrEnum):
    CREATE = "create"
    MODIFY = "modify"
    REMOVE = "remove"
    NOOP = "noop"


class PlanRisk(StrEnum):
    NONE = "none"
    LOW = "low"
    MANAGEMENT_CONNECTIVITY = "management_connectivity"


class RuleId(StrEnum):
    R1 = "R1"
    R2 = "R2"
    R3 = "R3"
    R4 = "R4"
    R5 = "R5"
    R6 = "R6"
    R7 = "R7"
    R8 = "R8"
    R9 = "R9"
    R10 = "R10"


__all__ = [
    "MANAGED_COMMENT_PREFIXES",
    "PLAN_ENGINE_VERSION",
    "DEFAULT_GUEST_BRIDGE_NAME",
    "SnapshotTrigger",
    "SnapshotStatus",
    "CompatibilityOverall",
    "CompatibilityCheckStatus",
    "VerificationScope",
    "WanVerificationOverall",
    "VerificationCheckStatus",
    "PlanStatus",
    "InterfaceAvailabilityStatus",
    "PlanActionType",
    "PlanRisk",
    "RuleId",
]
