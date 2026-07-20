"""SQLAlchemy ORM models for the Queue Management Engine domain.

Every table extends ``app.database.base.BaseModel`` (UUID PK, timestamps,
soft-delete, audit, version columns) for the same reason every other domain
does. Four models, deliberately not the full list of names the module brief
used (``QueueProfile``/``QueueAssignment``/``QueueHistory``/
``QueueTemplate``/``QueueAudit``/``QueueSchedule``) -- mirrors this
codebase's own established discipline (most recently,
``app.domains.provisioning_engine``'s own module docstring reducing a
9-entity brief to 4 real tables for an identical reason):

* **History** = querying :class:`QueueAssignment` rows for a target,
  ordered by ``created_at`` (``QueueManagementService.get_history``). No
  separate table -- every past assignment already is a row here, since
  reassignment ("Move Queue") creates a **new** row rather than mutating
  the old one (see ``QueueAssignment``'s own docstring).
* **Audit** = the existing RBAC ``audit_log_entries`` table, written through
  the same narrow ``AuditLogWriter`` protocol every other domain uses --
  mirrors ``app.domains.provisioning_engine``'s own identical "moderate-
  volume, human-attributable lifecycle events go through the shared audit
  table, not a domain-local one" posture.

None of these tables reference other domains' models by importing the
class -- only by FK'ing the target table name (``"routers.id"``,
``"organizations.id"``, ...), the same loose-coupling convention
``app.domains.router_provisioning.models``/``app.domains.provisioning_engine
.models`` already document for their own cross-domain FKs. The one
exception is ``QueueAssignment.target_id``, which is deliberately **not** a
real foreign key at all -- it is polymorphic (its target table depends on
``target_type``), mirroring ``app.domains.policy.models.PolicyAssignment
.scope_id``'s own identical "nullable, non-FK, polymorphic" shape.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

from .constants import (
    DEFAULT_QUEUE_PRIORITY,
    QueueStatus,
    QueueType,
)


class QueueProfile(BaseModel):
    """A reusable, named bandwidth/QoS rate definition (e.g. "5 Mbps",
    "Unlimited") -- the thing a :class:`QueueAssignment` points at, never
    duplicated per-assignment. Rates are in kbps; ``0`` means "unlimited",
    RouterOS's own real semantics for a simple queue's ``max-limit`` (see
    ``constants.UNLIMITED_RATE_KBPS``'s own docstring), not a platform-
    invented convention.

    ``organization_id IS NULL`` means a platform-wide system profile,
    available to every tenant -- mirrors
    ``app.domains.router_provisioning.models.ConfigTemplate
    .organization_id``'s identical convention.
    """

    __tablename__ = "queue_profiles"

    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True,
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    download_rate_kbps: Mapped[int] = mapped_column(Integer, nullable=False)
    upload_rate_kbps: Mapped[int] = mapped_column(Integer, nullable=False)
    burst_download_kbps: Mapped[int | None] = mapped_column(Integer, nullable=True)
    burst_upload_kbps: Mapped[int | None] = mapped_column(Integer, nullable=True)
    burst_threshold_kbps: Mapped[int | None] = mapped_column(Integer, nullable=True)
    burst_time_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    priority: Mapped[int] = mapped_column(
        Integer, default=DEFAULT_QUEUE_PRIORITY, nullable=False
    )
    queue_type: Mapped[str] = mapped_column(
        String(20), default=QueueType.SIMPLE.value, nullable=False
    )
    is_system_profile: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    __table_args__ = (
        Index("ix_queue_profiles_organization_id", "organization_id"),
        Index("ix_queue_profiles_is_system_profile", "is_system_profile"),
        Index("ix_queue_profiles_is_active", "is_active"),
        Index("ix_queue_profiles_name", "name"),
    )

    def __repr__(self) -> str:
        return (
            f"<QueueProfile(id={self.id}, name={self.name}, "
            f"download={self.download_rate_kbps}kbps, "
            f"upload={self.upload_rate_kbps}kbps)>"
        )


class QueueSchedule(BaseModel):
    """A reusable, named time-window definition (Office Hours/Night Mode/
    Weekend/Holiday/Custom) a :class:`QueueAssignment` may optionally be
    scoped to -- outside the window, the assignment is
    ``QueueStatus.SUSPENDED`` rather than actively pushed to the router.

    Recurring windows (``OFFICE_HOURS``/``NIGHT_MODE``/``WEEKEND``/
    ``CUSTOM``) use ``days_of_week`` (a JSONB list of ISO weekday integers,
    ``0``=Monday..``6``=Sunday) plus ``start_time``/``end_time`` (``"HH:MM"``
    24-hour strings). ``HOLIDAY`` instead uses ``specific_dates`` (a JSONB
    list of ISO ``"YYYY-MM-DD"`` date strings) -- a holiday is a set of
    calendar dates, not a recurring weekly window.
    """

    __tablename__ = "queue_schedules"

    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True,
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    schedule_type: Mapped[str] = mapped_column(String(20), nullable=False)
    days_of_week: Mapped[list[Any]] = mapped_column(JSONB, default=list, nullable=False)
    start_time: Mapped[str | None] = mapped_column(String(5), nullable=True)
    end_time: Mapped[str | None] = mapped_column(String(5), nullable=True)
    specific_dates: Mapped[list[Any]] = mapped_column(
        JSONB, default=list, nullable=False
    )
    timezone: Mapped[str] = mapped_column(String(50), default="UTC", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    __table_args__ = (
        Index("ix_queue_schedules_organization_id", "organization_id"),
        Index("ix_queue_schedules_schedule_type", "schedule_type"),
        Index("ix_queue_schedules_is_active", "is_active"),
    )

    def __repr__(self) -> str:
        return (
            f"<QueueSchedule(id={self.id}, name={self.name}, "
            f"schedule_type={self.schedule_type})>"
        )


class QueueTemplate(BaseModel):
    """A reusable, named site-persona bundle (Hotel Guest/VIP Guest/Staff/
    Corporate/Student/Premium/Trial/Unlimited) -- composes an existing
    :class:`QueueProfile` (and, optionally, a default :class:`QueueSchedule`)
    rather than duplicating either. Mirrors
    ``app.domains.provisioning_engine.models.ProvisionTemplate``'s own
    identical "package composing an existing X" shape.

    ``organization_id IS NULL`` means a platform-wide system template,
    mirroring ``QueueProfile.organization_id``'s own identical convention.
    """

    __tablename__ = "queue_templates"

    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True,
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    persona: Mapped[str] = mapped_column(String(20), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    queue_profile_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("queue_profiles.id", ondelete="SET NULL"),
        nullable=True,
    )
    default_queue_schedule_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("queue_schedules.id", ondelete="SET NULL"),
        nullable=True,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    __table_args__ = (
        Index("ix_queue_templates_organization_id", "organization_id"),
        Index("ix_queue_templates_persona", "persona"),
        Index("ix_queue_templates_is_active", "is_active"),
    )

    def __repr__(self) -> str:
        return (
            f"<QueueTemplate(id={self.id}, name={self.name}, "
            f"persona={self.persona})>"
        )


class QueueAssignment(BaseModel):
    """Attaches a :class:`QueueProfile` to a target -- see
    ``constants.QueueTargetType``'s own docstring for the full polymorphic
    ``target_type``/``target_id`` write-up, and ``constants.QueueStatus``
    for the full status-lifecycle write-up.

    **"New row, not mutate" on reassignment** -- mirrors
    ``ConfigVersion``'s/``ProvisionJob``'s own identical convention already
    established elsewhere in this codebase: a "Move Queue" operation (this
    target should now use a different profile) never edits an existing,
    already-``ACTIVE`` row's ``queue_profile_id`` in place. It creates a
    **new** ``QueueAssignment`` row instead, and marks the superseded row
    ``EXPIRED`` with ``superseded_by_assignment_id`` pointing at the new
    one -- so "every past assignment for this target" (the module brief's
    own "Queue History") is simply every row here, chronological, never a
    second table.
    """

    __tablename__ = "queue_assignments"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    # Denormalized where resolvable at assignment-creation time -- mirrors
    # app.domains.provisioning_engine.models.ProvisionJob.location_id's own
    # identical "denormalize onto every child row at write time" rationale.
    # NULL for an ORGANIZATION-level default assignment (no single location
    # applies).
    location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("locations.id", ondelete="CASCADE"),
        nullable=True,
    )
    # The router a device-bound assignment is actually pushed to. Required
    # (validated in validators.py, not a DB constraint -- mirrors
    # PolicyAssignment's own validator-level, not DB-level, scope_id
    # nullability rule) for every target_type in
    # constants.DEVICE_BOUND_TARGET_TYPES; NULL for an ORGANIZATION/
    # LOCATION-level default that has not (yet) been resolved against one
    # concrete device.
    router_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("routers.id", ondelete="CASCADE"),
        nullable=True,
    )
    target_type: Mapped[str] = mapped_column(String(20), nullable=False)
    # Polymorphic -- deliberately not a real foreign key. See module
    # docstring and constants.QueueTargetType's own write-up. NULL iff
    # target_type == "organization" (organization_id above already
    # identifies it, mirrors PolicyAssignment.scope_id's own "NULL iff
    # global" convention).
    target_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    # The resolved RouterOS ``target`` value (an IP/CIDR or interface name)
    # a device-bound assignment's own ``/queue simple`` entry uses --
    # supplied by the caller (e.g. the guest-login hook, which already has
    # a session's real IP address at hand) rather than resolved by this
    # domain itself, keeping queue_management decoupled from guest/voucher/
    # session internals. NULL for an ORGANIZATION/LOCATION-level default.
    device_target: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # The device-side queue id (e.g. RouterOS's own "*1") returned by
    # BaseQueueAdapter.create_simple_queue once this assignment is first
    # applied -- required to later update/remove/read that exact queue
    # entry. NULL until apply_queue succeeds at least once.
    device_queue_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    queue_profile_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("queue_profiles.id", ondelete="SET NULL"),
        nullable=True,
    )
    queue_schedule_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("queue_schedules.id", ondelete="SET NULL"),
        nullable=True,
    )
    status: Mapped[str] = mapped_column(
        String(20), default=QueueStatus.PENDING.value, nullable=False
    )
    # Overrides QueueProfile.priority for this one assignment only, if set
    # -- e.g. a VIP guest temporarily bumped above their profile's own
    # default priority without needing a whole second QueueProfile row.
    priority_override: Mapped[int | None] = mapped_column(Integer, nullable=True)
    applied_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Set iff this row was itself superseded by a later "Move Queue"
    # operation -- points at the new row, never mutated back. See module
    # docstring.
    superseded_by_assignment_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("queue_assignments.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )

    __table_args__ = (
        Index("ix_queue_assignments_organization_id", "organization_id"),
        Index("ix_queue_assignments_location_id", "location_id"),
        Index("ix_queue_assignments_router_id", "router_id"),
        Index("ix_queue_assignments_target_type", "target_type"),
        Index("ix_queue_assignments_target_id", "target_id"),
        Index("ix_queue_assignments_status", "status"),
        Index(
            "ix_queue_assignments_superseded_by_assignment_id",
            "superseded_by_assignment_id",
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<QueueAssignment(id={self.id}, target_type={self.target_type}, "
            f"target_id={self.target_id}, status={self.status})>"
        )


__all__ = ["QueueProfile", "QueueSchedule", "QueueTemplate", "QueueAssignment"]
