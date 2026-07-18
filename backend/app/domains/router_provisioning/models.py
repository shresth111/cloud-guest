"""SQLAlchemy ORM models for the Router Provisioning domain.

Every table extends ``app.database.base.BaseModel`` (UUID PK, timestamps,
soft-delete, audit, version columns) for the same reason every other domain
does -- Alembic autogenerate, ``GenericRepository``, and cross-domain FKs all
keep working uniformly. Eight models, in four groups:

**Configuration engine** -- :class:`ConfigTemplate`, :class:`ConfigVariable`,
:class:`ConfigProfile`, :class:`ConfigVersion`.

**Provisioning workflow** -- :class:`RouterEnrollmentRequest`,
:class:`ProvisioningJob`.

**Device history** -- :class:`RouterHealthSnapshot`, :class:`RouterEvent`.

None of these reference ``app.domains.router.models.Router`` by importing
the class -- only by FK'ing its table name (``"routers.id"``), the same
loose-coupling convention ``app.domains.rbac.models`` already uses for its
own ``router_id`` columns. This module composes with the real ``Router``
row via ``RouterService`` (see ``service.py``'s ``RouterLookupProtocol``),
never by querying ``routers`` directly.

## Design decisions worth calling out up front

**Backup = a tagged ``ConfigVersion``, not a separate table.** A backup is,
structurally, exactly the same thing as any other config version: an
immutable snapshot of full rendered config text for one router at one point
in time. Giving it a second table would duplicate every column
(``router_id``, ``rendered_content``, ``created_by_user_id``, ...) for no
new information captured -- the only genuinely distinct fact a backup needs
is "this one is not part of the router's normal apply/rollback lineage, it
is a point-in-time archival copy," which a single boolean
(:attr:`ConfigVersion.is_backup`) expresses completely. ``is_backup`` rows
are excluded from "what is this router's current live config" queries (see
``ConfigVersionRepository.get_latest_applied_version``) precisely so a
backup snapshot never gets mistaken for the live pointer.

**No ``RouterSecretRotationLog`` table.** The module brief invited one
("if you judge it valuable"). It was considered and rejected: a rotation is
already fully captured by one :class:`RouterEvent` row
(``event_type="secret_rotated"``, ``router_id``, ``occurred_at``,
``event_metadata={"rotated_by_user_id": ...}``) plus one
``audit_log_entries`` row (RBAC's ``AuditAction.ROUTER_SECRET_ROTATED``) --
a bespoke third table with the same three facts (router, actor, timestamp)
would duplicate data already captured twice over, for no distinct query need
that ``RouterEvent`` filtered by ``event_type`` doesn't already answer. This
mirrors this codebase's own established discipline of not adding a table
just because a gap *might* exist (see
``docs/router/ROUTER_ARCHITECTURE.md`` §7's identical reasoning for why no
``RouterRole`` table was added either).

**Why ``RouterEvent``/``RouterHealthSnapshot`` are separate from RBAC's
``audit_log_entries``, but the significant events write to *both*.**
``audit_log_entries`` is scoped to accountable, human-attributable,
moderate-volume platform actions (who did what, when, to which entity) --
it is explicitly documented (``AuditLogEntry``'s own module docstring) as a
table "other domains could plausibly reuse," not a general telemetry sink.
``RouterEvent``/``RouterHealthSnapshot`` are a different volume/retention
profile entirely: device-originated history that can arrive far more
frequently (a health snapshot could be recorded every few minutes per
router, across every router on the platform) and is meaningful even with no
human actor at all (a queued job failing is not "someone did something").
Mixing the two into one table would force ``audit_log_entries`` either to
grow a lot of nullable device-telemetry-shaped columns it doesn't need, or
force high-volume device history to inherit an audit table's implicit
"every row is a security-relevant admin action" semantics. They are kept
separate, but every event judged genuinely significant at the *admin
action* level (enrollment approved/rejected, secret rotated) is written to
**both** tables in the same service method call -- see
``RouterProvisioningService._record_event``/``_audit`` in ``service.py``.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

from .constants import (
    ConfigVariableScope,
    ConfigVersionStatus,
    EnrollmentStatus,
    ProvisioningJobStatus,
)

# ============================================================================
# Configuration engine
# ============================================================================


class ConfigTemplate(BaseModel):
    """A reusable RouterOS config script/template with ``{{variable_name}}``
    placeholders (see ``constants.TEMPLATE_PLACEHOLDER_PATTERN`` for the
    exact supported syntax).

    ``organization_id IS NULL`` means a **platform-wide system template**,
    available to every tenant (``is_system_template`` is always ``True`` in
    that case); a non-null ``organization_id`` means an **org-specific
    custom template**, usable only by that organization's own routers
    (``is_system_template`` is always ``False``). This mirrors
    ``Router.api_credentials_encrypted``-adjacent precedent of a nullable FK
    directly expressing "platform-wide vs. tenant-owned," the same pattern
    ``Role.organization_id`` (RBAC) already uses for system vs. custom
    roles. The ``is_system_template`` boolean is kept as an explicit,
    separately-queryable column (rather than deriving "is this a system
    template" purely from ``organization_id IS NULL`` at every call site) --
    the two are validated to always agree
    (``validators.validate_template_scope``), but having the flag as a real
    column makes "list every system template" a plain equality filter
    instead of an IS NULL filter, and keeps the invariant self-documenting
    on the row itself.
    """

    __tablename__ = "config_templates"

    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True,
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_system_template: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    # e.g. "RB750Gr3", or NULL meaning "applies to any router model".
    applicable_router_model: Mapped[str | None] = mapped_column(
        String(100), nullable=True
    )
    template_content: Mapped[str] = mapped_column(Text, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    __table_args__ = (
        Index("ix_config_templates_organization_id", "organization_id"),
        Index("ix_config_templates_is_system_template", "is_system_template"),
        Index("ix_config_templates_applicable_router_model", "applicable_router_model"),
        Index("ix_config_templates_is_active", "is_active"),
        Index("ix_config_templates_name", "name"),
    )

    def __repr__(self) -> str:
        return f"<ConfigTemplate(id={self.id}, name={self.name})>"


class ConfigVariable(BaseModel):
    """A key/value pair available for template rendering, scoped at
    ``ORGANIZATION``, ``LOCATION``, or ``ROUTER`` level (see
    ``constants.ConfigVariableScope``).

    All three FKs are nullable on the table itself; which ones are actually
    populated (and non-null) is dictated by ``scope_type`` and enforced in
    ``validators.validate_variable_scope``, not by a database ``CHECK``
    constraint -- consistent with this codebase's established convention of
    enforcing this class of business rule in the service/validators layer
    rather than in the schema (mirrors ``RouterStatus``'s transition graph
    being an application-level concern, not a SQL ``CHECK``):

    * ``scope_type=ROUTER`` -- ``router_id`` required; ``location_id``/
      ``organization_id`` are also populated, denormalized from the
      router's own hierarchy at creation time (mirrors
      ``Router.organization_id``'s own denormalization precedent) purely so
      resolution queries never need a join.
    * ``scope_type=LOCATION`` -- ``location_id`` required; ``organization_id``
      denormalized from the location. ``router_id`` is ``NULL``.
    * ``scope_type=ORGANIZATION`` -- ``organization_id`` may itself be
      ``NULL``, meaning a **global default** (the lowest-precedence tier --
      see ``RouterProvisioningService.resolve_variables``). ``location_id``/
      ``router_id`` are ``NULL``.

    ``value`` is a plain ``Text`` column, not JSONB: a template placeholder
    is always substituted as flat text into a RouterOS script, so a variable
    is always, semantically, "a string" -- JSONB would model structure this
    domain never needs. When ``is_secret`` is true, ``value`` holds
    Fernet ciphertext produced by the *same*
    ``app.domains.router.crypto.encrypt_secret``/``decrypt_secret`` helpers
    Module 008 already established for ``Router.api_credentials_encrypted``
    -- this module adds no second encryption mechanism.
    """

    __tablename__ = "config_variables"

    scope_type: Mapped[str] = mapped_column(
        String(20), default=ConfigVariableScope.ORGANIZATION.value, nullable=False
    )
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True,
    )
    location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("locations.id", ondelete="CASCADE"),
        nullable=True,
    )
    router_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("routers.id", ondelete="CASCADE"),
        nullable=True,
    )
    key: Mapped[str] = mapped_column(String(150), nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    is_secret: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    __table_args__ = (
        Index("ix_config_variables_scope_type", "scope_type"),
        Index("ix_config_variables_organization_id", "organization_id"),
        Index("ix_config_variables_location_id", "location_id"),
        Index("ix_config_variables_router_id", "router_id"),
        Index("ix_config_variables_key", "key"),
    )

    def __repr__(self) -> str:
        return (
            f"<ConfigVariable(id={self.id}, scope={self.scope_type}, key={self.key})>"
        )


class ConfigProfile(BaseModel):
    """The binding that says "this router runs this template" -- assigns
    exactly one :class:`ConfigTemplate` to exactly one router at a time
    (``router_id`` is unique: re-assigning a router's template updates this
    same row rather than creating a second one, since a router has at most
    one *current* template assignment)."""

    __tablename__ = "config_profiles"

    router_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("routers.id", ondelete="CASCADE"), nullable=False
    )
    template_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("config_templates.id", ondelete="RESTRICT"),
        nullable=False,
    )
    assigned_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    assigned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("router_id", name="uq_config_profiles_router_id"),
        Index("ix_config_profiles_router_id", "router_id"),
        Index("ix_config_profiles_template_id", "template_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<ConfigProfile(router_id={self.router_id}, "
            f"template_id={self.template_id})>"
        )


class ConfigVersion(BaseModel):
    """An immutable, versioned snapshot of a *rendered* configuration
    (template + resolved variables baked together into final config text)
    for one router. ``version_number`` is sequential per router (1, 2, 3,
    ...), assigned by the service layer, never reused.

    See ``constants.ConfigVersionStatus``/``CONFIG_VERSION_STATUS_TRANSITIONS``
    for the full status lifecycle, and this module's own docstring for why
    ``is_backup`` reuses this table rather than a separate one.
    ``rollback_of_version_id`` is set exactly when this row was created by
    ``RouterProvisioningService.rollback_to_version`` (content copied from
    an earlier version) -- ``NULL`` for an ordinary forward config push.
    """

    __tablename__ = "config_versions"

    router_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("routers.id", ondelete="CASCADE"), nullable=False
    )
    profile_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("config_profiles.id", ondelete="SET NULL"),
        nullable=True,
    )
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    rendered_content: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), default=ConfigVersionStatus.DRAFT.value, nullable=False
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    applied_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    rollback_of_version_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("config_versions.id", ondelete="SET NULL"),
        nullable=True,
    )
    # See module docstring: a backup is a ConfigVersion tagged, not a
    # separate table. Excluded from "current live config" resolution.
    is_backup: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "router_id",
            "version_number",
            name="uq_config_versions_router_id_version_number",
        ),
        Index("ix_config_versions_router_id", "router_id"),
        Index("ix_config_versions_status", "status"),
        Index("ix_config_versions_rollback_of_version_id", "rollback_of_version_id"),
        Index("ix_config_versions_is_backup", "is_backup"),
    )

    def __repr__(self) -> str:
        return (
            f"<ConfigVersion(router_id={self.router_id}, "
            f"version_number={self.version_number}, status={self.status})>"
        )


# ============================================================================
# Provisioning workflow
# ============================================================================


class RouterEnrollmentRequest(BaseModel):
    """Device-initiated enrollment submitted *before* any admin-side
    ``Router`` record exists -- the device announces its serial number, MAC
    address, and model; an admin later approves (creating the real BE-008
    ``Router`` row) or rejects it.

    ``approved_router_id`` is an additive field beyond the module brief's
    literal column list: it links an approved request to the ``Router`` row
    it produced, so ``get_provisioning_status``/audit trails can trace an
    enrollment through to its resulting device record without a secondary
    lookup by serial number.
    """

    __tablename__ = "router_enrollment_requests"

    serial_number: Mapped[str] = mapped_column(String(100), nullable=False)
    mac_address: Mapped[str] = mapped_column(String(17), nullable=False)
    model: Mapped[str] = mapped_column(String(100), nullable=False)
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(20), default=EnrollmentStatus.PENDING.value, nullable=False
    )
    reviewed_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    rejection_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    approved_router_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("routers.id", ondelete="SET NULL"),
        nullable=True,
    )

    __table_args__ = (
        Index("ix_router_enrollment_requests_serial_number", "serial_number"),
        Index("ix_router_enrollment_requests_mac_address", "mac_address"),
        Index("ix_router_enrollment_requests_status", "status"),
    )

    def __repr__(self) -> str:
        return (
            f"<RouterEnrollmentRequest(id={self.id}, "
            f"serial_number={self.serial_number}, status={self.status})>"
        )


class ProvisioningJob(BaseModel):
    """A durable job record for a device-affecting action (see
    ``constants.ProvisioningJobType``): ``initial_config``, ``config_push``,
    ``backup``, ``restore``, ``factory_reset``.

    **Redis is the dispatch transport, Postgres is the durable source of
    truth.** Creating a job (i) inserts this row (status=``queued``) and
    (ii) pushes the job id onto a Redis list
    (``constants.PROVISIONING_QUEUE_REDIS_KEY``) purely as a wake-up signal
    for a future worker (``app.domains.router_agent``) to drain. Every piece
    of state that must survive a Redis restart/eviction -- status, attempt
    count, error history -- lives only in this table; Redis holds nothing
    that isn't trivially reconstructible from it. This is the same posture
    Module 004 (RBAC) already takes for ``PermissionCache``: Redis as a
    disposable acceleration/signaling layer, Postgres as ground truth.
    """

    __tablename__ = "provisioning_jobs"

    router_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("routers.id", ondelete="CASCADE"), nullable=False
    )
    job_type: Mapped[str] = mapped_column(String(30), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), default=ProvisioningJobStatus.QUEUED.value, nullable=False
    )
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    scheduled_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    requested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )

    __table_args__ = (
        Index("ix_provisioning_jobs_router_id", "router_id"),
        Index("ix_provisioning_jobs_job_type", "job_type"),
        Index("ix_provisioning_jobs_status", "status"),
        Index("ix_provisioning_jobs_scheduled_at", "scheduled_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<ProvisioningJob(id={self.id}, router_id={self.router_id}, "
            f"job_type={self.job_type}, status={self.status})>"
        )


# ============================================================================
# Device history (separate from RBAC's audit_log_entries -- see module docstring)
# ============================================================================


class RouterHealthSnapshot(BaseModel):
    """A point-in-time health/metrics reading for a router -- the
    time-series history BE-008's own single ``Router.last_health_check_at``/
    ``health_status`` "current snapshot" fields deliberately do not keep."""

    __tablename__ = "router_health_snapshots"

    router_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("routers.id", ondelete="CASCADE"), nullable=False
    )
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    health_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    cpu_usage_percent: Mapped[float | None] = mapped_column(Float, nullable=True)
    memory_usage_percent: Mapped[float | None] = mapped_column(Float, nullable=True)
    uptime_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    connected_clients_count: Mapped[int | None] = mapped_column(Integer, nullable=True)

    __table_args__ = (
        Index("ix_router_health_snapshots_router_id", "router_id"),
        Index("ix_router_health_snapshots_recorded_at", "recorded_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<RouterHealthSnapshot(router_id={self.router_id}, "
            f"recorded_at={self.recorded_at})>"
        )


class RouterEvent(BaseModel):
    """A device-history log entry (reboot, config applied, error, factory
    reset, enrollment approved, secret rotated, ...) -- see
    ``constants.RouterEventType``.

    The Python attribute is ``event_metadata`` (not ``metadata``, reserved
    by SQLAlchemy's ``DeclarativeBase``) mapped to the ``metadata`` column,
    exactly mirroring ``AuditLogEntry.event_metadata``'s own convention.
    """

    __tablename__ = "router_events"

    router_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("routers.id", ondelete="CASCADE"), nullable=False
    )
    event_type: Mapped[str] = mapped_column(String(30), nullable=False)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    event_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, default=dict, nullable=False
    )

    __table_args__ = (
        Index("ix_router_events_router_id", "router_id"),
        Index("ix_router_events_event_type", "event_type"),
        Index("ix_router_events_occurred_at", "occurred_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<RouterEvent(router_id={self.router_id}, event_type={self.event_type})>"
        )


__all__ = [
    "ConfigTemplate",
    "ConfigVariable",
    "ConfigProfile",
    "ConfigVersion",
    "RouterEnrollmentRequest",
    "ProvisioningJob",
    "RouterHealthSnapshot",
    "RouterEvent",
]
