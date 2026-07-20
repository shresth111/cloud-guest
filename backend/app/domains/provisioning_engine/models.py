"""SQLAlchemy ORM models for the Provisioning Engine domain.

Every table extends ``app.database.base.BaseModel`` (UUID PK, timestamps,
soft-delete, audit, version columns) for the same reason every other domain
does. Four models, deliberately not the full list of names the module brief
used (``ProvisionJob``/``ProvisionStep``/``ProvisionHistory``/
``ProvisionTimeline``/``ProvisionLog``/``ProvisionTemplate``/
``ProvisionQueue``/``ProvisionRetry``/``ProvisionRollback``) -- several of
those are real, but as **read-models or a composition pattern over these
four tables**, not separate storage, mirroring this codebase's own
established discipline (e.g. ``app.domains.router_provisioning``'s own
module docstring rejecting a dedicated ``RouterSecretRotationLog`` table for
an analogous reason -- a bespoke table duplicating facts an existing row
shape already captures):

* **History** = querying :class:`ProvisionJob` rows for a router, ordered by
  ``created_at`` (``ProvisioningEngineService.get_history``). No separate
  table -- every past run already is a row here.
* **Timeline** = a read-model aggregating one job's :class:`ProvisionStep`
  transitions plus its key :class:`ProvisionLog` entries into one ordered
  list (``ProvisioningEngineService.get_timeline``). No separate table --
  every fact it needs already lives on ``ProvisionStep``/``ProvisionLog``.
* **Queue** = the same real "Postgres row + Redis wake-up signal" mechanism
  ``app.domains.router_provisioning``'s own ``ProvisioningJob``/
  ``RedisProvisioningQueueDispatcher`` already establishes, reused via a
  structurally identical dispatcher for this domain's own job shape (see
  ``repository.py``). No separate queue table.
* **Retry** = a **new** :class:`ProvisionJob` row (``retry_of_job_id`` set),
  never a mutation of the failed row back to a running status -- mirrors
  ``ConfigVersion``'s/``PolicyVersion``'s own "new row, not mutate"
  convention. Retry *history* is therefore just "every job with the same
  retry lineage", queryable from this same table.
* **Rollback** = a **new** :class:`ProvisionJob` row (``is_rollback=True``,
  ``rollback_of_job_id`` set) whose own step sequence composes
  ``app.domains.router_provisioning.RouterProvisioningService
  .rollback_to_version``/``apply_version`` -- never a duplicated rollback
  mechanism.

None of these tables reference other domains' models by importing the
class -- only by FK'ing the target table name (``"routers.id"``,
``"config_templates.id"``, ``"policies.id"``), the exact loose-coupling
convention ``app.domains.router_provisioning.models`` already documents for
its own cross-domain FKs.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

from .constants import ProvisionJobStatus, ProvisionLogLevel, ProvisionStepStatus


class ProvisionJob(BaseModel):
    """The top-level, end-to-end orchestration run for one router -- see
    ``constants.ProvisionJobStatus`` for the full status-lifecycle
    write-up, and this module's own docstring for why retry/rollback are
    new rows here rather than separate tables/mutations."""

    __tablename__ = "provision_jobs"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    # Denormalized from the target router at job-creation time -- see
    # app.domains.guest.models.RadiusNasClient's identical, already-
    # established "denormalize onto every child table at write time"
    # convention.
    location_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("locations.id", ondelete="CASCADE"),
        nullable=False,
    )
    router_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("routers.id", ondelete="CASCADE"), nullable=False
    )
    # No FK to router_provisioning's own ConfigTemplate here -- this points
    # at THIS domain's own ProvisionTemplate (the higher-level "site
    # package"), which itself composes a ConfigTemplate (see
    # ProvisionTemplate's own docstring). Nullable: a job may be started
    # against a router that already has a ConfigProfile assigned directly,
    # with no ProvisionTemplate "package" involved at all.
    provision_template_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("provision_templates.id", ondelete="SET NULL"),
        nullable=True,
    )
    status: Mapped[str] = mapped_column(
        String(20), default=ProvisionJobStatus.PENDING.value, nullable=False
    )
    # One of constants.ProvisionStepType's values, or NULL before the job
    # has started its first step.
    current_step: Mapped[str | None] = mapped_column(String(30), nullable=True)
    progress_percent: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    # A "copy, not reference" snapshot of the effective Policy rules
    # resolved at job-creation time (via app.domains.policy
    # .PolicyService.resolve_effective_policy) -- mirrors
    # app.domains.billing.models.Invoice.billing_snapshot's/
    # app.domains.voucher's own "freeze inputs at the moment that matters"
    # convention, so a later Policy edit never silently changes what an
    # already-run (or in-flight) job was actually configured with.
    policy_snapshot: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, nullable=False
    )
    requested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Which attempt number in this job's own retry lineage this row is (1
    # for an original job, 2 for its first retry, ...) -- see
    # retry_of_job_id.
    retry_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    max_retries: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    # Set iff this row was itself created by ProvisioningEngineService
    # .retry_job -- points at the immediately-prior attempt, never
    # mutated back onto the original failed row. See module docstring.
    retry_of_job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("provision_jobs.id", ondelete="SET NULL"),
        nullable=True,
    )
    is_rollback: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # Set iff is_rollback is true -- points at the SUCCESS job this
    # rollback job is reverting. See module docstring.
    rollback_of_job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("provision_jobs.id", ondelete="SET NULL"),
        nullable=True,
    )
    # Set once THIS job's own PUSH_CONFIG step successfully creates/applies
    # a router_provisioning ConfigVersion -- lets a later rollback_job find
    # exactly what this job changed, without re-deriving it from timestamps.
    applied_config_version_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("config_versions.id", ondelete="SET NULL"),
        nullable=True,
    )
    # Set only when is_rollback is true: which router_provisioning
    # ConfigVersion this rollback job's own PUSH_CONFIG-equivalent step
    # should reapply (the version immediately before the one
    # rollback_of_job_id's own applied_config_version_id points at) --
    # computed once, at rollback_job creation time, not re-derived on every
    # step run.
    rollback_target_version_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("config_versions.id", ondelete="SET NULL"),
        nullable=True,
    )

    __table_args__ = (
        Index("ix_provision_jobs_organization_id", "organization_id"),
        Index("ix_provision_jobs_location_id", "location_id"),
        Index("ix_provision_jobs_router_id", "router_id"),
        Index("ix_provision_jobs_status", "status"),
        Index("ix_provision_jobs_retry_of_job_id", "retry_of_job_id"),
        Index("ix_provision_jobs_rollback_of_job_id", "rollback_of_job_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<ProvisionJob(id={self.id}, router_id={self.router_id}, "
            f"status={self.status})>"
        )


class ProvisionStep(BaseModel):
    """One stage within a :class:`ProvisionJob`'s real, ordered sequence --
    see ``constants.PROVISION_STEP_SEQUENCE``."""

    __tablename__ = "provision_steps"

    job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("provision_jobs.id", ondelete="CASCADE"),
        nullable=False,
    )
    step_type: Mapped[str] = mapped_column(String(30), nullable=False)
    sequence_number: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), default=ProvisionStepStatus.PENDING.value, nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Real, step-specific structured output -- e.g. DISCOVER's
    # DeviceDiscoveryResult fields, VERIFY_CONFIG's boolean match result.
    output: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("ix_provision_steps_job_id", "job_id"),
        Index("ix_provision_steps_step_type", "step_type"),
        Index("ix_provision_steps_status", "status"),
    )

    def __repr__(self) -> str:
        return (
            f"<ProvisionStep(id={self.id}, job_id={self.job_id}, "
            f"step_type={self.step_type}, status={self.status})>"
        )


class ProvisionLog(BaseModel):
    """An append-only log line for a job (optionally attributed to one of
    its steps) -- separate from RBAC's ``audit_log_entries`` for the same
    volume/retention reason ``app.domains.router_provisioning.models
    .RouterEvent`` already documents (high-volume, device-process-
    originated, not a human-attributable admin action)."""

    __tablename__ = "provision_logs"

    job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("provision_jobs.id", ondelete="CASCADE"),
        nullable=False,
    )
    step_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("provision_steps.id", ondelete="SET NULL"),
        nullable=True,
    )
    level: Mapped[str] = mapped_column(
        String(10), default=ProvisionLogLevel.INFO.value, nullable=False
    )
    message: Mapped[str] = mapped_column(Text, nullable=False)
    logged_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        Index("ix_provision_logs_job_id", "job_id"),
        Index("ix_provision_logs_step_id", "step_id"),
        Index("ix_provision_logs_logged_at", "logged_at"),
    )

    def __repr__(self) -> str:
        return f"<ProvisionLog(id={self.id}, job_id={self.job_id}, level={self.level})>"


class ProvisionTemplate(BaseModel):
    """A reusable, named provisioning "package" for a site type (Hotel,
    Apartment, Corporate, ...) -- composes an existing
    ``app.domains.router_provisioning.models.ConfigTemplate`` (the actual
    device script) and an optional ``app.domains.policy.models.Policy``
    (the default session/authN policy for sites using this package),
    bundled with real DHCP/DNS/hotspot/WireGuard/firewall/NTP/logging preset
    values (``settings``) the Configuration Generator composes at
    render/generation time. Never re-implements template rendering or
    policy resolution itself -- see ``service.py``'s own module docstring.

    ``organization_id IS NULL`` means a platform-wide system package,
    mirroring ``ConfigTemplate.organization_id``'s own identical
    convention.
    """

    __tablename__ = "provision_templates"

    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True,
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    site_type: Mapped[str] = mapped_column(String(20), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    config_template_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("config_templates.id", ondelete="SET NULL"),
        nullable=True,
    )
    default_policy_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("policies.id", ondelete="SET NULL"),
        nullable=True,
    )
    # Real DHCP/DNS/hotspot/WireGuard/firewall/NTP/logging preset values --
    # see service.py's ConfigurationGenerator for exactly which keys are
    # consumed and how.
    settings: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    __table_args__ = (
        Index("ix_provision_templates_organization_id", "organization_id"),
        Index("ix_provision_templates_site_type", "site_type"),
        Index("ix_provision_templates_is_active", "is_active"),
    )

    def __repr__(self) -> str:
        return (
            f"<ProvisionTemplate(id={self.id}, name={self.name}, "
            f"site_type={self.site_type})>"
        )


__all__ = ["ProvisionJob", "ProvisionStep", "ProvisionLog", "ProvisionTemplate"]
