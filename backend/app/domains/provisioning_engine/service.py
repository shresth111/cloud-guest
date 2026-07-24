"""Provisioning Engine business logic: the end-to-end orchestrator that
drives a router through Discover -> Validate -> Generate Configuration ->
Push Configuration -> Verify Configuration -> Health Check -> Monitoring
Registration -> Success, tracked as a real, resumable, retryable,
rollback-able :class:`~.models.ProvisionJob`.

## Composition, not duplication -- this is the whole point of this module

This service **never reimplements** template rendering, variable
resolution, config versioning/diffing, the device-action job queue, policy
resolution, NAS registration, or health-snapshot recording -- every one of
those already exists, real and tested, in
``app.domains.router_provisioning`` (composed via
``RouterProvisioningLookupProtocol``), ``app.domains.router`` (via
``RouterLookupProtocol``), ``app.domains.policy`` (via
``PolicyLookupProtocol``), and ``app.domains.guest``'s ``RadiusService``
(via ``NasLookupProtocol``). What is genuinely new here is the
orchestration itself: a real, ordered, tracked step sequence over all of
them, plus the one piece none of them do -- actually calling a real device
adapter (``device_adapters.py``) to perform the push/verify/health-check,
and closing ``router_provisioning``'s own long-anticipated
``complete_provisioning_job`` seam (see that module's own docstring: *"a
future app.domains.router_agent module is expected to call
complete_provisioning_job after actually performing the device-side
action"* -- this module, via ``tasks.py``, is that caller, now real).

## The GENERATE_CONFIG step's real trick: settings become variables, not a
## second rendering mechanism

A naive design would have :class:`~.models.ProvisionTemplate`'s own
``settings`` (DHCP/DNS/hotspot/WireGuard/firewall/NTP/logging presets)
generate a *second* block of config text, appended after
``router_provisioning``'s own rendered ``ConfigTemplate`` content -- two
rendering mechanisms for one config. Instead, ``GENERATE_CONFIG``
materializes each ``settings`` entry as a real, router-scoped
``ConfigVariable`` (via ``RouterProvisioningLookupProtocol
.create_variable``, tolerating ``DuplicateConfigVariableError`` as "already
seeded, fine") *before* ``PUSH_CONFIG`` calls the existing
``assign_profile``/``apply_version``. The linked ``ConfigTemplate`` is
expected to reference these same variable names as ``{{placeholders}}`` --
authored once, by whoever writes that site type's script -- so the
*existing*, unmodified ``render_template``/``resolve_variables`` pipeline
picks them up naturally. One rendering mechanism, one source of truth,
zero changes to ``router_provisioning``'s own tested code.

## Retry and rollback are new rows, never a mutation

Mirrors ``ConfigVersion``'s/``PolicyVersion``'s own "new row, not mutate"
convention, already established elsewhere in this codebase: ``retry_job``
creates a new :class:`~.models.ProvisionJob` (``retry_of_job_id`` set);
``rollback_job`` creates a new one too (``is_rollback=True``,
``rollback_of_job_id`` + ``rollback_target_version_id`` set, the latter
resolved once, at creation time, to the ``ConfigVersion`` immediately
before the one the original job applied). Neither ever flips a terminal
row back to a running state.
"""

from __future__ import annotations

import contextlib
import dataclasses
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from app.domains.policy.constants import PolicyType
from app.domains.policy.service import ResolvedPolicy
from app.domains.rbac.enums import AuditAction
from app.domains.router.models import Router
from app.domains.router_provisioning.adapters import get_provisioning_adapter
from app.domains.router_provisioning.constants import ConfigVariableScope
from app.domains.router_provisioning.exceptions import DuplicateConfigVariableError
from app.domains.router_provisioning.models import ConfigTemplate, ConfigVersion
from app.domains.router_provisioning.service import render_template

from .constants import (
    PROVISION_JOB_STATUS_TRANSITIONS,
    PROVISION_STEP_SEQUENCE,
    RETRYABLE_JOB_STATUSES,
    ROLLBACKABLE_JOB_STATUSES,
    STEP_TYPE_TO_JOB_STATUS,
    ProvisionJobStatus,
    ProvisionLogLevel,
    ProvisionStepStatus,
    ProvisionStepType,
)
from .device_adapters import (
    DeviceCredentials,
    DeviceDiscoveryResult,
    DeviceHealthResult,
    get_device_adapter,
)
from .events import (
    ProvisionJobCancelled,
    ProvisionJobCreated,
    ProvisionJobFailed,
    ProvisionJobRetried,
    ProvisionJobRolledBack,
    ProvisionJobStarted,
    ProvisionJobSucceeded,
    ProvisionStepCompleted,
)
from .exceptions import (
    InvalidProvisionJobStatusTransitionError,
    ProvisionDeviceConnectionError,
    ProvisionDeviceOperationError,
    ProvisionJobHasNoAppliedVersionError,
    ProvisionJobNotFoundError,
    ProvisionJobNotRetryableError,
    ProvisionJobNotRollbackableError,
    ProvisionJobRetryLimitExceededError,
    ProvisionMissingCredentialsError,
    ProvisionNoConfigurationSourceError,
    ProvisionNoPriorVersionToRollBackToError,
    ProvisionTemplateNotFoundError,
)
from .models import ProvisionJob, ProvisionTemplate
from .repository import ProvisioningEngineRepositoryProtocol, QueueDispatcherProtocol

logger = logging.getLogger(__name__)


def _event_extra(event: object) -> dict[str, object]:
    return {
        f"event_{f.name}": value
        if isinstance(value := getattr(event, f.name), str | int | float | bool)
        else str(value)
        for f in dataclasses.fields(event)
    }


# ============================================================================
# Narrow cross-domain protocols (composition, not duplication)
# ============================================================================


class RouterLookupProtocol(Protocol):
    async def get_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Router: ...

    async def heartbeat(
        self,
        *,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None = None,
        routeros_version: str | None = None,
        management_ip_address: str | None = None,
    ) -> Router: ...

    def get_decrypted_api_secret(self, router: Router) -> str | None: ...


class RouterProvisioningLookupProtocol(Protocol):
    """The subset of ``RouterProvisioningService``'s real surface this
    orchestrator composes -- every method here already exists, real and
    tested, in that domain. See module docstring."""

    async def get_template(
        self,
        template_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> ConfigTemplate: ...

    async def resolve_variables(self, router: Router) -> dict[str, str]: ...

    async def create_variable(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        scope_type: ConfigVariableScope,
        key: str,
        value: str,
        is_secret: bool = False,
        organization_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
        router_id: uuid.UUID | None = None,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> object: ...

    async def assign_profile(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        template_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> tuple[object, ConfigVersion]: ...

    async def apply_version(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        version_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> tuple[ConfigVersion, object]: ...

    async def start_provisioning_job(self, job_id: uuid.UUID) -> object: ...

    async def complete_provisioning_job(
        self,
        job_id: uuid.UUID,
        *,
        success: bool,
        error_message: str | None = None,
    ) -> object: ...

    async def list_versions(
        self,
        *,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[ConfigVersion], object]: ...

    async def rollback_to_version(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        target_version_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> ConfigVersion: ...

    async def record_health_snapshot(
        self,
        *,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        cpu_usage_percent: float | None = None,
        memory_usage_percent: float | None = None,
        uptime_seconds: int | None = None,
        connected_clients_count: int | None = None,
        routeros_version: str | None = None,
        management_ip_address: str | None = None,
    ) -> tuple[Router, object]: ...

    async def record_failed_health_check(
        self,
        *,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        detail: str | None = None,
    ) -> object: ...


class PolicyLookupProtocol(Protocol):
    async def resolve_effective_policy(
        self,
        *,
        policy_type: PolicyType,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
    ) -> ResolvedPolicy: ...


class NasLookupProtocol(Protocol):
    async def register_nas(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        nas_identifier: str,
        shared_secret: str | None = None,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> object: ...

    async def list_nas_clients(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        router_id: uuid.UUID | None = None,
        status: object | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[object], object]: ...


class AuditLogWriter(Protocol):
    async def create_audit_log_entry(self, **fields: object) -> object: ...


# ============================================================================
# Read models
# ============================================================================


@dataclass(frozen=True, slots=True)
class TimelineEntry:
    label: str
    occurred_at: datetime
    step_type: str | None
    status: str | None
    detail: str | None


@dataclass(frozen=True, slots=True)
class ConfigurationPreview:
    rendered_content: str
    variables_used: dict[str, str]


@dataclass(frozen=True, slots=True)
class HealthPollSweepSummary:
    """Returned by ``run_router_health_poll_sweep`` below -- mirrors
    ``app.domains.isp.service.HealthCheckSweepSummary``'s/
    ``app.domains.connected_devices.service.DeviceSyncSweepSummary``'s
    identical "plain counts, no per-router detail" shape."""

    checked: int
    unreachable: int
    skipped: int
    errors: int


# ============================================================================
# Service
# ============================================================================


class ProvisioningEngineService:
    """The Provisioning Engine's core orchestrator -- see module docstring
    for the full architectural write-up."""

    def __init__(
        self,
        repository: ProvisioningEngineRepositoryProtocol,
        router_lookup: RouterLookupProtocol,
        router_provisioning: RouterProvisioningLookupProtocol,
        policy_lookup: PolicyLookupProtocol,
        nas_lookup: NasLookupProtocol,
        *,
        queue_dispatcher: QueueDispatcherProtocol,
        audit_writer: AuditLogWriter | None = None,
        device_adapter_resolver=get_device_adapter,
    ) -> None:
        self.repository = repository
        self.router_lookup = router_lookup
        self.router_provisioning = router_provisioning
        self.policy_lookup = policy_lookup
        self.nas_lookup = nas_lookup
        self.queue_dispatcher = queue_dispatcher
        self.audit_writer = audit_writer
        self._get_device_adapter = device_adapter_resolver

    # ========================================================================
    # Job lifecycle: create / start / cancel
    # ========================================================================

    async def create_job(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        provision_template_id: uuid.UUID | None = None,
        max_retries: int = 3,
    ) -> ProvisionJob:
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        if provision_template_id is not None:
            template = await self.repository.get_template_by_id(provision_template_id)
            if template is None:
                raise ProvisionTemplateNotFoundError(provision_template_id)

        # "Copy, not reference" -- freeze the effective session policy at
        # job-creation time. See models.ProvisionJob.policy_snapshot's own
        # docstring.
        resolved_policy = await self.policy_lookup.resolve_effective_policy(
            policy_type=PolicyType.SESSION,
            organization_id=router.organization_id,
            location_id=router.location_id,
        )
        policy_snapshot = {
            "policy_type": resolved_policy.policy_type.value,
            "rules": resolved_policy.rules,
            "source": resolved_policy.source,
        }

        job = await self.repository.create_job(
            organization_id=router.organization_id,
            location_id=router.location_id,
            router_id=router.id,
            provision_template_id=provision_template_id,
            status=ProvisionJobStatus.PENDING.value,
            current_step=None,
            progress_percent=0,
            policy_snapshot=policy_snapshot,
            requested_by_user_id=actor_user_id,
            started_at=None,
            completed_at=None,
            error_message=None,
            retry_count=1,
            max_retries=max_retries,
            retry_of_job_id=None,
            is_rollback=False,
            rollback_of_job_id=None,
            applied_config_version_id=None,
            rollback_target_version_id=None,
            created_by=actor_user_id,
        )
        event = ProvisionJobCreated(job_id=job.id, router_id=router.id)
        logger.info("provision_job_created", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.PROVISION_JOB_CREATED,
            job=job,
            description=f"Provision job created for router {router.id}",
        )
        return job

    async def start_job(
        self,
        *,
        job_id: uuid.UUID,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> ProvisionJob:
        job = await self.get_job(
            job_id, requesting_organization_id=requesting_organization_id
        )
        _validate_job_transition(
            current=ProvisionJobStatus(job.status), target=ProvisionJobStatus.QUEUED
        )
        updated = await self.repository.update_job(
            job,
            {"status": ProvisionJobStatus.QUEUED.value, "updated_by": actor_user_id},
        )
        await self.queue_dispatcher.enqueue(updated.id)
        event = ProvisionJobStarted(job_id=updated.id)
        logger.info("provision_job_started", extra=_event_extra(event))
        return updated

    async def cancel_job(
        self,
        *,
        job_id: uuid.UUID,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        reason: str | None = None,
    ) -> ProvisionJob:
        job = await self.get_job(
            job_id, requesting_organization_id=requesting_organization_id
        )
        current = ProvisionJobStatus(job.status)
        _validate_job_transition(current=current, target=ProvisionJobStatus.CANCELLED)
        now = datetime.now(UTC)
        updated = await self.repository.update_job(
            job,
            {
                "status": ProvisionJobStatus.CANCELLED.value,
                "completed_at": now,
                "error_message": reason,
                "updated_by": actor_user_id,
            },
        )
        # Mark every not-yet-terminal step SKIPPED rather than leaving them
        # PENDING/RUNNING forever.
        for step in await self.repository.list_steps_for_job(job.id):
            if step.status in (
                ProvisionStepStatus.PENDING.value,
                ProvisionStepStatus.RUNNING.value,
            ):
                await self.repository.update_step(
                    step, {"status": ProvisionStepStatus.SKIPPED.value}
                )
        await self._log(
            job.id,
            None,
            ProvisionLogLevel.WARNING,
            f"Job cancelled: {reason or 'no reason given'}",
        )
        event = ProvisionJobCancelled(job_id=updated.id, reason=reason)
        logger.info("provision_job_cancelled", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.PROVISION_JOB_CANCELLED,
            job=updated,
            description=f"Provision job {updated.id} cancelled",
        )
        return updated

    async def retry_job(
        self,
        *,
        job_id: uuid.UUID,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> ProvisionJob:
        job = await self.get_job(
            job_id, requesting_organization_id=requesting_organization_id
        )
        if ProvisionJobStatus(job.status) not in RETRYABLE_JOB_STATUSES:
            raise ProvisionJobNotRetryableError(job.id, job.status)
        if job.retry_count >= job.max_retries:
            raise ProvisionJobRetryLimitExceededError(job.id, job.max_retries)

        new_job = await self.repository.create_job(
            organization_id=job.organization_id,
            location_id=job.location_id,
            router_id=job.router_id,
            provision_template_id=job.provision_template_id,
            status=ProvisionJobStatus.PENDING.value,
            current_step=None,
            progress_percent=0,
            policy_snapshot=job.policy_snapshot,
            requested_by_user_id=actor_user_id,
            started_at=None,
            completed_at=None,
            error_message=None,
            retry_count=job.retry_count + 1,
            max_retries=job.max_retries,
            retry_of_job_id=job.id,
            is_rollback=False,
            rollback_of_job_id=None,
            applied_config_version_id=None,
            rollback_target_version_id=None,
            created_by=actor_user_id,
        )
        started = await self.start_job(
            job_id=new_job.id,
            actor_user_id=actor_user_id,
            requesting_organization_id=requesting_organization_id,
        )
        event = ProvisionJobRetried(job_id=started.id, retry_of_job_id=job.id)
        logger.info("provision_job_retried", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.PROVISION_JOB_RETRIED,
            job=started,
            description=f"Provision job {job.id} retried as {started.id}",
        )
        return started

    async def rollback_job(
        self,
        *,
        job_id: uuid.UUID,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> ProvisionJob:
        job = await self.get_job(
            job_id, requesting_organization_id=requesting_organization_id
        )
        if ProvisionJobStatus(job.status) not in ROLLBACKABLE_JOB_STATUSES:
            raise ProvisionJobNotRollbackableError(job.id, job.status)
        if job.applied_config_version_id is None:
            raise ProvisionJobHasNoAppliedVersionError(job.id)

        versions, _meta = await self.router_provisioning.list_versions(
            router_id=job.router_id,
            requesting_organization_id=requesting_organization_id,
            page=1,
            page_size=100,
        )
        applied_version = next(
            (v for v in versions if v.id == job.applied_config_version_id), None
        )
        if applied_version is None:
            raise ProvisionJobHasNoAppliedVersionError(job.id)
        target_version = next(
            (
                v
                for v in versions
                if v.version_number == applied_version.version_number - 1
            ),
            None,
        )
        if target_version is None:
            raise ProvisionNoPriorVersionToRollBackToError(job.id)

        new_job = await self.repository.create_job(
            organization_id=job.organization_id,
            location_id=job.location_id,
            router_id=job.router_id,
            provision_template_id=job.provision_template_id,
            status=ProvisionJobStatus.PENDING.value,
            current_step=None,
            progress_percent=0,
            policy_snapshot=job.policy_snapshot,
            requested_by_user_id=actor_user_id,
            started_at=None,
            completed_at=None,
            error_message=None,
            retry_count=1,
            max_retries=job.max_retries,
            retry_of_job_id=None,
            is_rollback=True,
            rollback_of_job_id=job.id,
            applied_config_version_id=None,
            rollback_target_version_id=target_version.id,
            created_by=actor_user_id,
        )
        started = await self.start_job(
            job_id=new_job.id,
            actor_user_id=actor_user_id,
            requesting_organization_id=requesting_organization_id,
        )
        event = ProvisionJobRolledBack(job_id=started.id, rollback_of_job_id=job.id)
        logger.info("provision_job_rollback_started", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.PROVISION_JOB_ROLLED_BACK,
            job=started,
            description=f"Rollback of provision job {job.id} started as {started.id}",
        )
        return started

    # ========================================================================
    # Reads
    # ========================================================================

    async def get_job(
        self,
        job_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> ProvisionJob:
        job = await self.repository.get_job_by_id(job_id)
        if job is None:
            raise ProvisionJobNotFoundError(job_id)
        if (
            requesting_organization_id is not None
            and job.organization_id != requesting_organization_id
        ):
            raise ProvisionJobNotFoundError(job_id)
        return job

    async def list_jobs(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        status: ProvisionJobStatus | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[ProvisionJob], object]:
        filters: dict[str, object] = {}
        if requesting_organization_id is not None:
            filters["organization_id"] = requesting_organization_id
        if router_id is not None:
            filters["router_id"] = router_id
        if status is not None:
            filters["status"] = status.value
        return await self.repository.list_jobs(
            page=page, page_size=page_size, filters=filters or None
        )

    async def get_history(
        self,
        *,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[ProvisionJob], object]:
        """Every past ``ProvisionJob`` (original, retries, rollbacks) for
        one router, chronological -- a read-model over this same table, not
        a separate history table. See module docstring."""
        return await self.list_jobs(
            requesting_organization_id=requesting_organization_id,
            router_id=router_id,
            page=page,
            page_size=page_size,
        )

    async def get_timeline(
        self,
        job_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
    ) -> list[TimelineEntry]:
        """A real read-model aggregating a job's own ``ProvisionStep``
        transitions and ``ProvisionLog`` entries into one ordered list --
        no separate timeline table. See module docstring."""
        job = await self.get_job(
            job_id, requesting_organization_id=requesting_organization_id
        )
        steps = await self.repository.list_steps_for_job(job.id)
        logs = await self.repository.list_logs_for_job(job.id)

        entries: list[TimelineEntry] = []
        for step in steps:
            if step.started_at is not None:
                entries.append(
                    TimelineEntry(
                        label=f"{step.step_type} started",
                        occurred_at=step.started_at,
                        step_type=step.step_type,
                        status=ProvisionStepStatus.RUNNING.value,
                        detail=None,
                    )
                )
            if step.completed_at is not None:
                entries.append(
                    TimelineEntry(
                        label=f"{step.step_type} {step.status}",
                        occurred_at=step.completed_at,
                        step_type=step.step_type,
                        status=step.status,
                        detail=step.error_message,
                    )
                )
        for log in logs:
            entries.append(
                TimelineEntry(
                    label=log.message,
                    occurred_at=log.logged_at,
                    step_type=None,
                    status=log.level,
                    detail=None,
                )
            )
        entries.sort(key=lambda e: e.occurred_at)
        return entries

    # ========================================================================
    # Standalone, ad-hoc actions (also used internally by the step runner)
    # ========================================================================

    async def discover_device(
        self,
        *,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> DeviceDiscoveryResult:
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        credentials = self._resolve_device_credentials(router)
        adapter = self._get_device_adapter(router.vendor)
        result = await adapter.discover(credentials)
        await self.router_lookup.heartbeat(
            router_id=router.id,
            requesting_organization_id=requesting_organization_id,
            routeros_version=result.firmware_version,
            management_ip_address=router.management_ip_address,
        )
        return result

    async def validate_device(
        self,
        *,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        provision_template_id: uuid.UUID | None = None,
    ) -> None:
        """Raises on any real validation failure; returns ``None`` on
        success. Real checks: the router has connection credentials, its
        vendor has a registered device adapter, and (if a
        ``ProvisionTemplate`` is supplied) its linked ``ConfigTemplate``'s
        own vendor is compatible with the router's."""
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        self._resolve_device_credentials(router)  # raises if missing
        self._get_device_adapter(router.vendor)  # raises if unsupported

        if provision_template_id is not None:
            template = await self._get_provision_template(provision_template_id)
            if template.config_template_id is not None:
                config_template = await self.router_provisioning.get_template(
                    template.config_template_id,
                    requesting_organization_id=requesting_organization_id,
                )
                get_provisioning_adapter(router.vendor).validate_template_compatibility(
                    template_vendor=config_template.vendor
                )

    async def generate_configuration(
        self,
        *,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        provision_template_id: uuid.UUID,
        actor_user_id: uuid.UUID | None = None,
    ) -> ConfigurationPreview:
        """Seeds real ``ConfigVariable`` rows from the
        ``ProvisionTemplate.settings`` (tolerating already-seeded values),
        registers a NAS for this router if none exists yet, then renders a
        preview using the exact same, unmodified
        ``RouterProvisioningLookupProtocol.resolve_variables``. Never
        creates a ``ConfigVersion`` itself -- that is ``PUSH_CONFIG``'s job
        (via ``assign_profile``)."""
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        template = await self._get_provision_template(provision_template_id)
        if template.config_template_id is None:
            raise ProvisionTemplateNotFoundError(provision_template_id)

        for key, value in _flatten_settings(template.settings).items():
            # Already seeded -- a router-scoped override wins, fine.
            with contextlib.suppress(DuplicateConfigVariableError):
                await self.router_provisioning.create_variable(
                    actor_user_id=actor_user_id,
                    scope_type=ConfigVariableScope.ROUTER,
                    key=key,
                    value=str(value),
                    router_id=router.id,
                    requesting_organization_id=requesting_organization_id,
                )

        existing_nas, _meta = await self.nas_lookup.list_nas_clients(
            requesting_organization_id=requesting_organization_id,
            router_id=router.id,
            page=1,
            page_size=1,
        )
        if not existing_nas:
            await self.nas_lookup.register_nas(
                actor_user_id=actor_user_id,
                router_id=router.id,
                nas_identifier=f"router-{router.id}",
                requesting_organization_id=requesting_organization_id,
            )

        config_template = await self.router_provisioning.get_template(
            template.config_template_id,
            requesting_organization_id=requesting_organization_id,
        )
        variables = await self.router_provisioning.resolve_variables(router)
        rendered = render_template(config_template.template_content, variables)
        return ConfigurationPreview(rendered_content=rendered, variables_used=variables)

    # ========================================================================
    # The full step-sequence runner -- called by tasks.py's real Celery task
    # ========================================================================

    async def run_provision_job(self, job_id: uuid.UUID) -> ProvisionJob:
        """Runs every step in ``constants.PROVISION_STEP_SEQUENCE`` (or, for
        a rollback job, the rollback-equivalent sequence) in order, updating
        ``job.status``/``current_step``/``progress_percent`` as it goes.
        Stops and marks the job ``FAILED`` the moment any step fails --
        never continues past a failure (unlike the per-item failure
        isolation this codebase's own *batch* sweeps use elsewhere, a
        single router's own provisioning steps are strictly sequential and
        dependent: pushing a config to a router that failed discovery would
        be a real, dangerous mistake, not a resilience win)."""
        job = await self.repository.get_job_by_id(job_id)
        if job is None:
            raise ProvisionJobNotFoundError(job_id)

        now = datetime.now(UTC)
        job = await self.repository.update_job(
            job, {"status": ProvisionJobStatus.RUNNING.value, "started_at": now}
        )

        total_steps = len(PROVISION_STEP_SEQUENCE)
        for index, step_type in enumerate(PROVISION_STEP_SEQUENCE, start=1):
            job_status = STEP_TYPE_TO_JOB_STATUS[step_type]
            job = await self.repository.update_job(
                job,
                {
                    "status": job_status.value,
                    "current_step": step_type.value,
                    "progress_percent": int((index - 1) / total_steps * 100),
                },
            )
            step = await self.repository.create_step(
                job_id=job.id,
                step_type=step_type.value,
                sequence_number=index,
                status=ProvisionStepStatus.RUNNING.value,
                started_at=datetime.now(UTC),
                completed_at=None,
                output={},
                error_message=None,
            )
            await self._log(
                job.id, step.id, ProvisionLogLevel.INFO, f"{step_type.value} started"
            )
            try:
                output = await self._run_step(job, step_type)
            except (
                ProvisionDeviceConnectionError,
                ProvisionDeviceOperationError,
                ProvisionMissingCredentialsError,
                ProvisionNoConfigurationSourceError,
                ProvisionNoPriorVersionToRollBackToError,
            ) as exc:
                await self.repository.update_step(
                    step,
                    {
                        "status": ProvisionStepStatus.FAILED.value,
                        "completed_at": datetime.now(UTC),
                        "error_message": str(exc),
                    },
                )
                await self._log(job.id, step.id, ProvisionLogLevel.ERROR, str(exc))
                return await self._fail_job(job, str(exc))

            await self.repository.update_step(
                step,
                {
                    "status": ProvisionStepStatus.SUCCEEDED.value,
                    "completed_at": datetime.now(UTC),
                    "output": output,
                },
            )
            event = ProvisionStepCompleted(job_id=job.id, step_type=step_type.value)
            logger.info("provision_step_completed", extra=_event_extra(event))
            await self._log(
                job.id, step.id, ProvisionLogLevel.INFO, f"{step_type.value} succeeded"
            )

        completed = await self.repository.update_job(
            job,
            {
                "status": ProvisionJobStatus.SUCCESS.value,
                "current_step": None,
                "progress_percent": 100,
                "completed_at": datetime.now(UTC),
            },
        )
        event = ProvisionJobSucceeded(job_id=completed.id)
        logger.info("provision_job_succeeded", extra=_event_extra(event))
        await self._audit(
            completed.requested_by_user_id,
            AuditAction.PROVISION_JOB_SUCCEEDED,
            job=completed,
            description=f"Provision job {completed.id} succeeded",
        )

        if completed.is_rollback and completed.rollback_of_job_id is not None:
            original = await self.repository.get_job_by_id(completed.rollback_of_job_id)
            if original is not None:
                await self.repository.update_job(
                    original, {"status": ProvisionJobStatus.ROLLED_BACK.value}
                )

        return completed

    async def _fail_job(self, job: ProvisionJob, error_message: str) -> ProvisionJob:
        failed = await self.repository.update_job(
            job,
            {
                "status": ProvisionJobStatus.FAILED.value,
                "completed_at": datetime.now(UTC),
                "error_message": error_message,
            },
        )
        event = ProvisionJobFailed(job_id=failed.id, error_message=error_message)
        logger.info("provision_job_failed", extra=_event_extra(event))
        await self._audit(
            failed.requested_by_user_id,
            AuditAction.PROVISION_JOB_FAILED,
            job=failed,
            description=f"Provision job {failed.id} failed: {error_message}",
        )
        return failed

    async def _run_step(
        self, job: ProvisionJob, step_type: ProvisionStepType
    ) -> dict[str, Any]:
        if step_type is ProvisionStepType.DISCOVER:
            return await self._step_discover(job)
        if step_type is ProvisionStepType.VALIDATE:
            return await self._step_validate(job)
        if step_type is ProvisionStepType.GENERATE_CONFIG:
            return await self._step_generate_config(job)
        if step_type is ProvisionStepType.PUSH_CONFIG:
            return await self._step_push_config(job)
        if step_type is ProvisionStepType.VERIFY_CONFIG:
            return await self._step_verify_config(job)
        if step_type is ProvisionStepType.HEALTH_CHECK:
            return await self._step_health_check(job)
        return await self._step_register_monitoring(job)

    async def _step_discover(self, job: ProvisionJob) -> dict[str, Any]:
        result = await self.discover_device(
            router_id=job.router_id, requesting_organization_id=job.organization_id
        )
        return dataclasses.asdict(result)

    async def _step_validate(self, job: ProvisionJob) -> dict[str, Any]:
        await self.validate_device(
            router_id=job.router_id,
            requesting_organization_id=job.organization_id,
            provision_template_id=job.provision_template_id,
        )
        return {"validated": True}

    async def _step_generate_config(self, job: ProvisionJob) -> dict[str, Any]:
        if job.is_rollback:
            return {"skipped": "rollback jobs reuse an existing prior version"}
        if job.provision_template_id is None:
            return {"skipped": "no provision_template_id set on this job"}
        preview = await self.generate_configuration(
            router_id=job.router_id,
            requesting_organization_id=job.organization_id,
            provision_template_id=job.provision_template_id,
            actor_user_id=job.requested_by_user_id,
        )
        return {"variables_used": preview.variables_used}

    async def _step_push_config(self, job: ProvisionJob) -> dict[str, Any]:
        router = await self.router_lookup.get_router(
            job.router_id, requesting_organization_id=job.organization_id
        )
        credentials = self._resolve_device_credentials(router)
        adapter = self._get_device_adapter(router.vendor)

        if job.is_rollback:
            if job.rollback_target_version_id is None:
                raise ProvisionNoPriorVersionToRollBackToError(job.id)
            version = await self.router_provisioning.rollback_to_version(
                actor_user_id=job.requested_by_user_id,
                router_id=router.id,
                target_version_id=job.rollback_target_version_id,
                requesting_organization_id=job.organization_id,
            )
        elif job.provision_template_id is not None:
            template = await self._get_provision_template(job.provision_template_id)
            _profile, version = await self.router_provisioning.assign_profile(
                actor_user_id=job.requested_by_user_id,
                router_id=router.id,
                template_id=template.config_template_id,
                requesting_organization_id=job.organization_id,
            )
        else:
            # No provision_template_id -- this job runs against a router
            # that already has a ConfigProfile/ConfigVersion assigned
            # directly, outside this orchestrator (see
            # models.ProvisionJob.provision_template_id's own docstring).
            # Re-push whatever is already the router's latest version.
            versions, _meta = await self.router_provisioning.list_versions(
                router_id=router.id,
                requesting_organization_id=job.organization_id,
                page=1,
                page_size=1,
            )
            if not versions:
                raise ProvisionNoConfigurationSourceError(router.id)
            version = versions[0]

        _updated_version, rp_job = await self.router_provisioning.apply_version(
            actor_user_id=job.requested_by_user_id,
            router_id=router.id,
            version_id=version.id,
            requesting_organization_id=job.organization_id,
        )
        await self.router_provisioning.start_provisioning_job(rp_job.id)

        try:
            await adapter.push_config(
                credentials, config_content=version.rendered_content
            )
        except (ProvisionDeviceConnectionError, ProvisionDeviceOperationError) as exc:
            await self.router_provisioning.complete_provisioning_job(
                rp_job.id, success=False, error_message=str(exc)
            )
            raise

        await self.router_provisioning.complete_provisioning_job(
            rp_job.id, success=True
        )
        await self.repository.update_job(job, {"applied_config_version_id": version.id})
        return {
            "config_version_id": str(version.id),
            "router_provisioning_job_id": str(rp_job.id),
        }

    async def _step_verify_config(self, job: ProvisionJob) -> dict[str, Any]:
        router = await self.router_lookup.get_router(
            job.router_id, requesting_organization_id=job.organization_id
        )
        credentials = self._resolve_device_credentials(router)
        adapter = self._get_device_adapter(router.vendor)
        versions, _meta = await self.router_provisioning.list_versions(
            router_id=router.id,
            requesting_organization_id=job.organization_id,
            page=1,
            page_size=1,
        )
        latest = versions[0] if versions else None
        expected_content = latest.rendered_content if latest else ""
        matched = await adapter.verify_config(
            credentials, expected_content=expected_content
        )
        if not matched:
            raise ProvisionDeviceOperationError(
                "verify_config", "pushed configuration does not match expected content"
            )
        return {"matched": matched}

    async def _step_health_check(self, job: ProvisionJob) -> dict[str, Any]:
        router = await self.router_lookup.get_router(
            job.router_id, requesting_organization_id=job.organization_id
        )
        credentials = self._resolve_device_credentials(router)
        adapter = self._get_device_adapter(router.vendor)
        result: DeviceHealthResult = await adapter.health_check(credentials)
        if not result.healthy:
            raise ProvisionDeviceOperationError(
                "health_check", result.detail or "unhealthy"
            )
        return dataclasses.asdict(result)

    async def _step_register_monitoring(self, job: ProvisionJob) -> dict[str, Any]:
        steps = await self.repository.list_steps_for_job(job.id)
        health_step = next(
            (s for s in steps if s.step_type == ProvisionStepType.HEALTH_CHECK.value),
            None,
        )
        health_output = health_step.output if health_step else {}
        _router, snapshot = await self.router_provisioning.record_health_snapshot(
            router_id=job.router_id,
            requesting_organization_id=job.organization_id,
            cpu_usage_percent=health_output.get("cpu_load_percent"),
            uptime_seconds=health_output.get("uptime_seconds"),
        )
        return {"health_snapshot_id": str(snapshot.id)}

    # ========================================================================
    # ProvisionTemplate CRUD
    # ========================================================================

    async def create_template(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        name: str,
        site_type: str,
        description: str | None = None,
        config_template_id: uuid.UUID | None = None,
        default_policy_id: uuid.UUID | None = None,
        settings: dict[str, Any] | None = None,
        is_active: bool = True,
    ) -> ProvisionTemplate:
        return await self.repository.create_template(
            organization_id=requesting_organization_id,
            name=name,
            site_type=site_type,
            description=description,
            config_template_id=config_template_id,
            default_policy_id=default_policy_id,
            settings=settings or {},
            is_active=is_active,
            created_by=actor_user_id,
        )

    async def get_template(self, template_id: uuid.UUID) -> ProvisionTemplate:
        return await self._get_provision_template(template_id)

    async def list_templates(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[ProvisionTemplate], object]:
        filters: dict[str, object] = {}
        if requesting_organization_id is not None:
            filters["organization_id"] = requesting_organization_id
        return await self.repository.list_templates(
            page=page, page_size=page_size, filters=filters or None
        )

    async def _get_provision_template(
        self, template_id: uuid.UUID | None
    ) -> ProvisionTemplate:
        if template_id is None:
            raise ProvisionTemplateNotFoundError(template_id)
        template = await self.repository.get_template_by_id(template_id)
        if template is None:
            raise ProvisionTemplateNotFoundError(template_id)
        return template

    # ========================================================================
    # Internal helpers
    # ========================================================================

    def _resolve_device_credentials(self, router: Router) -> DeviceCredentials:
        host = router.management_ip_address or router.public_ip_address
        secret = self.router_lookup.get_decrypted_api_secret(router)
        if not host or not router.api_username or not secret:
            raise ProvisionMissingCredentialsError(router.id)
        return DeviceCredentials(
            host=host, username=router.api_username, password=secret
        )

    async def _log(
        self,
        job_id: uuid.UUID,
        step_id: uuid.UUID | None,
        level: ProvisionLogLevel,
        message: str,
    ) -> None:
        await self.repository.create_log(
            job_id=job_id,
            step_id=step_id,
            level=level.value,
            message=message,
            logged_at=datetime.now(UTC),
        )

    async def _audit(
        self,
        actor_user_id: uuid.UUID | None,
        action: AuditAction,
        *,
        job: ProvisionJob,
        description: str,
    ) -> None:
        if self.audit_writer is None:
            return
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=actor_user_id,
            action=action.value,
            entity_type="provision_job",
            entity_id=job.id,
            description=description,
            organization_id=job.organization_id,
            location_id=job.location_id,
        )


async def run_router_health_poll_sweep(
    repository: ProvisioningEngineRepositoryProtocol,
    router_lookup: RouterLookupProtocol,
    router_provisioning: RouterProvisioningLookupProtocol,
    *,
    device_adapter_resolver=get_device_adapter,
) -> HealthPollSweepSummary:
    """The platform-wide router device-health poll sweep
    ``tasks.run_router_health_poll_sweep`` (Celery Beat) drives -- pulled
    out to module scope for the identical "Celery task + test suite share
    one real implementation, no live Postgres needed for the latter" reason
    ``app.domains.isp.service.run_health_check_sweep``/
    ``app.domains.connected_devices.service.run_device_sync_sweep`` were.

    ## Pull, not push -- and why this is the right choice

    ``app.domains.router_provisioning.models.RouterHealthSnapshot``/
    ``RouterProvisioningService.record_health_snapshot`` have existed since
    that domain's own first pass, but nothing has ever called them on a
    schedule. Two real, already-existing mechanisms could plausibly drive
    that call, and they are genuinely different architectures for the same
    concept:

    * **Pull** (this sweep): ``device_adapters.MikroTikProvisionAdapter
      .health_check`` -- the server actively reaches out to each router's
      real RouterOS API (``/system/resource/print``) on its own schedule.
    * **Push**: ``app.domains.router_agent``'s heartbeat
      (``POST /agent/heartbeat``) -- the *device* initiates contact, and
      that arrival is already its own trigger for recording a liveness
      signal (see ``RouterAgentService.heartbeat``); it needs no separate
      sweep to drive it, and building one that tried to would just be a
      sweep silently doing nothing between real device check-ins.

    A server-side *sweep* only makes sense for the pull architecture --
    hence this task calls ``health_check``, never touches the heartbeat
    path.

    ## Per-router failure isolation, and the two outcomes recorded
    differently

    Every router is polled independently; one router's own connection
    failure/timeout/missing-credentials never aborts the sweep for the
    rest (mirrors ``run_health_check_sweep``'s/``run_device_sync_sweep``'s
    identical per-item isolation contract). A device that does not answer
    at all is an expected, honest, non-fatal outcome per
    ``device_adapters``'s own "real client code, never fabricates success"
    module docstring -- ``health_check`` itself already returns
    ``DeviceHealthResult(healthy=False, ...)`` rather than raising for a
    connection failure, but this sweep additionally guards the whole
    per-router iteration with a broad ``except Exception`` for anything
    else that goes wrong (an unexpected adapter bug, a
    ``ProvisionDeviceOperationError`` from a post-connection RouterOS
    command failure, ...). A router with no ``management_ip_address``/
    ``api_username``/decrypted secret on file yet is skipped outright
    (``skipped``, not ``errors``) -- there is nothing to even attempt.

    On a successful read (``healthy=True``), records a full
    ``RouterHealthSnapshot`` via ``record_health_snapshot`` (which also
    calls ``RouterService.heartbeat`` -- the device really did just answer,
    so that liveness signal is honest). On an unreachable read
    (``healthy=False``), records the failed reading via
    ``record_failed_health_check`` instead -- see that method's own
    docstring for why it deliberately never calls ``heartbeat``."""
    routers = await repository.list_routers_for_health_poll()
    checked = 0
    unreachable = 0
    skipped = 0
    errors = 0
    for router in routers:
        try:
            host = router.management_ip_address or router.public_ip_address
            secret = router_lookup.get_decrypted_api_secret(router)
            if not host or not router.api_username or not secret:
                skipped += 1
                continue
            credentials = DeviceCredentials(
                host=host, username=router.api_username, password=secret
            )
            adapter = device_adapter_resolver(router.vendor)
            result: DeviceHealthResult = await adapter.health_check(credentials)
            if result.healthy:
                await router_provisioning.record_health_snapshot(
                    router_id=router.id,
                    requesting_organization_id=router.organization_id,
                    cpu_usage_percent=result.cpu_load_percent,
                    uptime_seconds=result.uptime_seconds,
                )
                checked += 1
            else:
                await router_provisioning.record_failed_health_check(
                    router_id=router.id,
                    requesting_organization_id=router.organization_id,
                    detail=result.detail,
                )
                unreachable += 1
                logger.warning(
                    "router_health_poll_sweep_router_unreachable",
                    extra={"router_id": str(router.id), "detail": result.detail},
                )
        except Exception as exc:  # noqa: BLE001 -- per-router isolation, see docstring
            errors += 1
            logger.warning(
                "router_health_poll_sweep_router_failed",
                extra={"router_id": str(router.id), "error": str(exc)},
            )
    return HealthPollSweepSummary(
        checked=checked, unreachable=unreachable, skipped=skipped, errors=errors
    )


def _validate_job_transition(
    *, current: ProvisionJobStatus, target: ProvisionJobStatus
) -> None:
    legal_targets = PROVISION_JOB_STATUS_TRANSITIONS.get(current, frozenset())
    if target not in legal_targets:
        raise InvalidProvisionJobStatusTransitionError(current.value, target.value)


def _flatten_settings(settings: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    """Flattens ``ProvisionTemplate.settings`` (which may nest, e.g.
    ``{"ntp": {"primary": "pool.ntp.org"}}``) into flat
    ``ntp_primary``-style variable names ``render_template``'s
    ``{{variable_name}}`` placeholder syntax can reference."""
    flat: dict[str, Any] = {}
    for key, value in settings.items():
        flat_key = f"{prefix}{key}" if not prefix else f"{prefix}_{key}"
        if isinstance(value, dict):
            flat.update(_flatten_settings(value, flat_key))
        elif isinstance(value, list):
            flat[flat_key] = ",".join(str(v) for v in value)
        else:
            flat[flat_key] = value
    return flat


__all__ = [
    "ProvisioningEngineService",
    "RouterLookupProtocol",
    "RouterProvisioningLookupProtocol",
    "PolicyLookupProtocol",
    "NasLookupProtocol",
    "AuditLogWriter",
    "TimelineEntry",
    "ConfigurationPreview",
    "HealthPollSweepSummary",
    "run_router_health_poll_sweep",
]
