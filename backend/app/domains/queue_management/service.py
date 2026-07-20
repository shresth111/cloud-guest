"""Queue Management Engine business logic: the vendor-agnostic bandwidth/
QoS orchestrator. Assigns a real, reusable :class:`~.models.QueueProfile`
to a target (organization/location/router/guest team/guest/voucher/device/
session -- see :class:`~.constants.QueueTargetType`), pushes it to a real
device through :class:`~.device_adapters.BaseQueueAdapter`, and resolves
what profile a target should get in the first place by composing
``app.domains.policy``'s own ``PolicyType.BANDWIDTH`` rules -- never
re-implementing policy resolution, device connection, or router lookup
itself.

## Composition, not duplication

This service composes ``app.domains.router.service.RouterService`` (via
``RouterLookupProtocol`` -- router existence/tenant-scoping, decrypted API
credentials) and ``app.domains.policy.service.PolicyService`` (via
``PolicyLookupProtocol`` -- ``resolve_effective_policy`` for
``PolicyType.BANDWIDTH``). It never composes ``app.domains.guest``/
``app.domains.voucher``/``app.domains.guest_teams`` directly: a
:class:`~.models.QueueAssignment`'s ``target_id`` is polymorphic and
deliberately not deep-validated against those domains' own tables (mirrors
``app.domains.policy.models.PolicyAssignment.scope_id``'s own "not a real
foreign key" stance) -- the caller (an admin via the REST API, or the
guest-login hook in ``app.domains.guest.service.GuestService``, see that
module's own additive ``queue_assignment_hook``) is responsible for
supplying a real, already-known ``target_id`` and ``device_target`` (the
RouterOS ``target`` string -- an IP/CIDR or interface), not this service.

## Apply / Remove *are* Enable / Disable

The module brief names four operations -- "Apply Queue", "Remove Queue",
"Enable Queue", "Disable Queue" -- as if they were four distinct actions.
They are two: ``apply_queue`` (push the profile's rates to the device,
``PENDING``/``DISABLED``/``SUSPENDED`` -> ``ACTIVE`` -- "enabling" a queue
*is* applying it) and ``remove_queue`` (pull the live queue off the device,
``ACTIVE`` -> ``DISABLED`` -- "disabling" a queue *is* removing it,
keeping the row for a later re-apply). Naming four separate methods that
collapse into the same two real device operations would be a fake
distinction, not a real one.

## Move Queue: a new row, not a mutation

Mirrors ``app.domains.provisioning_engine``'s own ``retry_job``/
``rollback_job`` convention (itself mirroring ``ConfigVersion``'s "new row,
not mutate"): reassigning a target to a different profile
(``move_queue``) never edits an ``ACTIVE`` row's own ``queue_profile_id``
in place. It creates a **new** ``QueueAssignment`` row and marks the old
one ``EXPIRED`` with ``superseded_by_assignment_id`` set -- so "Queue
History" (the module brief's own entity) is simply every
``QueueAssignment`` row for a target, chronological, never a second table
(see ``models.py``'s own module docstring).

## Time-based policies: evaluated at apply time, kept correct by a sweep

A :class:`~.models.QueueAssignment` scoped to a :class:`~.models.QueueSchedule`
is only ever pushed to the device while that schedule's window is
currently open -- ``apply_queue`` checks ``is_schedule_active_now`` itself
and, when the window is currently closed, records the assignment as
``SUSPENDED`` without ever attempting a device connection. ``tasks.py``'s
own Beat-scheduled sweep re-evaluates every schedule-bound assignment
periodically and calls ``apply_queue``/``remove_queue`` again the moment a
window opens or closes -- see that module's own docstring.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, time
from typing import Any, Protocol

from app.domains.policy.constants import PolicyType
from app.domains.policy.schemas import BandwidthPolicyRules
from app.domains.rbac.enums import AuditAction
from app.domains.router.models import Router

from .constants import (
    APPLICABLE_QUEUE_STATUSES,
    DEFAULT_QUEUE_PRIORITY,
    REMOVABLE_QUEUE_STATUSES,
    UNLIMITED_RATE_KBPS,
    QueueScheduleType,
    QueueStatus,
    QueueTargetType,
    QueueType,
)
from .device_adapters import QueueCredentials, get_queue_adapter
from .exceptions import (
    CrossOrganizationQueueAccessError,
    QueueAssignmentNotApplicableError,
    QueueAssignmentNotFoundError,
    QueueAssignmentNotRemovableError,
    QueueMissingCredentialsError,
    QueueProfileNotFoundError,
    QueueScheduleNotFoundError,
    QueueTemplateNotFoundError,
)
from .models import QueueAssignment, QueueProfile, QueueSchedule, QueueTemplate
from .repository import QueueManagementRepositoryProtocol
from .validators import validate_status_transition, validate_target

_SYSTEM_UNLIMITED_PROFILE_NAME = "Unlimited"


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

    def get_decrypted_api_secret(self, router: Router) -> str | None: ...


class ResolvedPolicyProtocol(Protocol):
    policy_type: PolicyType
    rules: dict[str, Any]
    source: str


class PolicyLookupProtocol(Protocol):
    async def resolve_effective_policy(
        self,
        *,
        policy_type: PolicyType,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
    ) -> ResolvedPolicyProtocol: ...


class AuditLogWriter(Protocol):
    async def create_audit_log_entry(self, **fields: object) -> object: ...


# ============================================================================
# Service
# ============================================================================


class QueueManagementService:
    """The Queue Management Engine's core orchestrator -- see module
    docstring for the full architectural write-up."""

    def __init__(
        self,
        repository: QueueManagementRepositoryProtocol,
        router_lookup: RouterLookupProtocol,
        policy_lookup: PolicyLookupProtocol,
        *,
        audit_writer: AuditLogWriter | None = None,
        device_adapter_resolver=get_queue_adapter,
    ) -> None:
        self.repository = repository
        self.router_lookup = router_lookup
        self.policy_lookup = policy_lookup
        self.audit_writer = audit_writer
        self._get_device_adapter = device_adapter_resolver

    # ========================================================================
    # Queue profiles
    # ========================================================================

    async def create_profile(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        name: str,
        download_rate_kbps: int,
        upload_rate_kbps: int,
        description: str | None = None,
        burst_download_kbps: int | None = None,
        burst_upload_kbps: int | None = None,
        burst_threshold_kbps: int | None = None,
        burst_time_seconds: int | None = None,
        priority: int = DEFAULT_QUEUE_PRIORITY,
        queue_type: QueueType = QueueType.SIMPLE,
        is_system_profile: bool = False,
        is_active: bool = True,
    ) -> QueueProfile:
        profile = await self.repository.create_profile(
            organization_id=None if is_system_profile else requesting_organization_id,
            name=name,
            description=description,
            download_rate_kbps=download_rate_kbps,
            upload_rate_kbps=upload_rate_kbps,
            burst_download_kbps=burst_download_kbps,
            burst_upload_kbps=burst_upload_kbps,
            burst_threshold_kbps=burst_threshold_kbps,
            burst_time_seconds=burst_time_seconds,
            priority=priority,
            queue_type=queue_type.value,
            is_system_profile=is_system_profile,
            is_active=is_active,
            created_by=actor_user_id,
        )
        await self._audit(
            actor_user_id,
            AuditAction.QUEUE_PROFILE_CREATED,
            organization_id=profile.organization_id,
            entity_id=profile.id,
            description=f"Queue profile '{profile.name}' created",
        )
        return profile

    async def get_profile(
        self,
        profile_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> QueueProfile:
        profile = await self.repository.get_profile_by_id(profile_id)
        if profile is None:
            raise QueueProfileNotFoundError(profile_id)
        _enforce_org_scope(profile.organization_id, requesting_organization_id)
        return profile

    async def update_profile(
        self,
        profile_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        **fields: object,
    ) -> QueueProfile:
        profile = await self.get_profile(
            profile_id, requesting_organization_id=requesting_organization_id
        )
        updated = await self.repository.update_profile(
            profile, {**fields, "updated_by": actor_user_id}
        )
        await self._audit(
            actor_user_id,
            AuditAction.QUEUE_PROFILE_UPDATED,
            organization_id=updated.organization_id,
            entity_id=updated.id,
            description=f"Queue profile '{updated.name}' updated",
        )
        return updated

    async def delete_profile(
        self,
        profile_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> QueueProfile:
        profile = await self.get_profile(
            profile_id, requesting_organization_id=requesting_organization_id
        )
        deleted = await self.repository.soft_delete_profile(profile)
        await self._audit(
            actor_user_id,
            AuditAction.QUEUE_PROFILE_DELETED,
            organization_id=deleted.organization_id,
            entity_id=deleted.id,
            description=f"Queue profile '{deleted.name}' deleted",
        )
        return deleted

    async def list_profiles(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[QueueProfile], object]:
        return await self.repository.list_profiles(
            requesting_organization_id=requesting_organization_id,
            page=page,
            page_size=page_size,
        )

    async def _get_or_create_system_profile(
        self, *, download_rate_kbps: int, upload_rate_kbps: int
    ) -> QueueProfile:
        """Finds an existing system profile with these exact rates, or
        creates one -- idempotent, mirrors
        ``app.domains.provisioning_engine.service
        .ProvisioningEngineService.generate_configuration``'s own
        "seed idempotently" ``ConfigVariable`` pattern. Used by
        ``resolve_and_assign_queue`` when no organization/location has a
        published ``PolicyType.BANDWIDTH`` policy -- never fabricates an
        ephemeral, unpersisted rate."""
        profiles, _meta = await self.repository.list_profiles(
            requesting_organization_id=None, page=1, page_size=100
        )
        for candidate in profiles:
            if (
                candidate.is_system_profile
                and candidate.download_rate_kbps == download_rate_kbps
                and candidate.upload_rate_kbps == upload_rate_kbps
            ):
                return candidate
        name = (
            _SYSTEM_UNLIMITED_PROFILE_NAME
            if download_rate_kbps == UNLIMITED_RATE_KBPS
            and upload_rate_kbps == UNLIMITED_RATE_KBPS
            else f"System {download_rate_kbps}k/{upload_rate_kbps}k"
        )
        return await self.create_profile(
            actor_user_id=None,
            requesting_organization_id=None,
            name=name,
            download_rate_kbps=download_rate_kbps,
            upload_rate_kbps=upload_rate_kbps,
            is_system_profile=True,
        )

    # ========================================================================
    # Queue schedules
    # ========================================================================

    async def create_schedule(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        name: str,
        schedule_type: QueueScheduleType,
        days_of_week: list[int] | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
        specific_dates: list[str] | None = None,
        timezone: str = "UTC",
        is_active: bool = True,
    ) -> QueueSchedule:
        return await self.repository.create_schedule(
            organization_id=requesting_organization_id,
            name=name,
            schedule_type=schedule_type.value,
            days_of_week=days_of_week or [],
            start_time=start_time,
            end_time=end_time,
            specific_dates=specific_dates or [],
            timezone=timezone,
            is_active=is_active,
            created_by=actor_user_id,
        )

    async def get_schedule(
        self,
        schedule_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> QueueSchedule:
        schedule = await self.repository.get_schedule_by_id(schedule_id)
        if schedule is None:
            raise QueueScheduleNotFoundError(schedule_id)
        _enforce_org_scope(schedule.organization_id, requesting_organization_id)
        return schedule

    async def update_schedule(
        self,
        schedule_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        **fields: object,
    ) -> QueueSchedule:
        schedule = await self.get_schedule(
            schedule_id, requesting_organization_id=requesting_organization_id
        )
        return await self.repository.update_schedule(
            schedule, {**fields, "updated_by": actor_user_id}
        )

    async def list_schedules(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[QueueSchedule], object]:
        return await self.repository.list_schedules(
            requesting_organization_id=requesting_organization_id,
            page=page,
            page_size=page_size,
        )

    # ========================================================================
    # Queue templates
    # ========================================================================

    async def create_template(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        name: str,
        persona: str,
        description: str | None = None,
        queue_profile_id: uuid.UUID | None = None,
        default_queue_schedule_id: uuid.UUID | None = None,
        is_active: bool = True,
    ) -> QueueTemplate:
        if queue_profile_id is not None:
            await self.get_profile(
                queue_profile_id, requesting_organization_id=requesting_organization_id
            )
        return await self.repository.create_template(
            organization_id=requesting_organization_id,
            name=name,
            persona=persona,
            description=description,
            queue_profile_id=queue_profile_id,
            default_queue_schedule_id=default_queue_schedule_id,
            is_active=is_active,
            created_by=actor_user_id,
        )

    async def get_template(
        self,
        template_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> QueueTemplate:
        template = await self.repository.get_template_by_id(template_id)
        if template is None:
            raise QueueTemplateNotFoundError(template_id)
        _enforce_org_scope(template.organization_id, requesting_organization_id)
        return template

    async def list_templates(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[QueueTemplate], object]:
        return await self.repository.list_templates(
            requesting_organization_id=requesting_organization_id,
            page=page,
            page_size=page_size,
        )

    # ========================================================================
    # Queue assignments: create / read / history
    # ========================================================================

    async def create_assignment(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        target_type: QueueTargetType,
        target_id: uuid.UUID | None = None,
        router_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
        device_target: str | None = None,
        queue_profile_id: uuid.UUID | None = None,
        queue_schedule_id: uuid.UUID | None = None,
        priority_override: int | None = None,
        expires_at: datetime | None = None,
    ) -> QueueAssignment:
        validate_target(
            target_type=target_type, target_id=target_id, router_id=router_id
        )

        organization_id = requesting_organization_id
        resolved_location_id = location_id
        if router_id is not None:
            router = await self.router_lookup.get_router(
                router_id, requesting_organization_id=requesting_organization_id
            )
            organization_id = router.organization_id
            resolved_location_id = resolved_location_id or router.location_id

        if queue_profile_id is not None:
            await self.get_profile(
                queue_profile_id, requesting_organization_id=organization_id
            )
        if queue_schedule_id is not None:
            await self.get_schedule(
                queue_schedule_id, requesting_organization_id=organization_id
            )

        assignment = await self.repository.create_assignment(
            organization_id=organization_id,
            location_id=resolved_location_id,
            router_id=router_id,
            target_type=target_type.value,
            target_id=target_id,
            device_target=device_target,
            device_queue_id=None,
            queue_profile_id=queue_profile_id,
            queue_schedule_id=queue_schedule_id,
            status=QueueStatus.PENDING.value,
            priority_override=priority_override,
            applied_at=None,
            expires_at=expires_at,
            error_message=None,
            superseded_by_assignment_id=None,
            created_by_user_id=actor_user_id,
            created_by=actor_user_id,
        )
        await self._audit(
            actor_user_id,
            AuditAction.QUEUE_ASSIGNMENT_CREATED,
            organization_id=assignment.organization_id,
            entity_id=assignment.id,
            description=f"Queue assignment created for {target_type.value}",
        )
        return assignment

    async def get_assignment(
        self,
        assignment_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> QueueAssignment:
        assignment = await self.repository.get_assignment_by_id(assignment_id)
        if assignment is None:
            raise QueueAssignmentNotFoundError(assignment_id)
        if (
            requesting_organization_id is not None
            and assignment.organization_id != requesting_organization_id
        ):
            raise QueueAssignmentNotFoundError(assignment_id)
        return assignment

    async def list_assignments(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        target_type: QueueTargetType | None = None,
        target_id: uuid.UUID | None = None,
        router_id: uuid.UUID | None = None,
        status: QueueStatus | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[QueueAssignment], object]:
        filters: dict[str, object] = {}
        if requesting_organization_id is not None:
            filters["organization_id"] = requesting_organization_id
        if target_type is not None:
            filters["target_type"] = target_type.value
        if target_id is not None:
            filters["target_id"] = target_id
        if router_id is not None:
            filters["router_id"] = router_id
        if status is not None:
            filters["status"] = status.value
        return await self.repository.list_assignments(
            page=page, page_size=page_size, filters=filters or None
        )

    async def get_history(
        self,
        *,
        target_type: QueueTargetType,
        target_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[QueueAssignment], object]:
        """Every past assignment (original and every "Move Queue"
        supersession) for one target, chronological -- a read-model over
        this same table, not a separate history table. See module
        docstring."""
        return await self.list_assignments(
            requesting_organization_id=requesting_organization_id,
            target_type=target_type,
            target_id=target_id,
            page=page,
            page_size=page_size,
        )

    async def get_rate_limit_reply_for_session(
        self, session_id: uuid.UUID
    ) -> str | None:
        """The single method ``app.domains.guest.service.RadiusService
        .authorize``'s optional ``queue_lookup`` hook needs -- returns a
        real RouterOS ``Mikrotik-Rate-Limit`` RADIUS reply-attribute
        string for this session's own current queue assignment (whatever
        its device-push status -- a guest's *entitled* rate is a RADIUS
        concern independent of whether that rate has actually finished
        being pushed to the device yet), or ``None`` if the session has no
        queue assignment at all. Never raises -- an absent/unresolvable
        assignment is a normal, common case (e.g. no bandwidth policy
        configured for this session's scope), not an error."""
        assignment = await self.repository.get_active_assignment_for_target(
            target_type=QueueTargetType.SESSION.value, target_id=session_id
        )
        if assignment is None or assignment.queue_profile_id is None:
            return None
        profile = await self.repository.get_profile_by_id(assignment.queue_profile_id)
        if profile is None:
            return None
        return format_mikrotik_rate_limit(
            profile, priority_override=assignment.priority_override
        )

    # ========================================================================
    # Queue lifecycle: apply / remove / move / reset / expire
    # ========================================================================

    async def apply_queue(
        self,
        assignment_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> QueueAssignment:
        assignment = await self.get_assignment(
            assignment_id, requesting_organization_id=requesting_organization_id
        )
        current = QueueStatus(assignment.status)
        if current not in APPLICABLE_QUEUE_STATUSES:
            raise QueueAssignmentNotApplicableError(assignment.id, assignment.status)
        if assignment.queue_profile_id is None:
            raise QueueProfileNotFoundError(None)

        profile = await self.get_profile(assignment.queue_profile_id)

        schedule = None
        if assignment.queue_schedule_id is not None:
            schedule = await self.get_schedule(assignment.queue_schedule_id)

        if schedule is not None and not is_schedule_active_now(schedule):
            validate_status_transition(current=current, target=QueueStatus.SUSPENDED)
            updated = await self.repository.update_assignment(
                assignment, {"status": QueueStatus.SUSPENDED.value}
            )
            return updated

        router = await self.router_lookup.get_router(
            assignment.router_id, requesting_organization_id=requesting_organization_id
        )
        credentials = self._resolve_device_credentials(router)
        adapter = self._get_device_adapter(router.vendor)

        priority = assignment.priority_override or profile.priority
        try:
            if assignment.device_queue_id is None:
                device_queue_id = await adapter.create_simple_queue(
                    credentials,
                    name=f"cloudguest-{assignment.id}",
                    target=assignment.device_target or "",
                    download_rate_kbps=profile.download_rate_kbps,
                    upload_rate_kbps=profile.upload_rate_kbps,
                    burst_download_kbps=profile.burst_download_kbps,
                    burst_upload_kbps=profile.burst_upload_kbps,
                    burst_threshold_kbps=profile.burst_threshold_kbps,
                    burst_time_seconds=profile.burst_time_seconds,
                    priority=priority,
                )
            else:
                device_queue_id = assignment.device_queue_id
                await adapter.update_simple_queue(
                    credentials,
                    device_queue_id=device_queue_id,
                    download_rate_kbps=profile.download_rate_kbps,
                    upload_rate_kbps=profile.upload_rate_kbps,
                    burst_download_kbps=profile.burst_download_kbps,
                    burst_upload_kbps=profile.burst_upload_kbps,
                    burst_threshold_kbps=profile.burst_threshold_kbps,
                    burst_time_seconds=profile.burst_time_seconds,
                    priority=priority,
                )
        except Exception as exc:  # noqa: BLE001 -- recorded, then re-raised
            await self.repository.update_assignment(
                assignment, {"error_message": str(exc)}
            )
            raise

        validate_status_transition(current=current, target=QueueStatus.ACTIVE)
        updated = await self.repository.update_assignment(
            assignment,
            {
                "status": QueueStatus.ACTIVE.value,
                "device_queue_id": device_queue_id,
                "applied_at": datetime.now(UTC),
                "error_message": None,
                "updated_by": actor_user_id,
            },
        )
        await self._audit(
            actor_user_id,
            AuditAction.QUEUE_APPLIED,
            organization_id=updated.organization_id,
            entity_id=updated.id,
            description=f"Queue assignment {updated.id} applied",
        )
        return updated

    async def remove_queue(
        self,
        assignment_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> QueueAssignment:
        assignment = await self.get_assignment(
            assignment_id, requesting_organization_id=requesting_organization_id
        )
        current = QueueStatus(assignment.status)
        if current not in REMOVABLE_QUEUE_STATUSES:
            raise QueueAssignmentNotRemovableError(assignment.id, assignment.status)

        if assignment.device_queue_id is not None:
            router = await self.router_lookup.get_router(
                assignment.router_id,
                requesting_organization_id=requesting_organization_id,
            )
            credentials = self._resolve_device_credentials(router)
            adapter = self._get_device_adapter(router.vendor)
            await adapter.remove_queue(
                credentials, device_queue_id=assignment.device_queue_id
            )

        validate_status_transition(current=current, target=QueueStatus.DISABLED)
        updated = await self.repository.update_assignment(
            assignment,
            {
                "status": QueueStatus.DISABLED.value,
                "device_queue_id": None,
                "updated_by": actor_user_id,
            },
        )
        await self._audit(
            actor_user_id,
            AuditAction.QUEUE_REMOVED,
            organization_id=updated.organization_id,
            entity_id=updated.id,
            description=f"Queue assignment {updated.id} removed from device",
        )
        return updated

    async def _suspend_queue(self, assignment: QueueAssignment) -> QueueAssignment:
        """Pulls an ``ACTIVE`` assignment's live device queue and marks it
        ``SUSPENDED`` -- its own :class:`~.models.QueueSchedule` window
        just closed. Distinct from ``remove_queue``'s own
        ``ACTIVE -> DISABLED`` (an explicit admin action): a schedule-
        driven suspension is expected to self-resume the moment the
        window reopens (see ``sweep_schedule_transitions``), never
        requiring a manual re-enable."""
        if assignment.device_queue_id is not None:
            router = await self.router_lookup.get_router(assignment.router_id)
            credentials = self._resolve_device_credentials(router)
            adapter = self._get_device_adapter(router.vendor)
            await adapter.remove_queue(
                credentials, device_queue_id=assignment.device_queue_id
            )
        validate_status_transition(
            current=QueueStatus.ACTIVE, target=QueueStatus.SUSPENDED
        )
        return await self.repository.update_assignment(
            assignment,
            {"status": QueueStatus.SUSPENDED.value, "device_queue_id": None},
        )

    async def sweep_schedule_transitions(self) -> dict[str, int]:
        """Re-evaluates every ``ACTIVE``/``SUSPENDED`` assignment scoped to
        a :class:`~.models.QueueSchedule` and flips its device state the
        moment the window opens or closes -- the real background executor
        behind the module brief's own "Automatically change assigned
        queues based on time" requirement. See ``tasks.py``'s own module
        docstring for the Beat-scheduled caller."""
        suspended_count = 0
        resumed_count = 0
        for status_value in (QueueStatus.ACTIVE, QueueStatus.SUSPENDED):
            assignments, _meta = await self.repository.list_assignments(
                page=1, page_size=1000, filters={"status": status_value.value}
            )
            for assignment in assignments:
                if assignment.queue_schedule_id is None:
                    continue
                schedule = await self.get_schedule(assignment.queue_schedule_id)
                should_be_active = is_schedule_active_now(schedule)
                if status_value == QueueStatus.ACTIVE and not should_be_active:
                    await self._suspend_queue(assignment)
                    suspended_count += 1
                elif status_value == QueueStatus.SUSPENDED and should_be_active:
                    await self.apply_queue(
                        assignment.id,
                        actor_user_id=None,
                        requesting_organization_id=assignment.organization_id,
                    )
                    resumed_count += 1
        return {"suspended": suspended_count, "resumed": resumed_count}

    async def reset_queue(
        self,
        assignment_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> QueueAssignment:
        """Remove then re-apply the same profile -- a real RouterOS "reset
        stats" operation (removing a queue entry and recreating it clears
        its accumulated byte/packet counters, RouterOS's own real
        behavior, not a platform-invented convention)."""
        assignment = await self.get_assignment(
            assignment_id, requesting_organization_id=requesting_organization_id
        )
        if QueueStatus(assignment.status) == QueueStatus.ACTIVE:
            await self.remove_queue(
                assignment_id,
                actor_user_id=actor_user_id,
                requesting_organization_id=requesting_organization_id,
            )
        return await self.apply_queue(
            assignment_id,
            actor_user_id=actor_user_id,
            requesting_organization_id=requesting_organization_id,
        )

    async def move_queue(
        self,
        assignment_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        new_queue_profile_id: uuid.UUID | None = None,
        new_queue_schedule_id: uuid.UUID | None = None,
        auto_apply: bool = True,
    ) -> QueueAssignment:
        """Real rollback on failure: the new assignment is applied to the
        device **before** the old one is ever touched. If ``apply_queue``
        below raises, this method propagates the exception without ever
        marking ``old`` superseded or removing its own live device queue
        -- the target is left exactly as it was, still served by its
        previous, already-working rate, never with zero bandwidth in
        between. Only once the new assignment is confirmed ``ACTIVE`` does
        the old one get pulled off the device and marked ``EXPIRED``. When
        ``auto_apply`` is ``False``, the old assignment's own live device
        queue is deliberately left untouched (and *not* yet marked
        superseded) until an admin explicitly calls ``apply_queue`` on the
        new row -- the same "never leave a target with zero bandwidth"
        principle, just deferred to a later, explicit action."""
        old = await self.get_assignment(
            assignment_id, requesting_organization_id=requesting_organization_id
        )

        new_assignment = await self.create_assignment(
            actor_user_id=actor_user_id,
            requesting_organization_id=old.organization_id,
            target_type=QueueTargetType(old.target_type),
            target_id=old.target_id,
            router_id=old.router_id,
            location_id=old.location_id,
            device_target=old.device_target,
            queue_profile_id=new_queue_profile_id or old.queue_profile_id,
            queue_schedule_id=new_queue_schedule_id
            if new_queue_schedule_id is not None
            else old.queue_schedule_id,
            priority_override=old.priority_override,
            expires_at=old.expires_at,
        )

        if not auto_apply:
            return new_assignment

        # Apply first -- if this raises, `old` is never touched below. See
        # this method's own docstring.
        applied = await self.apply_queue(
            new_assignment.id,
            actor_user_id=actor_user_id,
            requesting_organization_id=requesting_organization_id,
        )

        if QueueStatus(old.status) == QueueStatus.ACTIVE:
            await self.remove_queue(
                old.id,
                actor_user_id=actor_user_id,
                requesting_organization_id=requesting_organization_id,
            )
            old = await self.get_assignment(old.id)

        validate_status_transition(
            current=QueueStatus(old.status), target=QueueStatus.EXPIRED
        )
        await self.repository.update_assignment(
            old,
            {
                "status": QueueStatus.EXPIRED.value,
                "superseded_by_assignment_id": applied.id,
                "updated_by": actor_user_id,
            },
        )
        await self._audit(
            actor_user_id,
            AuditAction.QUEUE_ASSIGNMENT_CHANGED,
            organization_id=applied.organization_id,
            entity_id=applied.id,
            description=f"Queue assignment {old.id} moved to {applied.id}",
        )
        return applied

    async def expire_assignment(
        self,
        assignment_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        reason: str | None = None,
    ) -> QueueAssignment:
        assignment = await self.get_assignment(
            assignment_id, requesting_organization_id=requesting_organization_id
        )
        if QueueStatus(assignment.status) == QueueStatus.ACTIVE:
            await self.remove_queue(
                assignment_id,
                actor_user_id=actor_user_id,
                requesting_organization_id=requesting_organization_id,
            )
            assignment = await self.get_assignment(assignment_id)

        validate_status_transition(
            current=QueueStatus(assignment.status), target=QueueStatus.EXPIRED
        )
        updated = await self.repository.update_assignment(
            assignment,
            {"status": QueueStatus.EXPIRED.value, "updated_by": actor_user_id},
        )
        await self._audit(
            actor_user_id,
            AuditAction.QUEUE_ASSIGNMENT_EXPIRED,
            organization_id=updated.organization_id,
            entity_id=updated.id,
            description=f"Queue assignment {updated.id} expired"
            + (f": {reason}" if reason else ""),
        )
        return updated

    # ========================================================================
    # Dynamic queue assignment (Guest Login -> Policy Engine -> Queue
    # Profile Resolution -> Queue Assignment -> Queue Adapter -> Router)
    # ========================================================================

    async def resolve_and_assign_queue(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        router_id: uuid.UUID,
        target_type: QueueTargetType,
        target_id: uuid.UUID,
        device_target: str,
        actor_user_id: uuid.UUID | None = None,
        auto_apply: bool = True,
    ) -> QueueAssignment:
        """The real "Dynamic Queue Assignment" pipeline the module brief's
        own flow diagram names. Resolves the effective
        ``PolicyType.BANDWIDTH`` policy for this organization/location,
        finds-or-creates a matching :class:`~.models.QueueProfile`
        (idempotent, never an ephemeral unpersisted rate), and either
        creates a fresh :class:`~.models.QueueAssignment` for this target
        or -- if one already exists with a *different* profile -- moves
        it, exactly like an admin-driven "Move Queue" would."""
        resolved = await self.policy_lookup.resolve_effective_policy(
            policy_type=PolicyType.BANDWIDTH,
            organization_id=requesting_organization_id,
            location_id=location_id,
        )
        if resolved.rules:
            bandwidth_rules = BandwidthPolicyRules.model_validate(resolved.rules)
            profile = await self._get_or_create_system_profile(
                download_rate_kbps=bandwidth_rules.download_rate_kbps,
                upload_rate_kbps=bandwidth_rules.upload_rate_kbps,
            )
        else:
            profile = await self._get_or_create_system_profile(
                download_rate_kbps=UNLIMITED_RATE_KBPS,
                upload_rate_kbps=UNLIMITED_RATE_KBPS,
            )

        existing = await self.repository.get_active_assignment_for_target(
            target_type=target_type.value, target_id=target_id
        )
        if existing is None:
            new_assignment = await self.create_assignment(
                actor_user_id=actor_user_id,
                requesting_organization_id=requesting_organization_id,
                target_type=target_type,
                target_id=target_id,
                router_id=router_id,
                location_id=location_id,
                device_target=device_target,
                queue_profile_id=profile.id,
            )
            if auto_apply:
                return await self.apply_queue(
                    new_assignment.id,
                    actor_user_id=actor_user_id,
                    requesting_organization_id=requesting_organization_id,
                )
            return new_assignment

        if existing.queue_profile_id == profile.id:
            return existing

        return await self.move_queue(
            existing.id,
            actor_user_id=actor_user_id,
            requesting_organization_id=requesting_organization_id,
            new_queue_profile_id=profile.id,
            auto_apply=auto_apply,
        )

    # ========================================================================
    # Internal helpers
    # ========================================================================

    def _resolve_device_credentials(self, router: Router) -> QueueCredentials:
        host = router.management_ip_address or router.public_ip_address
        secret = self.router_lookup.get_decrypted_api_secret(router)
        if not host or not router.api_username or not secret:
            raise QueueMissingCredentialsError(router.id)
        return QueueCredentials(
            host=host, username=router.api_username, password=secret
        )

    async def _audit(
        self,
        actor_user_id: uuid.UUID | None,
        action: AuditAction,
        *,
        organization_id: uuid.UUID | None,
        entity_id: uuid.UUID,
        description: str,
    ) -> None:
        if self.audit_writer is None:
            return
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=actor_user_id,
            action=action.value,
            entity_type="queue_assignment",
            entity_id=entity_id,
            description=description,
            organization_id=organization_id,
        )


def _enforce_org_scope(
    row_organization_id: uuid.UUID | None,
    requesting_organization_id: uuid.UUID | None,
) -> None:
    """A ``None`` row ``organization_id`` is a platform-wide system row,
    readable by any organization -- mirrors ``ConfigTemplate``'s/
    ``QueueProfile``'s own identical convention. Otherwise the row must
    belong to the requesting organization."""
    if (
        requesting_organization_id is not None
        and row_organization_id is not None
        and row_organization_id != requesting_organization_id
    ):
        raise CrossOrganizationQueueAccessError("Resource", row_organization_id)


def is_schedule_active_now(
    schedule: QueueSchedule, *, at: datetime | None = None
) -> bool:
    """Pure logic: is ``schedule``'s own time window currently open? See
    ``models.QueueSchedule``'s own docstring for exactly which fields each
    ``schedule_type`` uses. A schedule with ``is_active=False`` is never
    considered open (an admin-level kill switch, independent of the
    window itself)."""
    if not schedule.is_active:
        return False
    now = at or datetime.now(UTC)

    if schedule.schedule_type == QueueScheduleType.HOLIDAY.value:
        today = now.date().isoformat()
        return today in (schedule.specific_dates or [])

    if schedule.days_of_week and now.weekday() not in schedule.days_of_week:
        return False

    if not schedule.start_time or not schedule.end_time:
        return True

    current_time = now.time()
    start = _parse_hhmm(schedule.start_time)
    end = _parse_hhmm(schedule.end_time)
    if start <= end:
        return start <= current_time <= end
    # Overnight window (e.g. Night Mode 22:00-06:00) wraps past midnight.
    return current_time >= start or current_time <= end


def _parse_hhmm(value: str) -> time:
    hour_str, minute_str = value.split(":")
    return time(hour=int(hour_str), minute=int(minute_str))


def format_mikrotik_rate_limit(
    profile: QueueProfile, *, priority_override: int | None = None
) -> str:
    """Formats a real RouterOS ``Mikrotik-Rate-Limit`` RADIUS reply-
    attribute value: ``rx-rate/tx-rate [rx-burst-rate/tx-burst-rate
    rx-burst-threshold/tx-burst-threshold rx-burst-time/tx-burst-time
    priority]`` -- RouterOS's own real attribute grammar (``rx`` = traffic
    received by the router from the client, i.e. the client's *upload*;
    ``tx`` = traffic transmitted to the client, i.e. the client's
    *download* -- matching ``QueueProfile.upload_rate_kbps``/
    ``download_rate_kbps``'s own ordering exactly). Priority is only
    appended when at least one burst field is set -- the same "all or
    nothing" convention ``device_adapters._burst_fields`` already
    establishes for the equivalent local ``/queue simple`` command, and it
    keeps the common "no burst, non-default priority" case from requiring
    fake zero-value burst placeholders just to reach the priority slot
    (RouterOS uses the profile's/queue's own default priority when the
    attribute omits it entirely)."""
    parts = [f"{profile.upload_rate_kbps}k/{profile.download_rate_kbps}k"]
    if profile.burst_upload_kbps is not None or profile.burst_download_kbps is not None:
        parts.append(
            f"{profile.burst_upload_kbps or 0}k/{profile.burst_download_kbps or 0}k"
        )
        threshold = profile.burst_threshold_kbps or 0
        parts.append(f"{threshold}k/{threshold}k")
        burst_time = profile.burst_time_seconds or 0
        parts.append(f"{burst_time}/{burst_time}")
        parts.append(str(priority_override or profile.priority))
    return " ".join(parts)


__all__ = [
    "QueueManagementService",
    "RouterLookupProtocol",
    "PolicyLookupProtocol",
    "AuditLogWriter",
    "is_schedule_active_now",
    "format_mikrotik_rate_limit",
]
