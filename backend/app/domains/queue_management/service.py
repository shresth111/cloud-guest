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

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, time
from typing import Any, Protocol

from app.domains.policy.constants import PolicyType
from app.domains.policy.schemas import BandwidthPolicyRules
from app.domains.rbac.enums import AuditAction
from app.domains.rbac.location_scope import (
    LocationScope,
    enforce_entity_location,
)
from app.domains.router.device_domain_gate import ensure_not_controller_managed
from app.domains.router.models import Router
from app.domains.router.vendor_capabilities import is_controller_managed

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
    ControllerQueueUnavailableError,
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


class ControllerSpeedHookProtocol(Protocol):
    """Setting and clearing one client's speed limit on a vendor controller.

    Injected rather than imported: ``network_integration`` composes this
    domain's service through its own dependency chain, so the module-level
    import edge runs one way only. Satisfied structurally by
    ``network_integration.service.NetworkIntegrationService``.
    """

    async def set_client_speed(
        self,
        *,
        location_id: uuid.UUID,
        organization_id: uuid.UUID | None,
        client_mac: str,
        down_kbps: int | None,
        up_kbps: int | None,
        actor_user_id: uuid.UUID | None,
    ) -> object: ...

    async def clear_client_speed(
        self,
        *,
        location_id: uuid.UUID,
        organization_id: uuid.UUID | None,
        client_mac: str,
        actor_user_id: uuid.UUID | None,
    ) -> object: ...


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
        guest_id: uuid.UUID | None = None,
    ) -> ResolvedPolicyProtocol: ...


class AuditLogWriter(Protocol):
    async def create_audit_log_entry(self, **fields: object) -> object: ...


logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class QueueReapplySummary:
    """Read model for :meth:`QueueManagementService
    .reapply_assignments_for_router` -- see that method's own docstring.
    Consumed by ``app.domains.device_sync``'s own orchestrator, composed
    rather than reimplemented."""

    reapplied: int
    failed: int


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
        caller_location_scope: LocationScope = None,
        controller_speed_hook: ControllerSpeedHookProtocol | None = None,
    ) -> None:
        self.repository = repository
        self.router_lookup = router_lookup
        self.policy_lookup = policy_lookup
        self.audit_writer = audit_writer
        self._get_device_adapter = device_adapter_resolver
        # How a speed limit reaches a venue whose network is run from a
        # vendor controller rather than from a device this platform logs in
        # to. ``None`` is a real value -- a deployment or a test without the
        # network-integration domain wired -- and produces a refusal that
        # names the situation, never a silent success.
        self.controller_speed_hook = controller_speed_hook
        # Constructor-injected -- see `app.domains.rbac.location_scope`.
        self.caller_location_scope = caller_location_scope

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
        ephemeral, unpersisted rate.

        Two things this had to stop doing. It scanned ``page=1,
        page_size=100`` of every profile on the platform, so once more than
        a page existed it could no longer see a profile it already had and
        quietly created another on each call;
        ``list_system_profiles_by_rates`` asks the question directly
        instead. And "look, then create" is a read-then-write, so two
        concurrent logins racing on a rate the platform had never used both
        created one -- production carried two ``System 40960k/40960k`` rows
        and two ``System 81920k/81920k`` rows for exactly this reason. The
        rate-pair lock closes that.

        The duplicates already in the table are deliberately left alone:
        assignments reference them and ``queue_profile_id`` is
        ``ON DELETE SET NULL``, so deleting one would silently unrate live
        guests. They are harmless once creation stops racing."""
        name = (
            _SYSTEM_UNLIMITED_PROFILE_NAME
            if download_rate_kbps == UNLIMITED_RATE_KBPS
            and upload_rate_kbps == UNLIMITED_RATE_KBPS
            else f"System {download_rate_kbps}k/{upload_rate_kbps}k"
        )
        # Serialize per rate pair before looking -- see docstring.
        await self.repository.acquire_profile_rate_lock(
            download_rate_kbps=download_rate_kbps,
            upload_rate_kbps=upload_rate_kbps,
        )
        existing = await self.repository.list_system_profiles_by_rates(
            download_rate_kbps=download_rate_kbps,
            upload_rate_kbps=upload_rate_kbps,
        )
        if existing:
            return existing[0]
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
            # Refused here, before a row exists -- *unless* this platform can
            # actually reach the controller, which it now can for a per-client
            # speed limit.
            #
            # The gate's original reasoning still holds for every venue it
            # still refuses: the adapter registry would decline the vendor
            # eventually, but only on a later `push`, after this method had
            # returned 201 and shown the venue a saved setting that would
            # never reach a device. See `app.domains.router
            # .device_domain_gate` for why the message is written for the
            # venue rather than for the registry.
            #
            # What changed is only whether the premise is true. With
            # `controller_speed_hook` wired, `apply_queue` sends this profile's
            # rates to the controller's own per-client rate limit, so the row
            # this method writes *is* backed by a real device write and the
            # refusal would now be the false statement. Without the hook the
            # premise is unchanged and so is the refusal -- which is why this
            # is gated on the hook rather than on the vendor.
            if self.controller_speed_hook is None:
                ensure_not_controller_managed(router, feature="Speed Limits")
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
        # Same reasoning as firewall, but raising this domain's own
        # NotFound rather than a 403: it already answers a foreign
        # *organization* that way so as not to confirm the row exists,
        # and a location refusal that 403s would leak exactly what the
        # organization refusal is careful not to.
        #
        # DO NOT "harmonise" this to the CrossLocation*AccessError 403 the
        # other domains raise. "No such row" and "that row is not yours"
        # are different answers, and this domain has deliberately chosen
        # the first. No test asserts that a refusal must be uninformative,
        # so that change would pass CI and quietly turn an
        # existence-hiding refusal into an existence-confirming one.
        enforce_entity_location(
            entity_location_id=getattr(assignment, "location_id", None),
            caller_location_scope=self.caller_location_scope,
            error=QueueAssignmentNotFoundError(assignment_id),
        )
        return assignment

    async def list_assignments(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        target_type: QueueTargetType | None = None,
        target_id: uuid.UUID | None = None,
        router_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
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
        if location_id is not None:
            filters["location_id"] = location_id
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
        # A profile with both rates at 0 is this codebase's own convention
        # for "unlimited" (see e.g. the seeded "Unlimited" profile) -- but
        # RouterOS's real Mikrotik-Rate-Limit wire format has no such
        # convention: a literal "0k/0k" reply is throttled to zero
        # bandwidth, not unlimited. Confirmed live: a guest authorized with
        # this profile got Access-Accept yet had no real throughput at all.
        # RouterOS's own convention for "no limit" is to omit the attribute
        # entirely, which is exactly what returning None here achieves.
        if profile.upload_rate_kbps == 0 and profile.download_rate_kbps == 0:
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

        # The vendor question is asked before the credential question, and
        # the ordering is the point. A controller-managed row has no host,
        # no API username and no secret by construction, so resolving
        # credentials first made an Omada venue fail with "this router is
        # missing device connection credentials" -- a sentence that asks the
        # operator to supply something that does not exist and never will.
        # ``router.device_domain_gate``'s module docstring names this exact
        # shape in seven domains; this is one of them.
        #
        # The RouterOS path below is untouched: same credentials, same
        # adapter, same `/queue simple` calls, same order, one branch later.
        if is_controller_managed(router):
            return await self._apply_queue_on_controller(
                assignment,
                profile,
                router,
                actor_user_id=actor_user_id,
                requesting_organization_id=requesting_organization_id,
                current=current,
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
            if is_controller_managed(router):
                # Same ordering fix as ``apply_queue``. Clearing the limit
                # rather than deleting a queue row: on a controller the limit
                # is a field on the client's own record, so there is no object
                # to remove -- which is also why a controller venue is immune
                # to the accumulating ``/queue simple`` rows that RouterOS
                # venues need ``_retire_superseded_assignments`` for.
                await self._controller_speed(
                    router,
                    assignment=assignment,
                    requesting_organization_id=requesting_organization_id,
                    actor_user_id=actor_user_id,
                    clear=True,
                )
            else:
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

    #: The ``device_queue_id`` written for a controller-managed assignment.
    #: A marker rather than an id, because there is no object on the
    #: controller to hold one: the limit is a field on the client's own
    #: record. Prefixed so nothing mistakes it for a RouterOS queue id and
    #: tries to address ``/queue simple`` with it.
    CONTROLLER_QUEUE_MARKER = "controller:client-rate-limit"

    async def _controller_speed(
        self,
        router: Router,
        *,
        assignment: QueueAssignment,
        requesting_organization_id: uuid.UUID | None,
        actor_user_id: uuid.UUID | None,
        clear: bool,
        download_rate_kbps: int = 0,
        upload_rate_kbps: int = 0,
    ) -> None:
        """Push (or clear) one client's limit through the controller.

        Raises rather than degrading. A speed limit that this platform
        recorded and the venue never received is precisely the silent success
        this work was commissioned to prevent, so an unwired hook, a venue
        with no location, an assignment that names no device, and a
        controller that refuses are all loud -- and ``apply_queue``'s
        existing ``except`` writes the message onto the assignment row before
        re-raising, so the failure is visible on the record too.
        """
        if self.controller_speed_hook is None:
            raise ControllerQueueUnavailableError(router.id)
        location_id = getattr(router, "location_id", None)
        client_mac = assignment.device_target
        if location_id is None or not client_mac:
            raise ControllerQueueUnavailableError(router.id)
        if clear:
            await self.controller_speed_hook.clear_client_speed(
                location_id=location_id,
                organization_id=requesting_organization_id,
                client_mac=client_mac,
                actor_user_id=actor_user_id,
            )
            return
        await self.controller_speed_hook.set_client_speed(
            location_id=location_id,
            organization_id=requesting_organization_id,
            client_mac=client_mac,
            # ``0`` is this platform's "unlimited" (RouterOS `max-limit`
            # semantics), and the controller has no encoding for an enabled
            # limit of zero -- so it is passed through as ``None``, which the
            # provider reads as "do not limit that direction".
            down_kbps=download_rate_kbps or None,
            up_kbps=upload_rate_kbps or None,
            actor_user_id=actor_user_id,
        )

    async def _apply_queue_on_controller(
        self,
        assignment: QueueAssignment,
        profile: QueueProfile,
        router: Router,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        current: QueueStatus,
    ) -> QueueAssignment:
        """``apply_queue`` for a venue reached through its controller.

        The same ``QueueProfile`` and the same rates -- there is deliberately
        no Omada-only speed model. What differs is only how the numbers get
        there: a controller takes a per-client write against the client
        record, where RouterOS takes a ``/queue simple`` row, and the profile
        is the same object in both cases.

        Burst and priority are **not** sent, and their absence is not an
        oversight. The controller's per-client limit is a plain ceiling: it
        has no burst vocabulary and no priority field, so a profile carrying
        those is applied for its rates alone. Saying so here rather than
        quietly dropping them is the difference between a documented
        limitation and a lie about what the venue is enforcing.
        """
        try:
            await self._controller_speed(
                router,
                assignment=assignment,
                requesting_organization_id=requesting_organization_id,
                actor_user_id=actor_user_id,
                clear=False,
                download_rate_kbps=profile.download_rate_kbps,
                upload_rate_kbps=profile.upload_rate_kbps,
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
                "device_queue_id": self.CONTROLLER_QUEUE_MARKER,
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
            description=f"Queue assignment {updated.id} applied via controller",
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
        docstring for the Beat-scheduled caller.

        Uses ``repository.list_assignments_by_status`` (an unpaginated,
        platform-wide query), not ``list_assignments``'s own paginated
        ``page``/``page_size`` interface -- an earlier version of this
        sweep called ``list_assignments(page=1, page_size=1000, ...)`` and
        never fetched subsequent pages, silently dropping every assignment
        past the first 1000 from schedule-transition evaluation. A sweep
        that must evaluate *every* matching row on each tick has no natural
        "page" to stop at."""
        suspended_count = 0
        resumed_count = 0
        for status_value in (QueueStatus.ACTIVE, QueueStatus.SUSPENDED):
            assignments = await self.repository.list_assignments_by_status(
                status=status_value.value
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

    async def reapply_assignments_for_router(
        self,
        router_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> QueueReapplySummary:
        """Force a fresh device push for every currently-``ACTIVE``
        assignment on this router -- the real "sync queues for this
        router" operation ``app.domains.device_sync``'s own orchestrator
        composes, never reimplementing device I/O itself. Each
        assignment is re-pushed via the exact same real
        ``reset_queue`` (remove then re-apply) every other caller uses;
        one assignment's own device failure is caught and counted, never
        aborting the rest of the router's own assignments -- mirrors
        ``app.domains.isp.service.run_health_check_sweep``'s identical
        per-item isolation contract."""
        assignments, _ = await self.list_assignments(
            requesting_organization_id=requesting_organization_id,
            router_id=router_id,
            status=QueueStatus.ACTIVE,
            page=1,
            page_size=1000,
        )
        reapplied = 0
        failed = 0
        for assignment in assignments:
            try:
                await self.reset_queue(
                    assignment.id,
                    actor_user_id=actor_user_id,
                    requesting_organization_id=requesting_organization_id,
                )
                reapplied += 1
            except Exception as exc:  # noqa: BLE001 -- per-assignment isolation, see docstring
                failed += 1
                logger.warning(
                    "queue_reapply_assignment_failed",
                    extra={"assignment_id": str(assignment.id), "error": str(exc)},
                )
        return QueueReapplySummary(reapplied=reapplied, failed=failed)

    async def move_queue(
        self,
        assignment_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        new_queue_profile_id: uuid.UUID | None = None,
        new_queue_schedule_id: uuid.UUID | None = None,
        new_device_target: str | None = None,
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
        principle, just deferred to a later, explicit action.

        ``new_device_target`` re-points the queue at a different address,
        defaulting to the one the old assignment already had. A
        ``/queue simple`` entry matches on one concrete IP, so a guest who
        comes back on a new DHCP lease needs the entry rebuilt against the
        new address or their rate applies to an address they no longer
        hold -- and the apply-then-remove ordering above is exactly what
        makes that safe to do while they are online."""
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
            device_target=new_device_target or old.device_target,
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
        guest_id: uuid.UUID | None = None,
    ) -> QueueAssignment:
        """The real "Dynamic Queue Assignment" pipeline the module brief's
        own flow diagram names. Resolves the effective
        ``PolicyType.BANDWIDTH`` policy for this organization/location
        (or, when ``guest_id`` is given and a Group Policies "Map users"
        assignment targets this exact guest, that override instead --
        see ``app.domains.policy.constants.PolicyAssignmentTargetType
        .GUEST``), finds-or-creates a matching :class:`~.models.QueueProfile`
        (idempotent, never an ephemeral unpersisted rate), and either
        creates a fresh :class:`~.models.QueueAssignment` for this target
        or -- if one already exists with a *different* profile -- moves
        it, exactly like an admin-driven "Move Queue" would.

        **Idempotent sequentially, serialized concurrently.** The
        find-or-create above is a read-then-write, so "there is no existing
        assignment" is not a fact two concurrent callers can both rely on.
        This method therefore takes a per-target advisory lock first
        (``repository.acquire_assignment_target_lock``), and -- because a
        duplicate may already exist from before that lock did, and because
        a reused guest IP can leave a previous holder's row naming the same
        address -- it retires every competing row before applying anything
        (``_retire_superseded_assignments``). Without that, the rate
        resolved here is not the rate the guest gets: RouterOS applies the
        first matching ``/queue simple`` for an address, so a stale sibling
        wins silently."""
        # Serialize per target *before* asking whether one already exists.
        # Everything below is a read-then-write -- "is there a live
        # assignment for this target? no -> create one" -- and two callers
        # that ask at the same moment both get "no". That is not
        # theoretical: production carried two ACTIVE rows, and two
        # `/queue simple` entries, for a single guest session, created
        # 204 ms apart. See `repository._acquire_advisory_lock`.
        await self.repository.acquire_assignment_target_lock(
            target_type=target_type.value, target_id=target_id
        )

        resolved = await self.policy_lookup.resolve_effective_policy(
            policy_type=PolicyType.BANDWIDTH,
            organization_id=requesting_organization_id,
            location_id=location_id,
            guest_id=guest_id,
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

        # Retire every *other* live row competing for this same device-side
        # target before anything is applied. A competing row is not merely
        # untidy -- it silently overrides the rate resolved above. See
        # `_retire_superseded_assignments`.
        await self._retire_superseded_assignments(
            keep_id=existing.id if existing is not None else None,
            target_type=target_type,
            target_id=target_id,
            router_id=router_id,
            device_target=device_target,
            actor_user_id=actor_user_id,
            requesting_organization_id=requesting_organization_id,
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

        # Both halves matter. The profile is the rate; ``device_target`` is
        # the address that rate is enforced against, and a ``/queue simple``
        # entry matches on one concrete IP. A returning guest on a fresh DHCP
        # lease keeps their assignment (same rate, so the profile compares
        # equal) while the live queue on the device still names the address
        # they used to hold -- and a queue that matches nothing rate-limits
        # nothing. Comparing only the profile made that the silent case.
        if (
            existing.queue_profile_id == profile.id
            and existing.device_target == device_target
        ):
            return existing

        return await self.move_queue(
            existing.id,
            actor_user_id=actor_user_id,
            requesting_organization_id=requesting_organization_id,
            new_queue_profile_id=profile.id,
            new_device_target=device_target,
            auto_apply=auto_apply,
        )

    async def reapply_active_sessions_for_location(
        self,
        *,
        location_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        actor_user_id: uuid.UUID | None = None,
    ) -> dict[str, int]:
        """Re-resolve every currently-``ACTIVE`` SESSION queue assignment
        for one location against the location's *current* bandwidth policy.

        This is the "a venue just raised their speeds" hook -- the
        counterpart to the per-login ``resolve_and_assign_queue`` call in
        ``GuestService._assign_guest_queue``. A bandwidth-policy publish
        only changes what the *next* login resolves until this runs; this
        method makes the change reach guests who are already connected,
        without waiting for their session to die or for a reconnect.

        Each affected assignment is fed back through the exact same
        ``resolve_and_assign_queue`` pipeline a fresh login uses, so the
        semantics are identical to a returning guest: an unchanged rate
        resolves to the same profile and returns without a device call
        (idempotent by construction -- see that method's own docstring),
        and a genuinely changed rate goes through ``move_queue``, which
        applies the new ``/queue simple`` before pulling the old one, so a
        connected guest is never left at zero bandwidth in between. The
        session's own stored ``device_target`` (the concrete IP the live
        queue already names) is reused -- re-resolving policy does not need
        to re-discover an address that has not changed.

        One assignment's device failure is caught and counted, never
        aborting the rest of the location's own re-applications -- mirrors
        ``reapply_assignments_for_router``'s identical per-item isolation
        contract. Returns ``{"reapplied": n, "failed": n}``.

        The repo lists by ``status`` + filters; ``location_id`` and
        ``target_type`` are the two real filters that select the sessions
        this method exists to reach, and only ``ACTIVE`` rows are touched
        (a ``PENDING``/``DISABLED`` assignment belongs to a target that is
        not currently online, and will pick the new policy up whenever it
        is next applied on its own)."""
        assignments, _ = await self.list_assignments(
            requesting_organization_id=requesting_organization_id,
            location_id=location_id,
            status=QueueStatus.ACTIVE,
            page=1,
            page_size=1000,
        )
        reapplied = 0
        failed = 0
        for assignment in assignments:
            if assignment.target_type != QueueTargetType.SESSION.value:
                continue
            if assignment.router_id is None:
                continue
            try:
                await self.resolve_and_assign_queue(
                    requesting_organization_id=assignment.organization_id,
                    location_id=assignment.location_id,
                    router_id=assignment.router_id,
                    target_type=QueueTargetType.SESSION,
                    target_id=assignment.target_id,
                    device_target=assignment.device_target or "",
                    actor_user_id=actor_user_id,
                    guest_id=None,
                )
                reapplied += 1
            except Exception as exc:  # noqa: BLE001 -- per-assignment isolation, see docstring
                failed += 1
                logger.warning(
                    "queue_reapply_session_failed",
                    extra={"assignment_id": str(assignment.id), "error": str(exc)},
                )
        return {"reapplied": reapplied, "failed": failed}

    # ========================================================================
    # Internal helpers
    # ========================================================================

    async def _retire_superseded_assignments(
        self,
        *,
        keep_id: uuid.UUID | None,
        target_type: QueueTargetType,
        target_id: uuid.UUID,
        router_id: uuid.UUID,
        device_target: str | None,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> int:
        """Retire every live assignment competing for the same device-side
        queue as the one about to be applied; returns how many were retired.

        Two kinds of row compete, and ``get_active_assignment_for_target``
        can see neither:

        * **A duplicate for this exact target** -- two rows for one session,
          left behind by the read-then-write race
          ``acquire_assignment_target_lock`` now closes. Each owns its own
          device queue.
        * **A previous holder of this address** -- a row naming the same
          ``device_target`` on the same router whose session has since
          ended. Guest IPs are reused, so the next guest handed that
          address inherits a rate nobody configured for them.

        This is not tidiness. A ``/queue simple`` entry matches one concrete
        IP, and RouterOS applies the **first matching entry in list order**
        (creation order). A competing row therefore does not merely sit
        there: it silently overrides the rate this call just resolved, and
        the limit the venue saved has no effect on the guest. Retiring them
        is what makes the applied rate the guest's actual rate.

        Only rows of the same ``target_type`` are retired. An
        admin-created router/guest/voucher/device assignment is an explicit
        instruction, not a stale automatic one, and a login is not the place
        to revoke it.

        One row's device failure is logged and skipped, never aborting the
        others nor the assignment this runs inside -- mirrors
        ``reapply_active_sessions_for_location``'s own per-item isolation.
        """
        rivals: dict[uuid.UUID, QueueAssignment] = {}
        for row in await self.repository.list_assignments_for_target(
            target_type=target_type.value, target_id=target_id
        ):
            if row.id != keep_id:
                rivals[row.id] = row
        if device_target:
            for row in await self.repository.list_assignments_for_device_target(
                router_id=router_id, device_target=device_target
            ):
                if (
                    row.id != keep_id
                    and row.target_type == target_type.value
                    and row.target_id != target_id
                ):
                    rivals[row.id] = row

        retired = 0
        for row in rivals.values():
            try:
                await self.expire_assignment(
                    row.id,
                    actor_user_id=actor_user_id,
                    requesting_organization_id=requesting_organization_id,
                    reason="superseded by a queue assignment for the same address",
                )
                retired += 1
            except Exception as exc:  # noqa: BLE001 -- see docstring
                logger.warning(
                    "queue_assignment_supersede_failed",
                    extra={"assignment_id": str(row.id), "error": str(exc)},
                )
        return retired

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
