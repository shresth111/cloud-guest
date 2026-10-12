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
from collections.abc import Callable, Collection
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from datetime import UTC, datetime, time, timedelta
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
from app.domains.router.vendor_capabilities import (
    is_controller_managed,
    is_nas_only,
)

from .constants import (
    APPLICABLE_QUEUE_STATUSES,
    BACKFILL_UNASSIGNED_SESSION_QUEUES_MAX_PER_RUN,
    BACKFILL_UNASSIGNED_SESSION_QUEUES_MIN_AGE_SECONDS,
    BACKFILL_UNASSIGNED_SESSION_QUEUES_SCAN_LIMIT,
    DEFAULT_QUEUE_PRIORITY,
    RELEASE_ENDED_SESSION_QUEUES_GRACE_SECONDS,
    REMOVABLE_QUEUE_STATUSES,
    UNLIMITED_RATE_KBPS,
    VENUE_QUEUE_NAME_PREFIX,
    QueueScheduleType,
    QueueStatus,
    QueueTargetType,
    QueueType,
)
from .device_adapters import QueueCredentials, VenueQueueState, get_queue_adapter
from .exceptions import (
    ControllerQueueUnavailableError,
    CrossOrganizationQueueAccessError,
    QueueAssignmentNotApplicableError,
    QueueAssignmentNotFoundError,
    QueueAssignmentNotRemovableError,
    QueueDeviceConnectionError,
    QueueDeviceOperationError,
    QueueMissingCredentialsError,
    QueueProfileNotFoundError,
    QueueScheduleNotFoundError,
    QueueTargetNotLanAddressError,
    QueueTargetNotOnRouterError,
    QueueTemplateNotFoundError,
    UnsupportedQueueVendorError,
)
from .models import QueueAssignment, QueueProfile, QueueSchedule, QueueTemplate
from .repository import QueueManagementRepositoryProtocol
from .validators import (
    routeros_guest_queue_target,
    validate_status_transition,
    validate_target,
)

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


class SessionLivenessLookupProtocol(Protocol):
    """Which guest sessions are still live -- the one question this domain
    has to ask the guest domain, and the only thing it learns from it.

    A SESSION-targeted assignment names its session by id and nothing else
    (``QueueAssignment.target_id`` is deliberately not a foreign key), so
    this service cannot see a session end. Without this it never did: a
    session's queue stayed ACTIVE, and on the router, for ever.

    ``live_session_ids`` returns the subset of ``session_ids`` whose session
    exists and can still carry traffic or be resumed (active or paused).
    An id it does not return is a session that has ended.

    ``None``-by-default on the service, like ``controller_speed_hook``: a
    deployment or a test without it wired releases nothing and re-applies
    exactly as before."""

    async def live_session_ids(
        self, session_ids: Collection[uuid.UUID]
    ) -> set[uuid.UUID]: ...


@dataclass(frozen=True, slots=True)
class SessionWithoutQueue:
    """One live guest session that holds no queue -- everything
    ``backfill_queues_for_unassigned_sessions`` needs to give it one, and
    exactly what the login path hands ``guest.tasks.assign_guest_queue``.
    ``ip_address`` is the session's recorded address, unjudged: whether a
    queue may target it is decided by the service, by the rule a login
    uses."""

    session_id: uuid.UUID
    organization_id: uuid.UUID | None
    location_id: uuid.UUID | None
    router_id: uuid.UUID
    ip_address: str | None
    guest_id: uuid.UUID | None
    started_at: datetime
    device_mac: str | None = None


class SessionsWithoutQueueLookupProtocol(Protocol):
    """Which live guest sessions hold no queue -- the second question
    this domain asks the guest domain (``SessionLivenessLookupProtocol`` is
    the first), for the same reason: ``QueueAssignment.target_id`` is not a
    foreign key, so "a session with no assignment" is not something this
    service can see from its own tables.

    Returns ACTIVE sessions that started at or before ``started_before``,
    have a router, and have no ACTIVE, SUSPENDED or DISABLED SESSION
    assignment -- newest first, at most ``limit`` of them. A PENDING row
    does not count as holding a queue: it never reached the device.

    ``None``-by-default on the service, like the other two hooks: without
    it the backfill does nothing."""

    async def list_sessions_without_queue(
        self,
        *,
        started_before: datetime,
        location_id: uuid.UUID | None = None,
        limit: int,
    ) -> list[SessionWithoutQueue]: ...

    async def device_macs_for_active_sessions(
        self, session_ids: Collection[uuid.UUID]
    ) -> dict[uuid.UUID, str]:
        """Session id -> the MAC of the device it signed in from, for those
        of ``session_ids`` that are ACTIVE and recorded a device. An id
        missing from the result is a session that has ended, is paused, or
        has no device on record -- none of which
        ``retarget_queues_for_moved_devices`` should touch."""
        ...


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


@dataclass(frozen=True, slots=True)
class VenueCap:
    """A venue's total speed: what all of its guests share, per direction.
    ``None`` on a direction is "no total in that direction". Never both
    ``None`` -- that is "no cap", and is spelled ``None`` for the whole
    thing."""

    download_rate_kbps: int | None
    upload_rate_kbps: int | None


def venue_queue_name(location_id: uuid.UUID) -> str:
    """The name of a location's parent queue on its routers -- see
    ``constants.VENUE_QUEUE_NAME_PREFIX``."""
    return f"{VENUE_QUEUE_NAME_PREFIX}{str(location_id)[:8]}"


def venue_cap_from_rules(rules: dict[str, Any] | None) -> VenueCap | None:
    """The venue total a bandwidth policy's ``rules`` carry, or ``None``.

    Read with ``.get`` and not through ``BandwidthPolicyRules``: a version
    saved before these keys existed does not have them, and a rules
    payload that fails validation for some unrelated reason must not turn
    "is there a venue cap" into an exception on the login path. Anything
    that is not a positive integer is "no cap in that direction"."""
    if not rules:
        return None

    def _rate(key: str) -> int | None:
        value = rules.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            return None
        return value

    download = _rate("venue_download_rate_kbps")
    upload = _rate("venue_upload_rate_kbps")
    if download is None and upload is None:
        return None
    return VenueCap(download_rate_kbps=download, upload_rate_kbps=upload)


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
        session_liveness_lookup: SessionLivenessLookupProtocol | None = None,
        sessions_without_queue_lookup: SessionsWithoutQueueLookupProtocol
        | None = None,
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
        # How this service learns that a guest session has ended -- see
        # ``SessionLivenessLookupProtocol``. ``None`` releases nothing.
        self.session_liveness_lookup = session_liveness_lookup
        # How this service finds live sessions that never got a queue -- see
        # ``SessionsWithoutQueueLookupProtocol``. ``None`` backfills nothing.
        self.sessions_without_queue_lookup = sessions_without_queue_lookup
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
        if await self._venue_cap_holds_this_session(assignment):
            return None
        return format_mikrotik_rate_limit(
            profile, priority_override=assignment.priority_override
        )

    async def _venue_cap_holds_this_session(self, assignment: QueueAssignment) -> bool:
        """Whether ``assignment``'s session is at a venue whose total cap
        this platform enforces on the router -- in which case the RADIUS
        reply must not carry a rate limit.

        The attribute makes RouterOS create a dynamic ``<hotspot-...>``
        simple queue for the guest's address, at the top level and at the
        top of the list. A top-level row above the venue's parent takes
        that guest's traffic before the parent sees it, so the guest would
        be limited to their own rate and counted in nobody's total. The
        guest's own limit does not depend on the attribute: it is the
        ``cloudguest-...`` row under the parent.

        Whether the attribute was sent has never been a setting. It is sent
        when an assignment row for the session already exists at the moment
        the hotspot authorizes -- and the row is written by a worker task
        that the login only enqueues, so it is a race with the portal's own
        hotspot sign-in. Observed both ways on one router on consecutive
        days. Under a venue cap that race is taken out of the picture.

        Never raises, and anything it cannot establish answers ``False``:
        the reply then carries the limit exactly as it did before."""
        if assignment.location_id is None or assignment.router_id is None:
            return False
        try:
            router = await self.router_lookup.get_router(
                assignment.router_id,
                requesting_organization_id=assignment.organization_id,
            )
            if is_controller_managed(router) or is_nas_only(router):
                return False
            cap = await self._venue_cap_for_location(
                organization_id=assignment.organization_id,
                location_id=assignment.location_id,
            )
        except Exception as exc:  # noqa: BLE001 -- see docstring: never raises
            logger.warning(
                "venue_cap_lookup_failed",
                extra={"assignment_id": str(assignment.id), "error": str(exc)},
            )
            return False
        return cap is not None

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

        # The last line of defence before a row is created on the device,
        # for every caller: a login, a policy re-apply, an admin's own POST.
        # A per-session ``/queue simple`` against an address that is not on
        # the venue's LAN is created, reads back, turns this assignment
        # ACTIVE -- and matches nothing. See
        # ``validators.routeros_guest_queue_target``.
        if (
            assignment.device_queue_id is None
            and assignment.target_type == QueueTargetType.SESSION.value
            and not _is_routeros_session_target(router, assignment.device_target)
        ):
            refusal = QueueTargetNotLanAddressError(router.id)
            await self.repository.update_assignment(
                assignment, {"error_message": str(refusal)}
            )
            raise refusal

        priority = assignment.priority_override or profile.priority
        try:
            # A venue with a total cap: its parent row has to be on this
            # router before the guest's own row is, and the guest's row is
            # created under it. An existing row is put under it by the same
            # call. ``None`` here is every venue without a cap, and the
            # ``/queue simple`` calls below are then exactly what they were.
            venue_parent = (
                await self._ensure_venue_parent(
                    router, adapter, credentials, assignment
                )
                if assignment.target_type == QueueTargetType.SESSION.value
                else None
            )
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
                    # Passed only when there is one, so an adapter that has
                    # never heard of ``parent`` is called as it always was.
                    **({"parent": venue_parent} if venue_parent else {}),
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
                try:
                    await adapter.remove_queue(
                        credentials, device_queue_id=assignment.device_queue_id
                    )
                except QueueDeviceOperationError as exc:
                    # The router answered and said the row is not there --
                    # removed by hand, or lost with a configuration reset.
                    # That is the state this call exists to reach, so it is
                    # not a failure; treating it as one left the assignment
                    # ACTIVE for good, re-tried and re-failed by every sweep
                    # and every supersede pass. Anything else the router
                    # says is still an error.
                    if not _device_says_row_is_gone(exc):
                        raise
                    logger.warning(
                        "queue_remove_row_already_gone",
                        extra={
                            "assignment_id": str(assignment.id),
                            "router_id": str(assignment.router_id),
                        },
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
        requiring a manual re-enable.

        The controller branch is the same one ``apply_queue`` and
        ``remove_queue`` already take, and for the same reason: a
        controller-managed row holds no device credentials and no
        ``/queue simple`` id, so resolving credentials first failed it with
        "this router is missing device connection credentials" -- a sentence
        asking an operator to supply something that does not exist. Suspending
        a window at such a venue clears the client's limit; reopening it
        re-applies through ``apply_queue``. The RouterOS path below is
        untouched: same credentials, same adapter, one branch later."""
        if assignment.device_queue_id is not None:
            router = await self.router_lookup.get_router(assignment.router_id)
            if is_controller_managed(router):
                await self._controller_speed(
                    router,
                    assignment=assignment,
                    requesting_organization_id=assignment.organization_id,
                    actor_user_id=None,
                    clear=True,
                )
            else:
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
        device_mac: str | None = None,
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
        wins silently.

        **``device_mac`` makes the router, not the caller, say what the
        address is.** For a SESSION target on a router this platform logs
        in to, ``device_target`` is what the login *claimed*; given the
        device's MAC, the router is asked for the address it actually has
        for that device and that is what the queue targets -- see
        ``_routers_address_for_device``. Without a MAC the claimed address
        is used as before."""
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

        # Refuse a target that cannot be this guest's own address *before*
        # anything is created, moved or retired. ``apply_queue`` refuses it
        # too, but by then ``move_queue`` has already inserted the
        # replacement row, and a policy re-apply would leave one more
        # never-applied assignment behind on every publish. Refusing here
        # also means a wrong address never retires the row that is still
        # correctly limiting whoever really holds it.
        if target_type == QueueTargetType.SESSION:
            target_router = await self.router_lookup.get_router(
                router_id, requesting_organization_id=requesting_organization_id
            )
            if not is_controller_managed(target_router) and device_mac:
                device_target = await self._routers_address_for_device(
                    target_router,
                    device_mac=device_mac,
                    claimed=device_target,
                    target_id=target_id,
                )
            if not is_controller_managed(
                target_router
            ) and not _is_routeros_session_target(target_router, device_target):
                logger.warning(
                    "queue_assignment_target_not_lan_address",
                    extra={
                        "router_id": str(router_id),
                        "target_id": str(target_id),
                        "has_target": bool(device_target),
                    },
                )
                raise QueueTargetNotLanAddressError(router_id)

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
        unit_of_work: Callable[[], AbstractAsyncContextManager[Any]] | None = None,
        clear_venue_cap_when_uncapped: bool = False,
    ) -> dict[str, int]:
        """Re-resolve every currently-``ACTIVE`` SESSION queue assignment
        for one location against the location's *current* bandwidth policy.

        The venue's total cap is brought in line first (see
        ``sync_venue_cap_for_location``). ``clear_venue_cap_when_uncapped``
        says whether a location whose policy now carries no total should
        have its routers read for a parent row to take away: the caller
        passes ``True`` when the policy has ever carried one, so a venue
        that never set a total costs no device call it did not cost before.

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
        is next applied on its own).

        **Single-flight per location.** One save in the venue's policy
        screen publishes several policies and dispatches a re-apply for
        each, a fraction of a second apart. This takes a per-location lock
        before it reads anything (``repository
        .acquire_location_reapply_lock``), so the second waits for the
        first to commit and then finds every assignment already at the
        published rate -- an unchanged rate and address returns without a
        device call or a new row, so a duplicate re-apply does nothing.

        ``unit_of_work`` wraps one assignment's re-resolve (the task passes
        the database session's own savepoint). Catching an exception is not
        enough on its own: a failed statement aborts the transaction this
        whole run shares, and every assignment after it then fails with
        "current transaction is aborted". Rolling back to a savepoint is
        what makes "one failure does not stop the rest" true."""
        await self.repository.acquire_location_reapply_lock(location_id=location_id)
        # The venue's total first, under the same lock: its parent row is
        # made (or changed, or taken away) and every guest row already on
        # the router is put under it (or returned to the top level) before
        # any guest's own rate is re-resolved below. A failure here is the
        # venue cap's failure and never the guests' -- it is counted by
        # ``sync_venue_cap_for_location`` itself and the loop below runs
        # either way.
        try:
            await self._sync_venue_cap_under_lock(
                location_id=location_id,
                requesting_organization_id=requesting_organization_id,
                clear_when_uncapped=clear_venue_cap_when_uncapped,
                router_allowed=None,
            )
        except Exception as exc:  # noqa: BLE001 -- must not stop the re-apply
            logger.warning(
                "venue_cap_sync_failed",
                extra={"location_id": str(location_id), "error": str(exc)},
            )
        assignments, _ = await self.list_assignments(
            requesting_organization_id=requesting_organization_id,
            location_id=location_id,
            status=QueueStatus.ACTIVE,
            page=1,
            page_size=1000,
        )
        candidates = [
            a
            for a in assignments
            if a.target_type == QueueTargetType.SESSION.value
            and a.router_id is not None
            and a.target_id is not None
        ]
        # Sessions that have ended are not re-applied. Their rows used to be:
        # nothing told this service a session was over, so every publish
        # rebuilt a queue for a guest who had left -- and, where that dead
        # row shared an address with a live one, whichever happened to be
        # iterated last retired the other. The periodic
        # ``release_queues_for_ended_sessions`` is what removes them; here
        # they are only kept out of the way.
        if self.session_liveness_lookup is not None and candidates:
            live = await self.session_liveness_lookup.live_session_ids(
                {a.target_id for a in candidates}
            )
            candidates = [a for a in candidates if a.target_id in live]
        # Newest first, so that where two rows still name one address the
        # most recent sign-in is the one that keeps it: its re-resolve
        # retires the older row, and the status re-read below then skips
        # that older row instead of letting it take the address back.
        candidates.sort(key=lambda a: a.created_at, reverse=True)
        reapplied = 0
        failed = 0
        for assignment in candidates:
            current = await self.repository.get_assignment_by_id(assignment.id)
            if current is None or current.status != QueueStatus.ACTIVE.value:
                continue
            try:
                if unit_of_work is None:
                    await self._reapply_one(assignment, actor_user_id)
                else:
                    async with unit_of_work():
                        await self._reapply_one(assignment, actor_user_id)
                reapplied += 1
            except Exception as exc:  # noqa: BLE001 -- per-assignment isolation, see docstring
                failed += 1
                logger.warning(
                    "queue_reapply_session_failed",
                    extra={"assignment_id": str(assignment.id), "error": str(exc)},
                )
        return {"reapplied": reapplied, "failed": failed}

    # ========================================================================
    # A venue's total speed cap
    # ========================================================================

    async def _venue_cap_for_location(
        self, *, organization_id: uuid.UUID | None, location_id: uuid.UUID | None
    ) -> VenueCap | None:
        """The total the location's *own* bandwidth policy carries, or
        ``None``. Resolved without a guest: a guest mapped to a group gets
        that group's per-guest rate, but a group is not where a venue's
        total is said, and one guest's group must not change what everybody
        shares."""
        if location_id is None:
            return None
        resolved = await self.policy_lookup.resolve_effective_policy(
            policy_type=PolicyType.BANDWIDTH,
            organization_id=organization_id,
            location_id=location_id,
        )
        return venue_cap_from_rules(resolved.rules)

    async def _ensure_venue_parent(
        self,
        router: Router,
        adapter: Any,
        credentials: QueueCredentials,
        assignment: QueueAssignment,
    ) -> str | None:
        """The name of the parent row ``assignment``'s guest row belongs
        under on ``router``, having made sure that row is there -- or
        ``None`` when the venue has no total cap, or when it has one that
        could not be put on this router.

        ``None`` for the second reason is deliberate. The guest's own limit
        is the thing this call is in the middle of applying; a venue cap
        that cannot be written (the router reports no guest subnet, or
        refuses the row) is logged and the guest still gets their own rate,
        exactly as before there was such a thing as a venue cap. Only a
        router that cannot be reached raises, as the write that follows
        would have."""
        if assignment.location_id is None or not hasattr(adapter, "sync_venue_queue"):
            return None
        try:
            cap = await self._venue_cap_for_location(
                organization_id=assignment.organization_id,
                location_id=assignment.location_id,
            )
        except Exception as exc:  # noqa: BLE001 -- the guest's own limit goes ahead
            logger.warning(
                "venue_cap_lookup_failed",
                extra={"assignment_id": str(assignment.id), "error": str(exc)},
            )
            return None
        if cap is None:
            return None
        name = venue_queue_name(assignment.location_id)
        try:
            state = await adapter.sync_venue_queue(
                credentials,
                name=name,
                download_rate_kbps=cap.download_rate_kbps,
                upload_rate_kbps=cap.upload_rate_kbps,
                child_queue_ids=(
                    (assignment.device_queue_id,) if assignment.device_queue_id else ()
                ),
            )
        except QueueDeviceOperationError as exc:
            logger.warning(
                "venue_queue_sync_failed",
                extra={
                    "router_id": str(router.id),
                    "location_id": str(assignment.location_id),
                    "error": str(exc),
                },
            )
            return None
        self._log_venue_queue_state(router.id, assignment.location_id, state)
        if state.device_queue_id is None:
            return None
        return name

    def _log_venue_queue_state(
        self, router_id: uuid.UUID, location_id: uuid.UUID, state: VenueQueueState
    ) -> None:
        """Says so when the device, read back, does not hold what was
        written -- or when nothing was written because the router reports
        no guest subnet. Silent when it matches."""
        if state.in_sync:
            return
        event = (
            "venue_queue_subnet_unresolved"
            if "guest_subnet_unresolved" in state.problems
            else "venue_queue_not_in_sync"
        )
        logger.warning(
            event,
            extra={
                "router_id": str(router_id),
                "location_id": str(location_id),
                "queue_name": state.name,
                "problems": list(state.problems),
            },
        )

    async def sync_venue_cap_for_location(
        self,
        *,
        location_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        clear_when_uncapped: bool = True,
        router_allowed: Callable[[uuid.UUID], bool] | None = None,
    ) -> dict[str, int]:
        """Bring every router at ``location_id`` in line with the venue's
        total speed cap, as its bandwidth policy states it now.

        ## What it does

        * **The policy carries a total:** each router gets one parent
          ``/queue simple`` (``venue_queue_name``) over the guest subnet(s)
          the router itself reports for its hotspot interface, at the
          venue's rates, first in the list; and every guest row this
          platform has on that router for this location is put under it.
          A device with no row of its own -- bypassed, trusted, or still
          waiting for the backfill -- is held by the parent because the
          parent targets the subnet.
        * **The policy carries none** and ``clear_when_uncapped``: each
          router's guest rows go back to the top level, then the parent is
          removed. In that order; a parent with a row still under it is
          left in place and reported.
        * **The policy carries none** and not ``clear_when_uncapped``:
          nothing is contacted at all.

        Only a router this platform logs in to. A venue run from a vendor
        controller, or one whose access points this platform cannot reach,
        is skipped: the cap is not enforced there and nothing pretends it
        is.

        ## What it never does

        It never guesses the subnet (a router that reports none is logged
        and left alone, guest rows untouched), never decides which of a
        router's rows are guests' from the router's list (the rows are the
        ones this platform's own assignments name), and never lets one
        router stop another: each is tried on its own, a router that does
        not answer is counted and converges on the next run.

        Idempotent -- a router that already matches costs one read. Takes
        the per-location re-apply lock first, so it never interleaves with
        a policy re-apply or a re-target for the same location.

        Returns ``{"routers", "synced", "cleared", "wrote", "failed",
        "skipped"}``; ``wrote`` counts routers this call changed."""
        await self.repository.acquire_location_reapply_lock(location_id=location_id)
        return await self._sync_venue_cap_under_lock(
            location_id=location_id,
            requesting_organization_id=requesting_organization_id,
            clear_when_uncapped=clear_when_uncapped,
            router_allowed=router_allowed,
        )

    async def _sync_venue_cap_under_lock(
        self,
        *,
        location_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        clear_when_uncapped: bool,
        router_allowed: Callable[[uuid.UUID], bool] | None,
    ) -> dict[str, int]:
        """``sync_venue_cap_for_location`` for a caller that already holds
        the location's re-apply lock."""
        result = {
            "routers": 0,
            "synced": 0,
            "cleared": 0,
            "wrote": 0,
            "failed": 0,
            "skipped": 0,
        }
        cap = await self._venue_cap_for_location(
            organization_id=requesting_organization_id, location_id=location_id
        )
        if cap is None and not clear_when_uncapped:
            return result

        assignments, _ = await self.list_assignments(
            requesting_organization_id=requesting_organization_id,
            location_id=location_id,
            status=QueueStatus.ACTIVE,
            page=1,
            page_size=1000,
        )
        children: dict[uuid.UUID, list[str]] = {}
        for row in assignments:
            if (
                row.target_type == QueueTargetType.SESSION.value
                and row.router_id is not None
                and row.device_queue_id
                and row.device_queue_id != self.CONTROLLER_QUEUE_MARKER
            ):
                children.setdefault(row.router_id, []).append(row.device_queue_id)

        routers = await self._routers_at_location(
            location_id,
            requesting_organization_id=requesting_organization_id,
            also=children.keys(),
        )
        name = venue_queue_name(location_id)
        for router in sorted(routers, key=lambda r: str(r.id)):
            if router_allowed is not None and not router_allowed(router.id):
                continue
            result["routers"] += 1
            if is_controller_managed(router) or is_nas_only(router):
                result["skipped"] += 1
                continue
            try:
                adapter = self._get_device_adapter(router.vendor)
                if not hasattr(adapter, "sync_venue_queue"):
                    result["skipped"] += 1
                    continue
                credentials = self._resolve_device_credentials(router)
            except (UnsupportedQueueVendorError, QueueMissingCredentialsError):
                result["skipped"] += 1
                continue
            try:
                if cap is not None:
                    state = await adapter.sync_venue_queue(
                        credentials,
                        name=name,
                        download_rate_kbps=cap.download_rate_kbps,
                        upload_rate_kbps=cap.upload_rate_kbps,
                        child_queue_ids=tuple(sorted(children.get(router.id, ()))),
                    )
                    result["synced"] += 1
                else:
                    state = await adapter.clear_venue_queue(credentials, name=name)
                    result["cleared"] += 1
            except QueueDeviceConnectionError as exc:
                result["failed"] += 1
                logger.warning(
                    "venue_queue_router_unreachable",
                    extra={
                        "router_id": str(router.id),
                        "location_id": str(location_id),
                        "error": str(exc),
                    },
                )
                continue
            except Exception as exc:  # noqa: BLE001 -- per-router isolation
                result["failed"] += 1
                logger.warning(
                    "venue_queue_sync_failed",
                    extra={
                        "router_id": str(router.id),
                        "location_id": str(location_id),
                        "error": str(exc),
                    },
                )
                continue
            if state.wrote:
                result["wrote"] += 1
                logger.info(
                    "venue_queue_synced" if cap is not None else "venue_queue_cleared",
                    extra={
                        "router_id": str(router.id),
                        "location_id": str(location_id),
                        "queue_name": name,
                        "created": state.created,
                        "updated": state.updated,
                        "reparented": state.reparented,
                        "moved_to_top": state.moved_to_top,
                        "removed": state.removed,
                    },
                )
            self._log_venue_queue_state(router.id, location_id, state)
        return result

    async def sync_venue_caps_for_live_locations(
        self,
        *,
        router_allowed: Callable[[uuid.UUID], bool] | None = None,
        unit_of_work: Callable[[], AbstractAsyncContextManager[Any]] | None = None,
    ) -> dict[str, int]:
        """``sync_venue_cap_for_location`` for every location that has a
        guest row on a router right now -- the periodic half, for the cases
        a publish cannot cover: a router that did not answer when the venue
        saved its total, a parent row somebody removed by hand, a guest row
        that was written while the parent could not be.

        Driven by this platform's own ACTIVE session assignments, so a
        location nobody is online at is not visited: with no guest row
        there is nothing to put under a parent, and its routers are brought
        in line by the next publish or the next sign-in. ``router_allowed``
        is the backfill's own switch.

        Returns the per-location counts summed, plus ``locations``."""
        total = {
            "locations": 0,
            "routers": 0,
            "synced": 0,
            "cleared": 0,
            "wrote": 0,
            "failed": 0,
            "skipped": 0,
        }
        locations: dict[uuid.UUID, uuid.UUID | None] = {}
        for row in await self.repository.list_assignments_by_status(
            status=QueueStatus.ACTIVE.value
        ):
            if (
                row.target_type == QueueTargetType.SESSION.value
                and row.location_id is not None
                and row.router_id is not None
                and not row.is_deleted
                and (router_allowed is None or router_allowed(row.router_id))
            ):
                locations.setdefault(row.location_id, row.organization_id)
        for location_id in sorted(locations, key=str):
            total["locations"] += 1
            try:
                if unit_of_work is None:
                    result = await self.sync_venue_cap_for_location(
                        location_id=location_id,
                        requesting_organization_id=locations[location_id],
                        router_allowed=router_allowed,
                    )
                else:
                    async with unit_of_work():
                        result = await self.sync_venue_cap_for_location(
                            location_id=location_id,
                            requesting_organization_id=locations[location_id],
                            router_allowed=router_allowed,
                        )
            except Exception as exc:  # noqa: BLE001 -- per-location isolation
                total["failed"] += 1
                logger.warning(
                    "venue_cap_sync_failed",
                    extra={"location_id": str(location_id), "error": str(exc)},
                )
                continue
            for key, value in result.items():
                total[key] += value
        return total

    async def _routers_at_location(
        self,
        location_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
        also: Collection[uuid.UUID] = (),
    ) -> list[Router]:
        """Every router at the location: the ones the router domain lists
        for it, and any that one of this platform's guest rows names (which
        covers a router lookup that cannot list). A router that cannot be
        loaded is left out, not raised."""
        found: dict[uuid.UUID, Router] = {}
        lister = getattr(self.router_lookup, "list_routers", None)
        if lister is not None:
            try:
                listed, _ = await lister(
                    location_id=location_id,
                    requesting_organization_id=requesting_organization_id,
                    page=1,
                    page_size=100,
                )
                found.update({router.id: router for router in listed})
            except Exception as exc:  # noqa: BLE001 -- fall back to the rows' own routers
                logger.warning(
                    "venue_cap_router_listing_failed",
                    extra={"location_id": str(location_id), "error": str(exc)},
                )
        for router_id in also:
            if router_id in found:
                continue
            try:
                found[router_id] = await self.router_lookup.get_router(
                    router_id, requesting_organization_id=requesting_organization_id
                )
            except Exception as exc:  # noqa: BLE001 -- per-router isolation
                logger.warning(
                    "venue_cap_router_lookup_failed",
                    extra={"router_id": str(router_id), "error": str(exc)},
                )
        return list(found.values())

    async def _reapply_one(
        self, assignment: QueueAssignment, actor_user_id: uuid.UUID | None
    ) -> QueueAssignment:
        return await self.resolve_and_assign_queue(
            requesting_organization_id=assignment.organization_id,
            location_id=assignment.location_id,
            router_id=assignment.router_id,
            target_type=QueueTargetType.SESSION,
            target_id=assignment.target_id,
            device_target=assignment.device_target or "",
            actor_user_id=actor_user_id,
            guest_id=None,
        )

    async def _routers_address_for_device(
        self,
        router: Router,
        *,
        device_mac: str,
        claimed: str | None,
        target_id: uuid.UUID | None,
    ) -> str:
        """The address ``router`` itself has for the device with this MAC --
        what a per-session ``/queue simple`` must target.

        A login records ``payload.ip_address or request.client.host``, and
        the first of those is a query parameter on the portal URL, filled
        in by the hotspot's ``$(ip)``. On a router whose clients lease from
        a subnet that is not the hotspot's own pool, that is a pool address
        and not the device's: observed live, a laptop holding one address
        signed in honestly, through the hotspot's own page, reporting
        another; the queue was written against the reported one, the
        dashboard showed an active limit and the guest ran unshaped. A
        guest can also put any address there deliberately. Either way the
        reported address is a private one, so the LAN check alone does not
        catch it.

        So the router is asked, by MAC (hotspot host, then DHCP lease), and
        its answer replaces the claim. When it has no entry for the MAC
        nothing is written against the claimed address: this raises
        ``QueueTargetNotOnRouterError`` and the session is left without an
        assignment, where ``backfill_queues_for_unassigned_sessions`` finds
        it once the device is on the network.

        An adapter with no ``resolve_client_address`` leaves the claim as it
        was. A router that cannot be reached raises as any device call
        does, before a row exists."""
        adapter = self._get_device_adapter(router.vendor)
        resolver = getattr(adapter, "resolve_client_address", None)
        if resolver is None:
            return claimed or ""
        credentials = self._resolve_device_credentials(router)
        found = await resolver(credentials, mac_address=device_mac)
        if not found:
            logger.warning(
                "queue_assignment_device_not_on_router",
                extra={
                    "router_id": str(router.id),
                    "target_id": str(target_id),
                    "had_claimed_address": bool(claimed),
                    "speed_limit_applied": False,
                },
            )
            raise QueueTargetNotOnRouterError(router.id)
        found = str(found).strip().removesuffix("/32")
        if found != (claimed or "").strip().removesuffix("/32"):
            logger.warning(
                "queue_assignment_target_corrected",
                extra={
                    "router_id": str(router.id),
                    "target_id": str(target_id),
                    "had_claimed_address": bool(claimed),
                },
            )
        return found

    async def release_queues_for_ended_sessions(
        self,
        *,
        now: datetime | None = None,
        grace_seconds: float = RELEASE_ENDED_SESSION_QUEUES_GRACE_SECONDS,
    ) -> dict[str, int]:
        """Expire every SESSION assignment whose guest session has ended,
        taking its ``/queue simple`` row (or controller limit) off the
        device.

        ## Why this exists

        Nothing else does it. A session ends in a dozen places -- an
        operator's disconnect, the guest's own logout, the timeout, FUP and
        data-cap sweeps, RADIUS Accounting-Stop, a NAS restart, the
        presence reconciliation -- and none of them touched the session's
        queue. The assignment stayed ACTIVE and the row stayed on the
        router. RouterOS applies the first matching ``/queue simple`` for
        an address in list order, so a dead session's row went on deciding
        the speed of whoever held that address next: observed live as an
        ``0/0`` (unlimited) row from an ended session sitting above a
        30 Mbps row for the same device.

        A periodic reconciliation rather than a hook on each of those
        paths, deliberately: it cannot be forgotten by the next path
        somebody adds, and it also clears the rows the old behaviour has
        already left on routers.

        ## What it decides from, and what it never does

        It reconciles **database rows against database rows**:
        ``QueueAssignment`` against the guest session it names. The device
        row removed is the one whose id this platform stored when it
        created it. Nothing here lists the router's queues and picks one --
        the device cannot say which of two rows for an address is correct.
        A row this platform has no assignment for is therefore out of this
        method's reach, by design.

        * An assignment younger than ``grace_seconds`` is not judged (see
          ``constants.RELEASE_ENDED_SESSION_QUEUES_GRACE_SECONDS``).
        * A paused session is live: it resumes onto the same assignment.
        * No lookup wired -> nothing is released.

        ## Failure

        One row's failure never stops the rest. A router that cannot be
        reached is skipped for the remainder of the run after its first
        connection failure -- each attempt costs a full connect timeout,
        and a venue that is offline may have dozens of rows waiting. Its
        assignments stay as they are and are retried on the next run.

        Returns ``{"released", "failed", "skipped_unreachable"}``."""
        result = {"released": 0, "failed": 0, "skipped_unreachable": 0}
        if self.session_liveness_lookup is None:
            return result
        now = now or datetime.now(UTC)
        cutoff = now - timedelta(seconds=grace_seconds)

        candidates: list[QueueAssignment] = []
        for status_value in (
            QueueStatus.ACTIVE,
            QueueStatus.SUSPENDED,
            QueueStatus.PENDING,
            QueueStatus.DISABLED,
        ):
            for row in await self.repository.list_assignments_by_status(
                status=status_value.value
            ):
                if (
                    row.target_type == QueueTargetType.SESSION.value
                    and row.target_id is not None
                    and not row.is_deleted
                    and row.created_at <= cutoff
                ):
                    candidates.append(row)
        if not candidates:
            return result

        live = await self.session_liveness_lookup.live_session_ids(
            {row.target_id for row in candidates}
        )
        unreachable_routers: set[uuid.UUID] = set()
        for row in sorted(candidates, key=lambda a: a.created_at):
            if row.target_id in live:
                continue
            if row.router_id in unreachable_routers:
                result["skipped_unreachable"] += 1
                continue
            try:
                await self.expire_assignment(
                    row.id,
                    actor_user_id=None,
                    requesting_organization_id=row.organization_id,
                    reason="guest session ended",
                )
                result["released"] += 1
            except QueueDeviceConnectionError as exc:
                if row.router_id is not None:
                    unreachable_routers.add(row.router_id)
                result["failed"] += 1
                logger.warning(
                    "queue_release_router_unreachable",
                    extra={
                        "assignment_id": str(row.id),
                        "router_id": str(row.router_id),
                        "error": str(exc),
                    },
                )
            except Exception as exc:  # noqa: BLE001 -- per-row isolation, see docstring
                result["failed"] += 1
                logger.warning(
                    "queue_release_failed",
                    extra={"assignment_id": str(row.id), "error": str(exc)},
                )
        return result

    async def backfill_queues_for_unassigned_sessions(
        self,
        *,
        now: datetime | None = None,
        min_age_seconds: float = BACKFILL_UNASSIGNED_SESSION_QUEUES_MIN_AGE_SECONDS,
        max_per_run: int = BACKFILL_UNASSIGNED_SESSION_QUEUES_MAX_PER_RUN,
        location_id: uuid.UUID | None = None,
        router_allowed: Callable[[uuid.UUID], bool] | None = None,
        unit_of_work: Callable[[], AbstractAsyncContextManager[Any]] | None = None,
    ) -> dict[str, int]:
        """Give a queue to every live guest session that has none.

        ## Why this exists

        A login hands its queue to the worker (``guest.tasks
        .assign_guest_queue``). When the router does not answer, that task
        retries a few times, gives up, and rolls its transaction back: the
        session stays ACTIVE with no assignment at all, which on the device
        is no ``/queue simple`` row -- unlimited -- for the rest of the
        session. Nothing came back for it. A policy publish did not either:
        ``reapply_active_sessions_for_location`` walks existing ACTIVE
        assignments, and this session has none to walk.

        ## What it does, and what it deliberately reuses

        Each such session is put through ``resolve_and_assign_queue``, the
        entry point the login itself uses, with the arguments the login
        would have passed. There is no second resolver and no second device
        writer here; a session this reaches ends up exactly where a
        successful login would have left it.

        The same refusals apply, before anything is attempted:

        * a venue run from a vendor controller, or one this platform has no
          API to, is left alone -- only a router this platform logs in to;
        * the address is the one the router has for the session's device
          (``_routers_address_for_device``), where the device's MAC is
          known; a device the router has no entry for is skipped and looked
          at again next run. Without a MAC the session's recorded address
          is used, and must be one a queue can match
          (``validators.routeros_guest_queue_target``).

        ## What it must not do

        * **Race the login.** A session younger than ``min_age_seconds`` is
          not looked at: the login's own task may still be retrying. A
          re-login on an older session can still overlap; both then
          serialize on the per-target lock and the second finds the first's
          row.
        * **Take an address from whoever holds it now.** Applying a queue
          retires every other row naming the same address, which is right
          for a sign-in and wrong here: two ACTIVE sessions can record one
          address (a lease reused before the older session was closed), and
          giving the unassigned one a queue would take it from the guest
          who really has the address -- and the next run would take it
          back. A session whose address already carries a live session's
          queue is skipped, and where several unassigned sessions share an
          address only the newest is considered.
        * **Revive a session that has just ended.** Liveness is asked again
          immediately before each write.
        * **Leave a half-made row behind.** ``unit_of_work`` wraps one
          session's attempt (the task passes the database session's own
          savepoint); a device failure undoes that attempt's rows, as the
          login task's rollback does. Without one, a failed attempt leaves
          a PENDING row, which the next run applies rather than duplicates.

        ## Failure

        One session's failure never stops the rest. A router that cannot be
        reached is tried once per run: every other session on it is skipped
        without a connection attempt and waits for the next run.
        ``max_per_run`` bounds device attempts, not sessions examined, so
        sessions that can never be given a queue do not use it up.

        Returns ``{"assigned", "failed", "skipped_unreachable",
        "skipped_no_target", "skipped_address_in_use"}``."""
        result = {
            "assigned": 0,
            "failed": 0,
            "skipped_unreachable": 0,
            "skipped_no_target": 0,
            "skipped_address_in_use": 0,
        }
        lookup = self.sessions_without_queue_lookup
        if lookup is None or max_per_run <= 0:
            return result
        now = now or datetime.now(UTC)
        candidates = await lookup.list_sessions_without_queue(
            started_before=now - timedelta(seconds=min_age_seconds),
            location_id=location_id,
            limit=BACKFILL_UNASSIGNED_SESSION_QUEUES_SCAN_LIMIT,
        )

        routers: dict[uuid.UUID, Router | None] = {}
        unreachable_routers: set[uuid.UUID] = set()
        claimed: set[tuple[uuid.UUID, str]] = set()
        attempts = 0
        for candidate in sorted(candidates, key=lambda c: c.started_at, reverse=True):
            if attempts >= max_per_run:
                break
            router_id = candidate.router_id
            if router_allowed is not None and not router_allowed(router_id):
                continue
            if router_id in unreachable_routers:
                result["skipped_unreachable"] += 1
                continue
            if router_id not in routers:
                try:
                    routers[router_id] = await self.router_lookup.get_router(
                        router_id,
                        requesting_organization_id=candidate.organization_id,
                    )
                except Exception as exc:  # noqa: BLE001 -- per-router isolation
                    routers[router_id] = None
                    logger.warning(
                        "queue_backfill_router_lookup_failed",
                        extra={"router_id": str(router_id), "error": str(exc)},
                    )
            router = routers[router_id]
            if router is None:
                result["failed"] += 1
                continue
            if is_controller_managed(router):
                result["skipped_no_target"] += 1
                continue
            device_target = routeros_guest_queue_target(
                candidate.ip_address,
                router_addresses=(
                    getattr(router, "public_ip_address", None),
                    getattr(router, "management_ip_address", None),
                ),
            )
            if device_target is None and not candidate.device_mac:
                result["skipped_no_target"] += 1
                continue
            if candidate.device_mac:
                # The router says what the address is; one read, counted
                # against the cap like any other device round trip.
                if self.session_liveness_lookup is not None and not (
                    await self.session_liveness_lookup.live_session_ids(
                        {candidate.session_id}
                    )
                ):
                    continue
                attempts += 1
                try:
                    device_target = await self._routers_address_for_device(
                        router,
                        device_mac=candidate.device_mac,
                        claimed=device_target,
                        target_id=candidate.session_id,
                    )
                except QueueTargetNotOnRouterError:
                    result["skipped_no_target"] += 1
                    continue
                except QueueDeviceConnectionError as exc:
                    unreachable_routers.add(router_id)
                    result["failed"] += 1
                    logger.warning(
                        "queue_backfill_router_unreachable",
                        extra={
                            "session_id": str(candidate.session_id),
                            "router_id": str(router_id),
                            "error": str(exc),
                        },
                    )
                    continue
                except Exception as exc:  # noqa: BLE001 -- per-session isolation
                    result["failed"] += 1
                    logger.warning(
                        "queue_backfill_failed",
                        extra={
                            "session_id": str(candidate.session_id),
                            "router_id": str(router_id),
                            "error": str(exc),
                        },
                    )
                    continue
                if not _is_routeros_session_target(router, device_target):
                    result["skipped_no_target"] += 1
                    continue
            address = (router_id, device_target.removesuffix("/32"))
            if address in claimed or await self._address_has_a_live_sessions_queue(
                router_id=router_id,
                device_target=device_target,
                session_id=candidate.session_id,
            ):
                result["skipped_address_in_use"] += 1
                continue
            if self.session_liveness_lookup is not None and not (
                await self.session_liveness_lookup.live_session_ids(
                    {candidate.session_id}
                )
            ):
                continue
            claimed.add(address)

            if not candidate.device_mac:
                attempts += 1
            try:
                if unit_of_work is None:
                    await self._assign_queue_to_session(candidate, device_target)
                else:
                    async with unit_of_work():
                        await self._assign_queue_to_session(candidate, device_target)
                result["assigned"] += 1
                logger.info(
                    "queue_backfill_assigned",
                    extra={
                        "session_id": str(candidate.session_id),
                        "router_id": str(router_id),
                    },
                )
            except QueueDeviceConnectionError as exc:
                unreachable_routers.add(router_id)
                result["failed"] += 1
                logger.warning(
                    "queue_backfill_router_unreachable",
                    extra={
                        "session_id": str(candidate.session_id),
                        "router_id": str(router_id),
                        "error": str(exc),
                    },
                )
            except Exception as exc:  # noqa: BLE001 -- per-session isolation, see docstring
                result["failed"] += 1
                logger.warning(
                    "queue_backfill_failed",
                    extra={
                        "session_id": str(candidate.session_id),
                        "router_id": str(router_id),
                        "error": str(exc),
                    },
                )
        return result

    async def retarget_queues_for_moved_devices(
        self,
        *,
        max_per_run: int = BACKFILL_UNASSIGNED_SESSION_QUEUES_MAX_PER_RUN,
        router_allowed: Callable[[uuid.UUID], bool] | None = None,
        unit_of_work: Callable[[], AbstractAsyncContextManager[Any]] | None = None,
    ) -> dict[str, int]:
        """Re-point a live session's queue when its device's address has
        changed since the queue was written.

        ## Why this exists

        A ``/queue simple`` names one address, and a guest does not keep
        one for the length of a session. Observed live: a device signed in
        on one address and was correctly given a queue on it; twelve
        minutes later the router had the same MAC, bound and bypassed, on a
        different address, carrying a few hundred megabytes, while the
        queue on the old address had carried a few kilobytes. The
        assignment still read ACTIVE. Asking the router for the address at
        sign-in is right at sign-in and says nothing about the next lease.

        ## What it does

        For each router this platform logs in to it reads, **once**, the
        address the router has for every device (hotspot host, then DHCP
        lease, then ARP), and compares that with the address each ACTIVE
        SESSION assignment on that router names, by the session's device
        MAC. Where they differ it re-points the *existing* device row
        (``retarget_simple_queue`` -- same row, same id, same rates) and
        records the new address on the *existing* assignment. It never
        creates a row and never retires one.

        * A device the router has no entry for is left alone: it is off
          the network, and its queue is the release sweep's business once
          its session ends.
        * A session with no device on record, or one that is no longer
          ACTIVE, is not looked at.
        * Two devices that have swapped addresses each keep their own row;
          both are re-pointed, neither is asked to give way to the other.
        * An address already named by another session's row that is not
          itself moving off it is not taken: that would put two rows on one
          address. Counted as ``skipped_address_in_use`` and looked at
          again next run, by when the release sweep has usually cleared
          the row of a guest who has left.

        It takes the per-location re-apply lock first, so it never
        interleaves with a policy re-apply for the same location, and
        re-reads each assignment after that before writing.

        ## Failure

        A router that cannot be read costs one connection attempt and all
        of its rows wait for the next run. One row's failed write is undone
        in its own ``unit_of_work`` and does not stop the rest.
        ``max_per_run`` bounds device writes.

        Returns ``{"retargeted", "failed", "skipped_unreachable",
        "skipped_absent", "skipped_address_in_use", "unchanged"}``."""
        result = {
            "retargeted": 0,
            "failed": 0,
            "skipped_unreachable": 0,
            "skipped_absent": 0,
            "skipped_address_in_use": 0,
            "unchanged": 0,
        }
        lookup = self.sessions_without_queue_lookup
        if lookup is None or max_per_run <= 0:
            return result
        rows = [
            row
            for row in await self.repository.list_assignments_by_status(
                status=QueueStatus.ACTIVE.value
            )
            if row.target_type == QueueTargetType.SESSION.value
            and row.target_id is not None
            and row.router_id is not None
            and row.device_queue_id
            and row.device_target
            and not row.is_deleted
            and (router_allowed is None or router_allowed(row.router_id))
        ]
        if not rows:
            return result
        macs = await lookup.device_macs_for_active_sessions(
            {row.target_id for row in rows}
        )
        by_router: dict[uuid.UUID, list[QueueAssignment]] = {}
        # Rows this cannot judge -- no device on record, or a session that
        # is no longer ACTIVE and is waiting for the release sweep. They
        # are not moved, and the address each names is not given away.
        not_judged: dict[uuid.UUID, set[str]] = {}
        for row in rows:
            if _canonical_mac(macs.get(row.target_id)) is not None:
                by_router.setdefault(row.router_id, []).append(row)
            else:
                not_judged.setdefault(row.router_id, set()).add(
                    _plain_address(row.device_target)
                )

        writes = 0
        for router_id in sorted(by_router, key=str):
            if writes >= max_per_run:
                break
            router_rows = by_router[router_id]
            try:
                router = await self.router_lookup.get_router(
                    router_id,
                    requesting_organization_id=router_rows[0].organization_id,
                )
                if is_controller_managed(router):
                    continue
                adapter = self._get_device_adapter(router.vendor)
                if not hasattr(adapter, "list_client_addresses"):
                    continue
                credentials = self._resolve_device_credentials(router)
                for location_id in sorted(
                    {r.location_id for r in router_rows if r.location_id}, key=str
                ):
                    await self.repository.acquire_location_reapply_lock(
                        location_id=location_id
                    )
                addresses = await adapter.list_client_addresses(credentials)
            except QueueDeviceConnectionError as exc:
                result["skipped_unreachable"] += len(router_rows)
                logger.warning(
                    "queue_retarget_router_unreachable",
                    extra={"router_id": str(router_id), "error": str(exc)},
                )
                continue
            except Exception as exc:  # noqa: BLE001 -- per-router isolation
                result["failed"] += len(router_rows)
                logger.warning(
                    "queue_retarget_router_failed",
                    extra={"router_id": str(router_id), "error": str(exc)},
                )
                continue

            # Where each row should point, from the one read above.
            moves: list[tuple[QueueAssignment, str]] = []
            staying: set[str] = set(not_judged.get(router_id, ()))
            for row in router_rows:
                current = await self.repository.get_assignment_by_id(row.id)
                if current is None or current.status != QueueStatus.ACTIVE.value:
                    continue
                held = _plain_address(current.device_target)
                wanted = addresses.get(_canonical_mac(macs.get(row.target_id)) or "")
                if not wanted:
                    result["skipped_absent"] += 1
                    staying.add(held)
                    continue
                wanted = _plain_address(wanted)
                if wanted == held:
                    result["unchanged"] += 1
                    staying.add(held)
                    continue
                if not _is_routeros_session_target(router, wanted):
                    result["skipped_absent"] += 1
                    staying.add(held)
                    continue
                moves.append((current, wanted))

            claimed: set[str] = set()
            for row, wanted in moves:
                if writes >= max_per_run:
                    break
                if wanted in staying or wanted in claimed:
                    result["skipped_address_in_use"] += 1
                    continue
                claimed.add(wanted)
                old = _plain_address(row.device_target)
                writes += 1
                try:
                    if unit_of_work is None:
                        await self._retarget_one(adapter, credentials, row, wanted)
                    else:
                        async with unit_of_work():
                            await self._retarget_one(adapter, credentials, row, wanted)
                    result["retargeted"] += 1
                    logger.info(
                        "queue_assignment_retargeted",
                        extra={
                            "assignment_id": str(row.id),
                            "session_id": str(row.target_id),
                            "router_id": str(router_id),
                            "old_address": old,
                            "new_address": wanted,
                        },
                    )
                except Exception as exc:  # noqa: BLE001 -- per-row isolation
                    result["failed"] += 1
                    logger.warning(
                        "queue_retarget_failed",
                        extra={
                            "assignment_id": str(row.id),
                            "router_id": str(router_id),
                            "error": str(exc),
                        },
                    )
        return result

    async def _retarget_one(
        self,
        adapter: Any,
        credentials: QueueCredentials,
        row: QueueAssignment,
        wanted: str,
    ) -> None:
        """The device first, then the record: a write that fails leaves the
        assignment naming the address the device row still has."""
        await adapter.retarget_simple_queue(
            credentials, device_queue_id=row.device_queue_id, target=wanted
        )
        await self.repository.update_assignment(
            row, {"device_target": wanted, "error_message": None}
        )
        await self._audit(
            None,
            AuditAction.QUEUE_APPLIED,
            organization_id=row.organization_id,
            entity_id=row.id,
            description=(
                f"Queue assignment {row.id} re-pointed: the device's address "
                "changed"
            ),
        )

    async def _assign_queue_to_session(
        self, candidate: SessionWithoutQueue, device_target: str
    ) -> QueueAssignment:
        """One backfilled session, through the login's own entry point. A
        row that comes back PENDING is one an earlier failed attempt left
        behind with the rate and address already right, so
        ``resolve_and_assign_queue`` had nothing to change and made no
        device call; it is applied here."""
        assignment = await self.resolve_and_assign_queue(
            requesting_organization_id=candidate.organization_id,
            location_id=candidate.location_id,
            router_id=candidate.router_id,
            target_type=QueueTargetType.SESSION,
            target_id=candidate.session_id,
            device_target=device_target,
            guest_id=candidate.guest_id,
        )
        if assignment.status == QueueStatus.PENDING.value:
            assignment = await self.apply_queue(
                assignment.id,
                actor_user_id=None,
                requesting_organization_id=candidate.organization_id,
            )
        return assignment

    async def _address_has_a_live_sessions_queue(
        self, *, router_id: uuid.UUID, device_target: str, session_id: uuid.UUID
    ) -> bool:
        """Whether another session's queue already governs this address on
        this router. A row whose session has ended does not count -- the
        assignment about to be made retires it, as a sign-in would. With no
        liveness lookup wired every such row counts: this would rather skip
        a session than take an address from a guest it cannot ask about."""
        rivals = [
            row
            for row in await self.repository.list_assignments_for_device_target(
                router_id=router_id, device_target=device_target
            )
            if row.target_type == QueueTargetType.SESSION.value
            and row.target_id is not None
            and row.target_id != session_id
            and row.status != QueueStatus.PENDING.value
        ]
        if not rivals:
            return False
        if self.session_liveness_lookup is None:
            return True
        live = await self.session_liveness_lookup.live_session_ids(
            {row.target_id for row in rivals}
        )
        return bool(live)

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


def _plain_address(value: str | None) -> str:
    """An address without the ``/32`` RouterOS prints after a single host."""
    return (value or "").strip().removesuffix("/32")


def _canonical_mac(value: str | None) -> str | None:
    """``AA:BB:CC:DD:EE:FF`` for any spelling of a six-octet MAC, else
    ``None`` -- the form the gateway keys ``list_client_addresses`` by."""
    digits = "".join(ch for ch in (value or "") if ch.isalnum()).upper()
    if len(digits) != 12 or any(ch not in "0123456789ABCDEF" for ch in digits):
        return None
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def _device_says_row_is_gone(exc: Exception) -> bool:
    """Whether a device error means "there is no such row".

    RouterOS answers a ``remove`` of an id it does not hold with a trap
    whose message is ``no such item``; the gateway carries that text
    through unchanged. Matched on the message because that is all the
    device gives -- there is no error code for it."""
    return "no such item" in str(exc).lower()


def _is_routeros_session_target(router: Router, device_target: str | None) -> bool:
    """Whether a per-session ``/queue simple`` on ``router`` may target
    ``device_target`` -- see ``validators.routeros_guest_queue_target``."""
    return (
        routeros_guest_queue_target(
            device_target,
            router_addresses=(
                getattr(router, "public_ip_address", None),
                getattr(router, "management_ip_address", None),
            ),
        )
        is not None
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
    "SessionWithoutQueue",
    "SessionsWithoutQueueLookupProtocol",
    "is_schedule_active_now",
    "format_mikrotik_rate_limit",
]
