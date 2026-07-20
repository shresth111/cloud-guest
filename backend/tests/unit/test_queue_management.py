"""Unit tests for the Queue Management Engine domain: queue profile CRUD
(tenant-scoped reads, system-vs-org visibility), queue schedules (the pure
``is_schedule_active_now`` time-window logic -- office hours, overnight
"night mode" wrap-around, weekend day-of-week filtering, holiday specific
dates), queue templates, the full assignment lifecycle (create with
polymorphic target validation, apply/remove -- including the schedule-
suspended path that never opens a device connection, reset, move as a new
row superseding the old one, expire), the dynamic "resolve and assign"
pipeline composing ``PolicyType.BANDWIDTH``, the schedule-transition sweep,
and a structural RBAC check that every route carries a permission
dependency.

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_provisioning_engine.py``); ``asyncio_mode = "auto"`` runs
async tests directly. ``QueueManagementService`` is exercised against
small, hand-rolled in-memory fakes for its own repository and every
composed cross-domain protocol (``RouterLookupProtocol``/
``PolicyLookupProtocol``) and a controllable fake device adapter -- mirrors
``test_provisioning_engine.py``'s own identical "fake the narrow Protocol
boundary" precedent. Real device I/O
(``device_adapters.py``) is covered separately in
``test_queue_management_adapters.py``.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.policy.constants import PolicyType
from app.domains.policy.service import ResolvedPolicy
from app.domains.queue_management.constants import (
    UNLIMITED_RATE_KBPS,
    QueueScheduleType,
    QueueStatus,
    QueueTargetType,
)
from app.domains.queue_management.device_adapters import (
    QueueDeviceStatus,
)
from app.domains.queue_management.exceptions import (
    CrossOrganizationQueueAccessError,
    QueueAssignmentNotApplicableError,
    QueueAssignmentNotRemovableError,
    QueueMissingCredentialsError,
    QueueTargetIdNotAllowedError,
    QueueTargetIdRequiredError,
    QueueTargetRouterRequiredError,
)
from app.domains.queue_management.models import (
    QueueAssignment,
    QueueProfile,
    QueueSchedule,
    QueueTemplate,
)
from app.domains.queue_management.router import router as queue_management_router
from app.domains.queue_management.service import (
    QueueManagementService,
    is_schedule_active_now,
)
from app.domains.router.exceptions import RouterNotFoundError
from app.domains.router.models import Router

# ============================================================================
# Shared helpers
# ============================================================================


def _now() -> datetime:
    return datetime.now(UTC)


def _base_fields(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": uuid.uuid4(),
        "created_at": _now(),
        "updated_at": _now(),
        "deleted_at": None,
        "is_deleted": False,
        "created_by": None,
        "updated_by": None,
        "version": 1,
    }
    base.update(overrides)
    return base


def _make_router(
    *, organization_id: uuid.UUID | None = None, location_id: uuid.UUID | None = None
) -> Router:
    return Router(
        **_base_fields(
            organization_id=organization_id or uuid.uuid4(),
            location_id=location_id or uuid.uuid4(),
            name="Test Router",
            serial_number=f"SN-{uuid.uuid4().hex[:8]}",
            mac_address="AA:BB:CC:DD:EE:FF",
            model="RB4011",
            vendor="mikrotik",
            routeros_version=None,
            management_ip_address="10.0.0.1",
            public_ip_address=None,
            status="online",
            last_seen_at=None,
            last_health_check_at=None,
            health_status=None,
            api_username="admin",
            api_credentials_encrypted="encrypted-placeholder",
            settings={},
        )
    )


# ============================================================================
# Fakes: repository
# ============================================================================


@dataclass
class FakeQueueManagementRepository:
    profiles: dict[uuid.UUID, QueueProfile] = field(default_factory=dict)
    schedules: dict[uuid.UUID, QueueSchedule] = field(default_factory=dict)
    templates: dict[uuid.UUID, QueueTemplate] = field(default_factory=dict)
    assignments: dict[uuid.UUID, QueueAssignment] = field(default_factory=dict)

    async def create_profile(self, **fields: object) -> QueueProfile:
        profile = QueueProfile(**_base_fields(**fields))
        self.profiles[profile.id] = profile
        return profile

    async def get_profile_by_id(
        self, profile_id: uuid.UUID, *, include_deleted: bool = False
    ) -> QueueProfile | None:
        profile = self.profiles.get(profile_id)
        if profile is None or (profile.is_deleted and not include_deleted):
            return None
        return profile

    async def update_profile(
        self, profile: QueueProfile, data: dict[str, object]
    ) -> QueueProfile:
        for key, value in data.items():
            if hasattr(profile, key):
                setattr(profile, key, value)
        profile.version += 1
        return profile

    async def soft_delete_profile(self, profile: QueueProfile) -> QueueProfile:
        profile.is_deleted = True
        profile.deleted_at = _now()
        return profile

    async def list_profiles(
        self, *, requesting_organization_id, page: int, page_size: int
    ):
        values = [p for p in self.profiles.values() if not p.is_deleted]
        if requesting_organization_id is not None:
            values = [
                p
                for p in values
                if p.organization_id == requesting_organization_id
                or p.organization_id is None
            ]
        values.sort(key=lambda p: p.created_at, reverse=True)
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))

    async def create_schedule(self, **fields: object) -> QueueSchedule:
        schedule = QueueSchedule(**_base_fields(**fields))
        self.schedules[schedule.id] = schedule
        return schedule

    async def get_schedule_by_id(self, schedule_id: uuid.UUID) -> QueueSchedule | None:
        return self.schedules.get(schedule_id)

    async def update_schedule(
        self, schedule: QueueSchedule, data: dict[str, object]
    ) -> QueueSchedule:
        for key, value in data.items():
            if hasattr(schedule, key):
                setattr(schedule, key, value)
        schedule.version += 1
        return schedule

    async def list_schedules(
        self, *, requesting_organization_id, page: int, page_size: int
    ):
        values = [s for s in self.schedules.values() if not s.is_deleted]
        if requesting_organization_id is not None:
            values = [
                s
                for s in values
                if s.organization_id == requesting_organization_id
                or s.organization_id is None
            ]
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))

    async def create_template(self, **fields: object) -> QueueTemplate:
        template = QueueTemplate(**_base_fields(**fields))
        self.templates[template.id] = template
        return template

    async def get_template_by_id(self, template_id: uuid.UUID) -> QueueTemplate | None:
        return self.templates.get(template_id)

    async def update_template(self, template, data):
        for key, value in data.items():
            if hasattr(template, key):
                setattr(template, key, value)
        template.version += 1
        return template

    async def list_templates(
        self, *, requesting_organization_id, page: int, page_size: int
    ):
        values = [t for t in self.templates.values() if not t.is_deleted]
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))

    async def create_assignment(self, **fields: object) -> QueueAssignment:
        assignment = QueueAssignment(**_base_fields(**fields))
        self.assignments[assignment.id] = assignment
        return assignment

    async def get_assignment_by_id(
        self, assignment_id: uuid.UUID, *, include_deleted: bool = False
    ) -> QueueAssignment | None:
        assignment = self.assignments.get(assignment_id)
        if assignment is None or (assignment.is_deleted and not include_deleted):
            return None
        return assignment

    async def update_assignment(
        self, assignment: QueueAssignment, data: dict[str, object]
    ) -> QueueAssignment:
        for key, value in data.items():
            if hasattr(assignment, key):
                setattr(assignment, key, value)
        assignment.version += 1
        return assignment

    async def list_assignments(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        **_kw,
    ):
        values = [a for a in self.assignments.values() if not a.is_deleted]
        for key, value in (filters or {}).items():
            values = [a for a in values if getattr(a, key, None) == value]
        values.sort(key=lambda a: a.created_at, reverse=True)
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))

    async def get_active_assignment_for_target(
        self, *, target_type: str, target_id: uuid.UUID | None
    ) -> QueueAssignment | None:
        candidates = [
            a
            for a in self.assignments.values()
            if a.target_type == target_type
            and a.target_id == target_id
            and a.status != QueueStatus.EXPIRED.value
            and not a.is_deleted
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda a: a.created_at)


@dataclass
class FakeAuditLogWriter:
    entries: list[dict[str, object]] = field(default_factory=list)

    async def create_audit_log_entry(self, **fields: object) -> dict[str, object]:
        self.entries.append(fields)
        return fields


@dataclass
class FakeRouterLookup:
    routers: dict[uuid.UUID, Router] = field(default_factory=dict)
    secrets: dict[uuid.UUID, str | None] = field(default_factory=dict)

    def add(self, router: Router, *, secret: str | None = "decrypted-secret") -> Router:
        self.routers[router.id] = router
        self.secrets[router.id] = secret
        return router

    async def get_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Router:
        router = self.routers.get(router_id)
        if router is None:
            raise RouterNotFoundError(router_id)
        if (
            requesting_organization_id is not None
            and router.organization_id != requesting_organization_id
        ):
            raise RouterNotFoundError(router_id)
        return router

    def get_decrypted_api_secret(self, router: Router) -> str | None:
        return self.secrets.get(router.id)


@dataclass
class FakePolicyLookup:
    rules_by_scope: dict[tuple, dict[str, object]] = field(default_factory=dict)

    async def resolve_effective_policy(
        self, *, policy_type: PolicyType, organization_id, location_id
    ) -> ResolvedPolicy:
        rules = self.rules_by_scope.get((organization_id, location_id), {})
        return ResolvedPolicy(
            policy_type=policy_type,
            organization_id=organization_id,
            location_id=location_id,
            rules=rules,
            source="platform_default" if not rules else "organization",
        )


@dataclass
class FakeQueueDeviceAdapter:
    vendor: str = "mikrotik"
    created_ids: list[str] = field(default_factory=list)
    updated_calls: list[dict[str, object]] = field(default_factory=list)
    removed_ids: list[str] = field(default_factory=list)
    _counter: int = 0

    async def create_simple_queue(self, credentials, **kwargs) -> str:
        self._counter += 1
        device_id = f"*{self._counter}"
        self.created_ids.append(device_id)
        return device_id

    async def update_simple_queue(
        self, credentials, *, device_queue_id, **kwargs
    ) -> None:
        self.updated_calls.append({"device_queue_id": device_queue_id, **kwargs})

    async def delete_simple_queue(self, credentials, *, device_queue_id) -> None:
        self.removed_ids.append(device_queue_id)

    async def create_queue_tree(self, credentials, **kwargs) -> str:
        return "*tree1"

    async def apply_pcq(self, credentials, **kwargs) -> str:
        return "*pcq1"

    async def set_priority(self, credentials, **kwargs) -> None:
        return None

    async def assign_queue_to_target(self, credentials, **kwargs) -> None:
        return None

    async def remove_queue(self, credentials, *, device_queue_id, **kwargs) -> None:
        self.removed_ids.append(device_queue_id)

    async def read_queue_status(self, credentials, *, device_queue_id, **kwargs):
        return QueueDeviceStatus(
            device_queue_id=device_queue_id,
            name="q",
            target="10.0.0.5/32",
            disabled=False,
            bytes_uploaded=0,
            bytes_downloaded=0,
            packets_uploaded=0,
            packets_downloaded=0,
            queued_bytes=0,
        )


# ============================================================================
# Harness
# ============================================================================


@dataclass
class Harness:
    service: QueueManagementService
    repository: FakeQueueManagementRepository
    router_lookup: FakeRouterLookup
    policy_lookup: FakePolicyLookup
    audit_writer: FakeAuditLogWriter
    device_adapter: FakeQueueDeviceAdapter


def make_harness() -> Harness:
    repository = FakeQueueManagementRepository()
    router_lookup = FakeRouterLookup()
    policy_lookup = FakePolicyLookup()
    audit_writer = FakeAuditLogWriter()
    adapter = FakeQueueDeviceAdapter()

    service = QueueManagementService(
        repository,
        router_lookup,
        policy_lookup,
        audit_writer=audit_writer,
        device_adapter_resolver=lambda vendor: adapter,
    )
    return Harness(
        service=service,
        repository=repository,
        router_lookup=router_lookup,
        policy_lookup=policy_lookup,
        audit_writer=audit_writer,
        device_adapter=adapter,
    )


# ============================================================================
# Queue profiles
# ============================================================================


class TestQueueProfiles:
    async def test_create_org_scoped_profile(self) -> None:
        h = make_harness()
        org_id = uuid.uuid4()
        profile = await h.service.create_profile(
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=org_id,
            name="5 Mbps",
            download_rate_kbps=5000,
            upload_rate_kbps=1000,
        )
        assert profile.organization_id == org_id
        assert profile.is_system_profile is False
        assert len(h.audit_writer.entries) == 1

    async def test_create_system_profile_has_no_organization(self) -> None:
        h = make_harness()
        profile = await h.service.create_profile(
            actor_user_id=None,
            requesting_organization_id=uuid.uuid4(),
            name="Unlimited",
            download_rate_kbps=UNLIMITED_RATE_KBPS,
            upload_rate_kbps=UNLIMITED_RATE_KBPS,
            is_system_profile=True,
        )
        assert profile.organization_id is None

    async def test_cross_organization_read_raises(self) -> None:
        h = make_harness()
        org_a = uuid.uuid4()
        org_b = uuid.uuid4()
        profile = await h.service.create_profile(
            actor_user_id=None,
            requesting_organization_id=org_a,
            name="Org A profile",
            download_rate_kbps=1000,
            upload_rate_kbps=500,
        )
        with pytest.raises(CrossOrganizationQueueAccessError):
            await h.service.get_profile(profile.id, requesting_organization_id=org_b)

    async def test_system_profile_readable_by_any_organization(self) -> None:
        h = make_harness()
        profile = await h.service.create_profile(
            actor_user_id=None,
            requesting_organization_id=None,
            name="Unlimited",
            download_rate_kbps=0,
            upload_rate_kbps=0,
            is_system_profile=True,
        )
        fetched = await h.service.get_profile(
            profile.id, requesting_organization_id=uuid.uuid4()
        )
        assert fetched.id == profile.id

    async def test_list_profiles_includes_org_and_system_rows(self) -> None:
        h = make_harness()
        org_id = uuid.uuid4()
        await h.service.create_profile(
            actor_user_id=None,
            requesting_organization_id=org_id,
            name="Org profile",
            download_rate_kbps=1000,
            upload_rate_kbps=500,
        )
        await h.service.create_profile(
            actor_user_id=None,
            requesting_organization_id=None,
            name="System profile",
            download_rate_kbps=0,
            upload_rate_kbps=0,
            is_system_profile=True,
        )
        profiles, _meta = await h.service.list_profiles(
            requesting_organization_id=org_id
        )
        assert len(profiles) == 2

    async def test_update_and_delete_profile(self) -> None:
        h = make_harness()
        org_id = uuid.uuid4()
        profile = await h.service.create_profile(
            actor_user_id=None,
            requesting_organization_id=org_id,
            name="5 Mbps",
            download_rate_kbps=5000,
            upload_rate_kbps=1000,
        )
        updated = await h.service.update_profile(
            profile.id,
            actor_user_id=None,
            requesting_organization_id=org_id,
            name="5 Mbps Renamed",
        )
        assert updated.name == "5 Mbps Renamed"
        deleted = await h.service.delete_profile(
            profile.id, actor_user_id=None, requesting_organization_id=org_id
        )
        assert deleted.is_deleted is True


# ============================================================================
# Queue schedules: is_schedule_active_now
# ============================================================================


def _make_schedule(**overrides: object) -> QueueSchedule:
    base = dict(
        organization_id=None,
        name="Test Schedule",
        schedule_type=QueueScheduleType.CUSTOM.value,
        days_of_week=[],
        start_time=None,
        end_time=None,
        specific_dates=[],
        timezone="UTC",
        is_active=True,
    )
    base.update(overrides)
    return QueueSchedule(**_base_fields(**base))


class TestIsScheduleActiveNow:
    def test_inactive_schedule_is_never_active(self) -> None:
        schedule = _make_schedule(is_active=False, start_time="00:00", end_time="23:59")
        assert is_schedule_active_now(schedule) is False

    def test_within_daytime_window(self) -> None:
        schedule = _make_schedule(start_time="09:00", end_time="17:00")
        at = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)  # Monday, noon
        assert is_schedule_active_now(schedule, at=at) is True

    def test_outside_daytime_window(self) -> None:
        schedule = _make_schedule(start_time="09:00", end_time="17:00")
        at = datetime(2026, 7, 20, 20, 0, tzinfo=UTC)
        assert is_schedule_active_now(schedule, at=at) is False

    def test_overnight_window_wraps_past_midnight(self) -> None:
        schedule = _make_schedule(
            schedule_type=QueueScheduleType.NIGHT_MODE.value,
            start_time="22:00",
            end_time="06:00",
        )
        at_night = datetime(2026, 7, 20, 23, 30, tzinfo=UTC)
        at_early_morning = datetime(2026, 7, 21, 3, 0, tzinfo=UTC)
        at_midday = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)
        assert is_schedule_active_now(schedule, at=at_night) is True
        assert is_schedule_active_now(schedule, at=at_early_morning) is True
        assert is_schedule_active_now(schedule, at=at_midday) is False

    def test_weekend_day_of_week_filter(self) -> None:
        schedule = _make_schedule(
            schedule_type=QueueScheduleType.WEEKEND.value, days_of_week=[5, 6]
        )
        saturday = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)
        monday = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)
        assert is_schedule_active_now(schedule, at=saturday) is True
        assert is_schedule_active_now(schedule, at=monday) is False

    def test_holiday_specific_dates(self) -> None:
        schedule = _make_schedule(
            schedule_type=QueueScheduleType.HOLIDAY.value,
            specific_dates=["2026-12-25"],
        )
        christmas = datetime(2026, 12, 25, 12, 0, tzinfo=UTC)
        other_day = datetime(2026, 12, 26, 12, 0, tzinfo=UTC)
        assert is_schedule_active_now(schedule, at=christmas) is True
        assert is_schedule_active_now(schedule, at=other_day) is False


class TestQueueScheduleService:
    async def test_create_and_get_schedule(self) -> None:
        h = make_harness()
        org_id = uuid.uuid4()
        schedule = await h.service.create_schedule(
            actor_user_id=None,
            requesting_organization_id=org_id,
            name="Office Hours",
            schedule_type=QueueScheduleType.OFFICE_HOURS,
            start_time="09:00",
            end_time="18:00",
        )
        fetched = await h.service.get_schedule(
            schedule.id, requesting_organization_id=org_id
        )
        assert fetched.name == "Office Hours"


# ============================================================================
# Queue templates
# ============================================================================


class TestQueueTemplates:
    async def test_create_template_composing_profile(self) -> None:
        h = make_harness()
        org_id = uuid.uuid4()
        profile = await h.service.create_profile(
            actor_user_id=None,
            requesting_organization_id=org_id,
            name="10 Mbps",
            download_rate_kbps=10000,
            upload_rate_kbps=2000,
        )
        template = await h.service.create_template(
            actor_user_id=None,
            requesting_organization_id=org_id,
            name="Hotel Guest Package",
            persona="hotel_guest",
            queue_profile_id=profile.id,
        )
        assert template.queue_profile_id == profile.id


# ============================================================================
# Queue assignments: create / target validation
# ============================================================================


class TestCreateAssignment:
    async def test_device_bound_target_requires_router(self) -> None:
        h = make_harness()
        with pytest.raises(QueueTargetRouterRequiredError):
            await h.service.create_assignment(
                actor_user_id=None,
                requesting_organization_id=uuid.uuid4(),
                target_type=QueueTargetType.GUEST,
                target_id=uuid.uuid4(),
                router_id=None,
            )

    async def test_non_organization_target_requires_target_id(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        with pytest.raises(QueueTargetIdRequiredError):
            await h.service.create_assignment(
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
                target_type=QueueTargetType.SESSION,
                target_id=None,
                router_id=router.id,
            )

    async def test_organization_target_forbids_target_id(self) -> None:
        h = make_harness()
        with pytest.raises(QueueTargetIdNotAllowedError):
            await h.service.create_assignment(
                actor_user_id=None,
                requesting_organization_id=uuid.uuid4(),
                target_type=QueueTargetType.ORGANIZATION,
                target_id=uuid.uuid4(),
            )

    async def test_denormalizes_organization_and_location_from_router(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        assignment = await h.service.create_assignment(
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            target_type=QueueTargetType.SESSION,
            target_id=uuid.uuid4(),
            router_id=router.id,
            device_target="10.0.0.5/32",
        )
        assert assignment.organization_id == router.organization_id
        assert assignment.location_id == router.location_id
        assert assignment.status == QueueStatus.PENDING.value


# ============================================================================
# Queue lifecycle: apply / remove / reset / move / expire
# ============================================================================


class TestApplyAndRemoveQueue:
    async def _create_assignment_with_profile(self, h: Harness):
        router = h.router_lookup.add(_make_router())
        profile = await h.service.create_profile(
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            name="5 Mbps",
            download_rate_kbps=5000,
            upload_rate_kbps=1000,
        )
        assignment = await h.service.create_assignment(
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            target_type=QueueTargetType.SESSION,
            target_id=uuid.uuid4(),
            router_id=router.id,
            device_target="10.0.0.5/32",
            queue_profile_id=profile.id,
        )
        return assignment, router, profile

    async def test_apply_creates_device_queue_and_activates(self) -> None:
        h = make_harness()
        assignment, _router, _profile = await self._create_assignment_with_profile(h)

        applied = await h.service.apply_queue(
            assignment.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=assignment.organization_id,
        )
        assert applied.status == QueueStatus.ACTIVE.value
        assert applied.device_queue_id is not None
        assert applied.applied_at is not None
        assert len(h.device_adapter.created_ids) == 1

    async def test_apply_twice_updates_existing_device_queue(self) -> None:
        h = make_harness()
        assignment, _router, _profile = await self._create_assignment_with_profile(h)
        await h.service.apply_queue(
            assignment.id,
            actor_user_id=None,
            requesting_organization_id=assignment.organization_id,
        )
        await h.service.remove_queue(
            assignment.id,
            actor_user_id=None,
            requesting_organization_id=assignment.organization_id,
        )
        await h.service.apply_queue(
            assignment.id,
            actor_user_id=None,
            requesting_organization_id=assignment.organization_id,
        )
        assert len(h.device_adapter.created_ids) == 2  # removed, then re-created

    async def test_apply_already_active_raises(self) -> None:
        h = make_harness()
        assignment, _router, _profile = await self._create_assignment_with_profile(h)
        await h.service.apply_queue(
            assignment.id, actor_user_id=None, requesting_organization_id=None
        )
        with pytest.raises(QueueAssignmentNotApplicableError):
            await h.service.apply_queue(
                assignment.id, actor_user_id=None, requesting_organization_id=None
            )

    async def test_apply_missing_credentials_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router(), secret=None)
        profile = await h.service.create_profile(
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            name="5 Mbps",
            download_rate_kbps=5000,
            upload_rate_kbps=1000,
        )
        assignment = await h.service.create_assignment(
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            target_type=QueueTargetType.SESSION,
            target_id=uuid.uuid4(),
            router_id=router.id,
            device_target="10.0.0.5/32",
            queue_profile_id=profile.id,
        )
        with pytest.raises(QueueMissingCredentialsError):
            await h.service.apply_queue(
                assignment.id, actor_user_id=None, requesting_organization_id=None
            )

    async def test_apply_with_closed_schedule_window_suspends_without_device_call(
        self,
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        profile = await h.service.create_profile(
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            name="Night Rate",
            download_rate_kbps=1000,
            upload_rate_kbps=500,
        )
        # A HOLIDAY schedule matching a date that can never be "today" --
        # deterministically closed regardless of when this test actually
        # runs, unlike a recurring time-of-day window.
        schedule = await h.service.create_schedule(
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            name="Never",
            schedule_type=QueueScheduleType.HOLIDAY,
            specific_dates=["1999-01-01"],
        )
        assignment = await h.service.create_assignment(
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            target_type=QueueTargetType.SESSION,
            target_id=uuid.uuid4(),
            router_id=router.id,
            device_target="10.0.0.5/32",
            queue_profile_id=profile.id,
            queue_schedule_id=schedule.id,
        )

        applied = await h.service.apply_queue(
            assignment.id, actor_user_id=None, requesting_organization_id=None
        )
        assert applied.status == QueueStatus.SUSPENDED.value
        assert len(h.device_adapter.created_ids) == 0

    async def test_remove_transitions_active_to_disabled(self) -> None:
        h = make_harness()
        assignment, _router, _profile = await self._create_assignment_with_profile(h)
        await h.service.apply_queue(
            assignment.id, actor_user_id=None, requesting_organization_id=None
        )
        removed = await h.service.remove_queue(
            assignment.id, actor_user_id=None, requesting_organization_id=None
        )
        assert removed.status == QueueStatus.DISABLED.value
        assert removed.device_queue_id is None
        assert len(h.device_adapter.removed_ids) == 1

    async def test_remove_non_active_raises(self) -> None:
        h = make_harness()
        assignment, _router, _profile = await self._create_assignment_with_profile(h)
        with pytest.raises(QueueAssignmentNotRemovableError):
            await h.service.remove_queue(
                assignment.id, actor_user_id=None, requesting_organization_id=None
            )

    async def test_reset_queue_removes_then_reapplies(self) -> None:
        h = make_harness()
        assignment, _router, _profile = await self._create_assignment_with_profile(h)
        await h.service.apply_queue(
            assignment.id, actor_user_id=None, requesting_organization_id=None
        )
        reset = await h.service.reset_queue(
            assignment.id, actor_user_id=None, requesting_organization_id=None
        )
        assert reset.status == QueueStatus.ACTIVE.value
        assert len(h.device_adapter.removed_ids) == 1
        assert len(h.device_adapter.created_ids) == 2


class TestMoveQueue:
    async def test_move_creates_new_row_and_expires_old(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        profile_a = await h.service.create_profile(
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            name="A",
            download_rate_kbps=1000,
            upload_rate_kbps=500,
        )
        profile_b = await h.service.create_profile(
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            name="B",
            download_rate_kbps=9000,
            upload_rate_kbps=3000,
        )
        old = await h.service.create_assignment(
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            target_type=QueueTargetType.SESSION,
            target_id=uuid.uuid4(),
            router_id=router.id,
            device_target="10.0.0.5/32",
            queue_profile_id=profile_a.id,
        )
        await h.service.apply_queue(
            old.id, actor_user_id=None, requesting_organization_id=None
        )

        new_assignment = await h.service.move_queue(
            old.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            new_queue_profile_id=profile_b.id,
        )

        assert new_assignment.id != old.id
        assert new_assignment.queue_profile_id == profile_b.id
        assert new_assignment.status == QueueStatus.ACTIVE.value

        old_refetched = await h.repository.get_assignment_by_id(old.id)
        assert old_refetched.status == QueueStatus.EXPIRED.value
        assert old_refetched.superseded_by_assignment_id == new_assignment.id

    async def test_history_returns_original_and_superseding_rows(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        profile = await h.service.create_profile(
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            name="A",
            download_rate_kbps=1000,
            upload_rate_kbps=500,
        )
        target_id = uuid.uuid4()
        old = await h.service.create_assignment(
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            target_type=QueueTargetType.SESSION,
            target_id=target_id,
            router_id=router.id,
            device_target="10.0.0.5/32",
            queue_profile_id=profile.id,
        )
        await h.service.move_queue(
            old.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            new_queue_profile_id=profile.id,
            auto_apply=False,
        )
        history, _meta = await h.service.get_history(
            target_type=QueueTargetType.SESSION,
            target_id=target_id,
            requesting_organization_id=router.organization_id,
        )
        assert len(history) == 2


class TestExpireAssignment:
    async def test_expire_pending_assignment(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        profile = await h.service.create_profile(
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            name="A",
            download_rate_kbps=1000,
            upload_rate_kbps=500,
        )
        assignment = await h.service.create_assignment(
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            target_type=QueueTargetType.SESSION,
            target_id=uuid.uuid4(),
            router_id=router.id,
            device_target="10.0.0.5/32",
            queue_profile_id=profile.id,
        )
        expired = await h.service.expire_assignment(
            assignment.id, actor_user_id=None, requesting_organization_id=None
        )
        assert expired.status == QueueStatus.EXPIRED.value

    async def test_expire_active_assignment_removes_from_device_first(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        profile = await h.service.create_profile(
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            name="A",
            download_rate_kbps=1000,
            upload_rate_kbps=500,
        )
        assignment = await h.service.create_assignment(
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            target_type=QueueTargetType.SESSION,
            target_id=uuid.uuid4(),
            router_id=router.id,
            device_target="10.0.0.5/32",
            queue_profile_id=profile.id,
        )
        await h.service.apply_queue(
            assignment.id, actor_user_id=None, requesting_organization_id=None
        )
        expired = await h.service.expire_assignment(
            assignment.id, actor_user_id=None, requesting_organization_id=None
        )
        assert expired.status == QueueStatus.EXPIRED.value
        assert len(h.device_adapter.removed_ids) == 1


# ============================================================================
# Dynamic queue assignment (resolve_and_assign_queue)
# ============================================================================


class TestResolveAndAssignQueue:
    async def test_no_policy_configured_falls_back_to_unlimited(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        target_id = uuid.uuid4()

        assignment = await h.service.resolve_and_assign_queue(
            requesting_organization_id=router.organization_id,
            location_id=router.location_id,
            router_id=router.id,
            target_type=QueueTargetType.SESSION,
            target_id=target_id,
            device_target="10.0.0.5/32",
        )
        assert assignment.status == QueueStatus.ACTIVE.value
        profile = await h.service.get_profile(assignment.queue_profile_id)
        assert profile.download_rate_kbps == UNLIMITED_RATE_KBPS
        assert profile.is_system_profile is True

    async def test_bandwidth_policy_resolves_matching_profile(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        h.policy_lookup.rules_by_scope[(router.organization_id, router.location_id)] = {
            "download_rate_kbps": 5000,
            "upload_rate_kbps": 1000,
            "burst_download_kbps": None,
            "burst_upload_kbps": None,
            "burst_threshold_kbps": None,
            "burst_time_seconds": None,
            "priority": None,
        }
        target_id = uuid.uuid4()

        assignment = await h.service.resolve_and_assign_queue(
            requesting_organization_id=router.organization_id,
            location_id=router.location_id,
            router_id=router.id,
            target_type=QueueTargetType.SESSION,
            target_id=target_id,
            device_target="10.0.0.5/32",
        )
        profile = await h.service.get_profile(assignment.queue_profile_id)
        assert profile.download_rate_kbps == 5000
        assert profile.upload_rate_kbps == 1000

    async def test_existing_assignment_with_same_profile_is_idempotent(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        target_id = uuid.uuid4()

        first = await h.service.resolve_and_assign_queue(
            requesting_organization_id=router.organization_id,
            location_id=router.location_id,
            router_id=router.id,
            target_type=QueueTargetType.SESSION,
            target_id=target_id,
            device_target="10.0.0.5/32",
        )
        second = await h.service.resolve_and_assign_queue(
            requesting_organization_id=router.organization_id,
            location_id=router.location_id,
            router_id=router.id,
            target_type=QueueTargetType.SESSION,
            target_id=target_id,
            device_target="10.0.0.5/32",
        )
        assert second.id == first.id

    async def test_existing_assignment_with_different_profile_moves(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        target_id = uuid.uuid4()

        first = await h.service.resolve_and_assign_queue(
            requesting_organization_id=router.organization_id,
            location_id=router.location_id,
            router_id=router.id,
            target_type=QueueTargetType.SESSION,
            target_id=target_id,
            device_target="10.0.0.5/32",
        )
        h.policy_lookup.rules_by_scope[(router.organization_id, router.location_id)] = {
            "download_rate_kbps": 2000,
            "upload_rate_kbps": 500,
            "burst_download_kbps": None,
            "burst_upload_kbps": None,
            "burst_threshold_kbps": None,
            "burst_time_seconds": None,
            "priority": None,
        }
        second = await h.service.resolve_and_assign_queue(
            requesting_organization_id=router.organization_id,
            location_id=router.location_id,
            router_id=router.id,
            target_type=QueueTargetType.SESSION,
            target_id=target_id,
            device_target="10.0.0.5/32",
        )
        assert second.id != first.id
        old_refetched = await h.repository.get_assignment_by_id(first.id)
        assert old_refetched.status == QueueStatus.EXPIRED.value


# ============================================================================
# Schedule-transition sweep
# ============================================================================


class TestSweepScheduleTransitions:
    async def test_sweep_suspends_active_assignment_outside_window(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        profile = await h.service.create_profile(
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            name="A",
            download_rate_kbps=1000,
            upload_rate_kbps=500,
        )
        # A schedule window that is never active (start == end at an
        # instant only) -- guarantees a deterministic "closed" state
        # regardless of when the test actually runs.
        schedule = await h.service.create_schedule(
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            name="Never",
            schedule_type=QueueScheduleType.HOLIDAY,
            specific_dates=["1999-01-01"],
        )
        assignment = await h.service.create_assignment(
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            target_type=QueueTargetType.SESSION,
            target_id=uuid.uuid4(),
            router_id=router.id,
            device_target="10.0.0.5/32",
            queue_profile_id=profile.id,
            queue_schedule_id=schedule.id,
        )
        # Force ACTIVE directly (bypassing apply_queue's own schedule
        # check) to simulate "was active, window has since closed".
        await h.repository.update_assignment(
            assignment,
            {"status": QueueStatus.ACTIVE.value, "device_queue_id": "*1"},
        )

        result = await h.service.sweep_schedule_transitions()
        assert result["suspended"] == 1
        refetched = await h.repository.get_assignment_by_id(assignment.id)
        assert refetched.status == QueueStatus.SUSPENDED.value

    async def test_sweep_resumes_suspended_assignment_inside_window(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        profile = await h.service.create_profile(
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            name="A",
            download_rate_kbps=1000,
            upload_rate_kbps=500,
        )
        today = datetime.now(UTC).date().isoformat()
        schedule = await h.service.create_schedule(
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            name="Always today",
            schedule_type=QueueScheduleType.HOLIDAY,
            specific_dates=[today],
        )
        assignment = await h.service.create_assignment(
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            target_type=QueueTargetType.SESSION,
            target_id=uuid.uuid4(),
            router_id=router.id,
            device_target="10.0.0.5/32",
            queue_profile_id=profile.id,
            queue_schedule_id=schedule.id,
        )
        await h.repository.update_assignment(
            assignment, {"status": QueueStatus.SUSPENDED.value}
        )

        result = await h.service.sweep_schedule_transitions()
        assert result["resumed"] == 1
        refetched = await h.repository.get_assignment_by_id(assignment.id)
        assert refetched.status == QueueStatus.ACTIVE.value


# ============================================================================
# RBAC -- every route requires a permission dependency
# ============================================================================


class TestEveryRouteRequiresPermission:
    def test_every_queue_management_route_has_a_permission_dependency(self) -> None:
        assert len(queue_management_router.routes) == 18
        for route in queue_management_router.routes:
            assert (
                route.dependencies != []
            ), f"{route.path} ({route.methods}) has no permission dependency"
