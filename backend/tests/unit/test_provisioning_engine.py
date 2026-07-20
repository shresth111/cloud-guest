"""Unit tests for the Provisioning Engine domain: job creation (policy
snapshot freezing, denormalized organization/location), the full status
transition graph (start/cancel/retry/rollback -- including the "new row,
not mutate" convention for retry/rollback), tenant isolation, the
history/timeline read-models, the three ad-hoc actions (discover/validate/
generate-configuration), and the full seven-step ``run_provision_job``
orchestration (success path, a mid-sequence step failure halting the
job, and a rollback job's ``GENERATE_CONFIG`` skip).

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_policy.py``); ``asyncio_mode = "auto"`` runs async tests
directly. ``ProvisioningEngineService`` is exercised against small,
hand-rolled in-memory fakes for its own repository and every composed
cross-domain protocol (``RouterLookupProtocol``/
``RouterProvisioningLookupProtocol``/``PolicyLookupProtocol``/
``NasLookupProtocol``) and a controllable fake device adapter -- mirroring
``test_policy.py``'s own "fake the narrow Protocol boundary, not the real
composed service" precedent, since Router/Router Provisioning/Policy/Guest
are all peripheral, already-tested domains here, not the subject under
test. Real device I/O (``device_adapters.py``) is covered separately in
``test_provisioning_engine_adapters.py``.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.policy.constants import PolicyType
from app.domains.policy.service import ResolvedPolicy
from app.domains.provisioning_engine.constants import (
    ProvisionJobStatus,
    ProvisionLogLevel,
    ProvisionStepStatus,
    ProvisionStepType,
)
from app.domains.provisioning_engine.device_adapters import (
    DeviceCredentials,
    DeviceDiscoveryResult,
    DeviceHealthResult,
)
from app.domains.provisioning_engine.exceptions import (
    InvalidProvisionJobStatusTransitionError,
    ProvisionDeviceConnectionError,
    ProvisionJobHasNoAppliedVersionError,
    ProvisionJobNotFoundError,
    ProvisionJobNotRetryableError,
    ProvisionJobNotRollbackableError,
    ProvisionJobRetryLimitExceededError,
    ProvisionMissingCredentialsError,
    ProvisionNoPriorVersionToRollBackToError,
    ProvisionTemplateNotFoundError,
    UnsupportedDeviceVendorError,
)
from app.domains.provisioning_engine.models import (
    ProvisionJob,
    ProvisionLog,
    ProvisionStep,
    ProvisionTemplate,
)
from app.domains.provisioning_engine.repository import (
    ProvisioningEngineRepository,
    RedisProvisionEngineQueueDispatcher,
)
from app.domains.provisioning_engine.router import router as provisioning_engine_router
from app.domains.provisioning_engine.service import ProvisioningEngineService
from app.domains.router.exceptions import RouterNotFoundError
from app.domains.router.models import Router
from app.domains.router_provisioning.exceptions import DuplicateConfigVariableError
from app.domains.router_provisioning.models import ConfigTemplate, ConfigVersion

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


def _make_config_template(*, vendor: str = "mikrotik") -> ConfigTemplate:
    return ConfigTemplate(
        **_base_fields(
            organization_id=None,
            name="Hotel Base",
            description=None,
            is_system_template=True,
            applicable_router_model=None,
            vendor=vendor,
            template_content="/ip dns set servers={{dns_primary}}",
            is_active=True,
        )
    )


def _make_config_version(
    *, router_id: uuid.UUID, version_number: int, rendered_content: str = "content"
) -> ConfigVersion:
    return ConfigVersion(
        **_base_fields(
            router_id=router_id,
            profile_id=None,
            version_number=version_number,
            rendered_content=rendered_content,
            status="applied",
            created_by_user_id=None,
            applied_at=_now(),
            rollback_of_version_id=None,
            is_backup=False,
        )
    )


# ============================================================================
# Fakes: repository (this domain's own)
# ============================================================================


@dataclass
class FakeProvisioningEngineRepository:
    jobs: dict[uuid.UUID, ProvisionJob] = field(default_factory=dict)
    steps: dict[uuid.UUID, ProvisionStep] = field(default_factory=dict)
    logs: dict[uuid.UUID, ProvisionLog] = field(default_factory=dict)
    templates: dict[uuid.UUID, ProvisionTemplate] = field(default_factory=dict)

    async def create_job(self, **fields: object) -> ProvisionJob:
        job = ProvisionJob(**_base_fields(**fields))
        self.jobs[job.id] = job
        return job

    async def get_job_by_id(
        self, job_id: uuid.UUID, *, include_deleted: bool = False
    ) -> ProvisionJob | None:
        job = self.jobs.get(job_id)
        if job is None or (job.is_deleted and not include_deleted):
            return None
        return job

    async def update_job(
        self, job: ProvisionJob, data: dict[str, object]
    ) -> ProvisionJob:
        for key, value in data.items():
            if hasattr(job, key):
                setattr(job, key, value)
        job.version += 1
        return job

    async def list_jobs(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        **_kw,
    ):
        values = [j for j in self.jobs.values() if not j.is_deleted]
        for key, value in (filters or {}).items():
            values = [j for j in values if getattr(j, key, None) == value]
        values.sort(key=lambda j: j.created_at, reverse=True)
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))

    async def create_step(self, **fields: object) -> ProvisionStep:
        step = ProvisionStep(**_base_fields(**fields))
        self.steps[step.id] = step
        return step

    async def get_step_by_id(self, step_id: uuid.UUID) -> ProvisionStep | None:
        return self.steps.get(step_id)

    async def update_step(
        self, step: ProvisionStep, data: dict[str, object]
    ) -> ProvisionStep:
        for key, value in data.items():
            if hasattr(step, key):
                setattr(step, key, value)
        step.version += 1
        return step

    async def list_steps_for_job(self, job_id: uuid.UUID) -> list[ProvisionStep]:
        values = [s for s in self.steps.values() if s.job_id == job_id]
        values.sort(key=lambda s: s.sequence_number)
        return values

    async def create_log(self, **fields: object) -> ProvisionLog:
        log = ProvisionLog(**_base_fields(**fields))
        self.logs[log.id] = log
        return log

    async def list_logs_for_job(self, job_id: uuid.UUID) -> list[ProvisionLog]:
        values = [log_row for log_row in self.logs.values() if log_row.job_id == job_id]
        values.sort(key=lambda log_row: log_row.logged_at)
        return values

    async def create_template(self, **fields: object) -> ProvisionTemplate:
        template = ProvisionTemplate(**_base_fields(**fields))
        self.templates[template.id] = template
        return template

    async def get_template_by_id(
        self, template_id: uuid.UUID
    ) -> ProvisionTemplate | None:
        return self.templates.get(template_id)

    async def update_template(self, template, data):
        for key, value in data.items():
            if hasattr(template, key):
                setattr(template, key, value)
        template.version += 1
        return template

    async def list_templates(self, *, page: int, page_size: int, filters=None):
        values = [t for t in self.templates.values() if not t.is_deleted]
        for key, value in (filters or {}).items():
            values = [t for t in values if getattr(t, key, None) == value]
        values.sort(key=lambda t: t.created_at, reverse=True)
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))


@dataclass
class FakeQueueDispatcher:
    enqueued: list[uuid.UUID] = field(default_factory=list)

    async def enqueue(self, job_id: uuid.UUID) -> None:
        self.enqueued.append(job_id)


@dataclass
class FakeAuditLogWriter:
    entries: list[dict[str, object]] = field(default_factory=list)

    async def create_audit_log_entry(self, **fields: object) -> dict[str, object]:
        self.entries.append(fields)
        return fields


# ============================================================================
# Fakes: composed cross-domain protocols
# ============================================================================


@dataclass
class FakeRouterLookup:
    routers: dict[uuid.UUID, Router] = field(default_factory=dict)
    secrets: dict[uuid.UUID, str | None] = field(default_factory=dict)
    heartbeats: list[uuid.UUID] = field(default_factory=list)

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

    async def heartbeat(
        self,
        *,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None = None,
        routeros_version: str | None = None,
        management_ip_address: str | None = None,
    ) -> Router:
        self.heartbeats.append(router_id)
        return self.routers[router_id]

    def get_decrypted_api_secret(self, router: Router) -> str | None:
        return self.secrets.get(router.id)


@dataclass
class FakeRouterProvisioningLookup:
    templates: dict[uuid.UUID, ConfigTemplate] = field(default_factory=dict)
    versions: dict[uuid.UUID, ConfigVersion] = field(default_factory=dict)
    variables_created: list[dict[str, object]] = field(default_factory=list)
    duplicate_keys: set[str] = field(default_factory=set)
    started_jobs: list[uuid.UUID] = field(default_factory=list)
    completed_jobs: list[tuple[uuid.UUID, bool, str | None]] = field(
        default_factory=list
    )
    health_snapshots_recorded: list[dict[str, object]] = field(default_factory=list)

    def add_template(self, template: ConfigTemplate) -> ConfigTemplate:
        self.templates[template.id] = template
        return template

    def add_version(self, version: ConfigVersion) -> ConfigVersion:
        self.versions[version.id] = version
        return version

    async def get_template(
        self, template_id: uuid.UUID, *, requesting_organization_id=None
    ) -> ConfigTemplate:
        return self.templates[template_id]

    async def resolve_variables(self, router: Router) -> dict[str, str]:
        return {"dns_primary": "1.1.1.1"}

    async def create_variable(self, *, key: str, value: str, **_kw) -> object:
        if key in self.duplicate_keys:
            raise DuplicateConfigVariableError("router", key)
        self.variables_created.append({"key": key, "value": value})
        return object()

    async def assign_profile(
        self, *, router_id: uuid.UUID, template_id: uuid.UUID, **_kw
    ) -> tuple[object, ConfigVersion]:
        version = _make_config_version(
            router_id=router_id, version_number=len(self.versions) + 1
        )
        self.add_version(version)
        return object(), version

    async def apply_version(
        self, *, router_id: uuid.UUID, version_id: uuid.UUID, **_kw
    ):
        version = self.versions[version_id]

        @dataclass
        class _FakeRpJob:
            id: uuid.UUID = field(default_factory=uuid.uuid4)

        return version, _FakeRpJob()

    async def start_provisioning_job(self, job_id: uuid.UUID) -> object:
        self.started_jobs.append(job_id)
        return object()

    async def complete_provisioning_job(
        self, job_id: uuid.UUID, *, success: bool, error_message: str | None = None
    ) -> object:
        self.completed_jobs.append((job_id, success, error_message))
        return object()

    async def list_versions(self, *, router_id: uuid.UUID, **_kw):
        values = [v for v in self.versions.values() if v.router_id == router_id]
        values.sort(key=lambda v: v.version_number, reverse=True)
        return values, PaginationMeta.from_total(PageParams(), len(values))

    async def rollback_to_version(
        self, *, router_id: uuid.UUID, target_version_id: uuid.UUID, **_kw
    ) -> ConfigVersion:
        target = self.versions[target_version_id]
        new_version = _make_config_version(
            router_id=router_id,
            version_number=len(self.versions) + 1,
            rendered_content=target.rendered_content,
        )
        self.add_version(new_version)
        return new_version

    async def record_health_snapshot(self, *, router_id: uuid.UUID, **kwargs):
        self.health_snapshots_recorded.append({"router_id": router_id, **kwargs})

        @dataclass
        class _FakeSnapshot:
            id: uuid.UUID = field(default_factory=uuid.uuid4)

        return object(), _FakeSnapshot()


@dataclass
class FakePolicyLookup:
    async def resolve_effective_policy(
        self, *, policy_type: PolicyType, organization_id, location_id
    ) -> ResolvedPolicy:
        return ResolvedPolicy(
            policy_type=policy_type,
            organization_id=organization_id,
            location_id=location_id,
            rules={"idle_timeout_minutes": 30},
            source="platform_default",
        )


@dataclass
class FakeNasLookup:
    existing_nas_router_ids: set[uuid.UUID] = field(default_factory=set)
    registered: list[uuid.UUID] = field(default_factory=list)

    async def register_nas(self, *, router_id: uuid.UUID, **_kw) -> object:
        self.registered.append(router_id)
        self.existing_nas_router_ids.add(router_id)
        return object()

    async def list_nas_clients(self, *, router_id: uuid.UUID | None = None, **_kw):
        items = ["nas"] if router_id in self.existing_nas_router_ids else []
        return items, PaginationMeta.from_total(PageParams(), len(items))


@dataclass
class FakeDeviceAdapter:
    vendor: str = "mikrotik"
    discover_result: DeviceDiscoveryResult | None = None
    discover_exception: Exception | None = None
    push_exception: Exception | None = None
    verify_result: bool = True
    health_result: DeviceHealthResult | None = None
    push_calls: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.discover_result is None:
            self.discover_result = DeviceDiscoveryResult(
                vendor="mikrotik",
                model="RB4011",
                serial_number="ABC123",
                firmware_version="7.14",
                cpu_load_percent=5.0,
                free_memory_bytes=1000,
                total_memory_bytes=2000,
                uptime_seconds=3600,
                interfaces=["ether1"],
                mac_address="AA:BB:CC:DD:EE:FF",
            )
        if self.health_result is None:
            self.health_result = DeviceHealthResult(
                healthy=True,
                cpu_load_percent=5.0,
                free_memory_bytes=1000,
                uptime_seconds=3600,
            )

    async def discover(self, credentials: DeviceCredentials) -> DeviceDiscoveryResult:
        if self.discover_exception:
            raise self.discover_exception
        return self.discover_result

    async def push_config(
        self, credentials: DeviceCredentials, *, config_content: str
    ) -> None:
        if self.push_exception:
            raise self.push_exception
        self.push_calls.append(config_content)

    async def verify_config(
        self, credentials: DeviceCredentials, *, expected_content: str
    ) -> bool:
        return self.verify_result

    async def health_check(self, credentials: DeviceCredentials) -> DeviceHealthResult:
        return self.health_result

    async def backup(self, credentials: DeviceCredentials) -> bytes:
        return b""

    async def restore(
        self, credentials: DeviceCredentials, *, backup_content: bytes
    ) -> None:
        return None

    async def upload_file(self, credentials, *, filename: str, content: bytes) -> None:
        return None


# ============================================================================
# Service factory
# ============================================================================


@dataclass
class Harness:
    service: ProvisioningEngineService
    repository: FakeProvisioningEngineRepository
    router_lookup: FakeRouterLookup
    router_provisioning: FakeRouterProvisioningLookup
    policy_lookup: FakePolicyLookup
    nas_lookup: FakeNasLookup
    queue_dispatcher: FakeQueueDispatcher
    audit_writer: FakeAuditLogWriter
    device_adapter: FakeDeviceAdapter


def make_harness(*, device_adapter: FakeDeviceAdapter | None = None) -> Harness:
    repository = FakeProvisioningEngineRepository()
    router_lookup = FakeRouterLookup()
    router_provisioning = FakeRouterProvisioningLookup()
    policy_lookup = FakePolicyLookup()
    nas_lookup = FakeNasLookup()
    queue_dispatcher = FakeQueueDispatcher()
    audit_writer = FakeAuditLogWriter()
    adapter = device_adapter or FakeDeviceAdapter()

    service = ProvisioningEngineService(
        repository,
        router_lookup,
        router_provisioning,
        policy_lookup,
        nas_lookup,
        queue_dispatcher=queue_dispatcher,
        audit_writer=audit_writer,
        device_adapter_resolver=lambda vendor: adapter,
    )
    return Harness(
        service=service,
        repository=repository,
        router_lookup=router_lookup,
        router_provisioning=router_provisioning,
        policy_lookup=policy_lookup,
        nas_lookup=nas_lookup,
        queue_dispatcher=queue_dispatcher,
        audit_writer=audit_writer,
        device_adapter=adapter,
    )


# ============================================================================
# create_job
# ============================================================================


class TestCreateJob:
    async def test_creates_job_with_denormalized_fields_and_policy_snapshot(
        self,
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())

        job = await h.service.create_job(
            actor_user_id=uuid.uuid4(),
            router_id=router.id,
            requesting_organization_id=router.organization_id,
        )

        assert job.organization_id == router.organization_id
        assert job.location_id == router.location_id
        assert job.router_id == router.id
        assert job.status == ProvisionJobStatus.PENDING.value
        assert job.policy_snapshot["rules"] == {"idle_timeout_minutes": 30}
        assert job.retry_count == 1
        assert job.is_rollback is False
        assert len(h.audit_writer.entries) == 1

    async def test_unknown_provision_template_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        with pytest.raises(ProvisionTemplateNotFoundError):
            await h.service.create_job(
                actor_user_id=uuid.uuid4(),
                router_id=router.id,
                requesting_organization_id=router.organization_id,
                provision_template_id=uuid.uuid4(),
            )

    async def test_unknown_router_raises(self) -> None:
        h = make_harness()
        with pytest.raises(RouterNotFoundError):
            await h.service.create_job(
                actor_user_id=uuid.uuid4(),
                router_id=uuid.uuid4(),
                requesting_organization_id=None,
            )


# ============================================================================
# start_job / cancel_job
# ============================================================================


class TestStartJob:
    async def test_transitions_pending_to_queued_and_enqueues(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        job = await h.service.create_job(
            actor_user_id=uuid.uuid4(),
            router_id=router.id,
            requesting_organization_id=router.organization_id,
        )
        started = await h.service.start_job(
            job_id=job.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
        )
        assert started.status == ProvisionJobStatus.QUEUED.value
        assert h.queue_dispatcher.enqueued == [job.id]

    async def test_starting_an_already_queued_job_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        job = await h.service.create_job(
            actor_user_id=uuid.uuid4(),
            router_id=router.id,
            requesting_organization_id=router.organization_id,
        )
        await h.service.start_job(
            job_id=job.id, actor_user_id=None, requesting_organization_id=None
        )
        with pytest.raises(InvalidProvisionJobStatusTransitionError):
            await h.service.start_job(
                job_id=job.id, actor_user_id=None, requesting_organization_id=None
            )

    async def test_cross_organization_start_raises_not_found(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        job = await h.service.create_job(
            actor_user_id=uuid.uuid4(),
            router_id=router.id,
            requesting_organization_id=router.organization_id,
        )
        with pytest.raises(ProvisionJobNotFoundError):
            await h.service.start_job(
                job_id=job.id,
                actor_user_id=None,
                requesting_organization_id=uuid.uuid4(),
            )


class TestCancelJob:
    async def test_cancels_pending_job(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        job = await h.service.create_job(
            actor_user_id=uuid.uuid4(),
            router_id=router.id,
            requesting_organization_id=router.organization_id,
        )
        cancelled = await h.service.cancel_job(
            job_id=job.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
            reason="changed my mind",
        )
        assert cancelled.status == ProvisionJobStatus.CANCELLED.value
        assert cancelled.error_message == "changed my mind"

    async def test_cancelling_a_running_job_marks_pending_steps_skipped(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        job = await h.service.create_job(
            actor_user_id=uuid.uuid4(),
            router_id=router.id,
            requesting_organization_id=router.organization_id,
        )
        await h.repository.update_job(job, {"status": ProvisionJobStatus.RUNNING.value})
        step = await h.repository.create_step(
            job_id=job.id,
            step_type=ProvisionStepType.DISCOVER.value,
            sequence_number=1,
            status=ProvisionStepStatus.PENDING.value,
            started_at=None,
            completed_at=None,
            output={},
            error_message=None,
        )
        await h.service.cancel_job(
            job_id=job.id, actor_user_id=None, requesting_organization_id=None
        )
        assert h.repository.steps[step.id].status == ProvisionStepStatus.SKIPPED.value

    async def test_cancelling_a_terminal_job_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        job = await h.service.create_job(
            actor_user_id=uuid.uuid4(),
            router_id=router.id,
            requesting_organization_id=router.organization_id,
        )
        await h.repository.update_job(job, {"status": ProvisionJobStatus.FAILED.value})
        with pytest.raises(InvalidProvisionJobStatusTransitionError):
            await h.service.cancel_job(
                job_id=job.id, actor_user_id=None, requesting_organization_id=None
            )


# ============================================================================
# retry_job / rollback_job
# ============================================================================


class TestRetryJob:
    async def test_retry_creates_new_job_with_lineage_and_starts_it(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        job = await h.service.create_job(
            actor_user_id=uuid.uuid4(),
            router_id=router.id,
            requesting_organization_id=router.organization_id,
        )
        await h.repository.update_job(
            job, {"status": ProvisionJobStatus.FAILED.value, "error_message": "boom"}
        )

        retried = await h.service.retry_job(
            job_id=job.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
        )

        assert retried.id != job.id
        assert retried.retry_of_job_id == job.id
        assert retried.retry_count == 2
        assert retried.status == ProvisionJobStatus.QUEUED.value
        assert job.status == ProvisionJobStatus.FAILED.value  # original untouched

    async def test_retrying_a_non_failed_job_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        job = await h.service.create_job(
            actor_user_id=uuid.uuid4(),
            router_id=router.id,
            requesting_organization_id=router.organization_id,
        )
        with pytest.raises(ProvisionJobNotRetryableError):
            await h.service.retry_job(
                job_id=job.id, actor_user_id=None, requesting_organization_id=None
            )

    async def test_retry_limit_exceeded_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        job = await h.service.create_job(
            actor_user_id=uuid.uuid4(),
            router_id=router.id,
            requesting_organization_id=router.organization_id,
            max_retries=1,
        )
        await h.repository.update_job(
            job, {"status": ProvisionJobStatus.FAILED.value, "retry_count": 1}
        )
        with pytest.raises(ProvisionJobRetryLimitExceededError):
            await h.service.retry_job(
                job_id=job.id, actor_user_id=None, requesting_organization_id=None
            )


class TestRollbackJob:
    async def test_rollback_creates_new_job_targeting_prior_version(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        version_1 = h.router_provisioning.add_version(
            _make_config_version(router_id=router.id, version_number=1)
        )
        version_2 = h.router_provisioning.add_version(
            _make_config_version(router_id=router.id, version_number=2)
        )
        job = await h.service.create_job(
            actor_user_id=uuid.uuid4(),
            router_id=router.id,
            requesting_organization_id=router.organization_id,
        )
        await h.repository.update_job(
            job,
            {
                "status": ProvisionJobStatus.SUCCESS.value,
                "applied_config_version_id": version_2.id,
            },
        )

        rollback = await h.service.rollback_job(
            job_id=job.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
        )

        assert rollback.is_rollback is True
        assert rollback.rollback_of_job_id == job.id
        assert rollback.rollback_target_version_id == version_1.id
        assert rollback.status == ProvisionJobStatus.QUEUED.value

    async def test_rollback_of_non_success_job_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        job = await h.service.create_job(
            actor_user_id=uuid.uuid4(),
            router_id=router.id,
            requesting_organization_id=router.organization_id,
        )
        with pytest.raises(ProvisionJobNotRollbackableError):
            await h.service.rollback_job(
                job_id=job.id, actor_user_id=None, requesting_organization_id=None
            )

    async def test_rollback_without_applied_version_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        job = await h.service.create_job(
            actor_user_id=uuid.uuid4(),
            router_id=router.id,
            requesting_organization_id=router.organization_id,
        )
        await h.repository.update_job(job, {"status": ProvisionJobStatus.SUCCESS.value})
        with pytest.raises(ProvisionJobHasNoAppliedVersionError):
            await h.service.rollback_job(
                job_id=job.id, actor_user_id=None, requesting_organization_id=None
            )

    async def test_rollback_with_no_prior_version_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        version_1 = h.router_provisioning.add_version(
            _make_config_version(router_id=router.id, version_number=1)
        )
        job = await h.service.create_job(
            actor_user_id=uuid.uuid4(),
            router_id=router.id,
            requesting_organization_id=router.organization_id,
        )
        await h.repository.update_job(
            job,
            {
                "status": ProvisionJobStatus.SUCCESS.value,
                "applied_config_version_id": version_1.id,
            },
        )
        with pytest.raises(ProvisionNoPriorVersionToRollBackToError):
            await h.service.rollback_job(
                job_id=job.id, actor_user_id=None, requesting_organization_id=None
            )


# ============================================================================
# Reads: get_job / list_jobs / get_history / get_timeline
# ============================================================================


class TestReads:
    async def test_list_jobs_filters_by_router_and_status(self) -> None:
        h = make_harness()
        router_a = h.router_lookup.add(_make_router())
        router_b = h.router_lookup.add(_make_router())
        job_a = await h.service.create_job(
            actor_user_id=None, router_id=router_a.id, requesting_organization_id=None
        )
        await h.service.create_job(
            actor_user_id=None, router_id=router_b.id, requesting_organization_id=None
        )

        jobs, _meta = await h.service.list_jobs(
            requesting_organization_id=None, router_id=router_a.id
        )
        assert [j.id for j in jobs] == [job_a.id]

    async def test_get_history_is_scoped_to_one_router(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        job_1 = await h.service.create_job(
            actor_user_id=None, router_id=router.id, requesting_organization_id=None
        )
        jobs, _meta = await h.service.get_history(
            router_id=router.id, requesting_organization_id=None
        )
        assert [j.id for j in jobs] == [job_1.id]

    async def test_get_timeline_aggregates_steps_and_logs_chronologically(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        job = await h.service.create_job(
            actor_user_id=None, router_id=router.id, requesting_organization_id=None
        )
        step = await h.repository.create_step(
            job_id=job.id,
            step_type=ProvisionStepType.DISCOVER.value,
            sequence_number=1,
            status=ProvisionStepStatus.SUCCEEDED.value,
            started_at=_now(),
            completed_at=_now(),
            output={},
            error_message=None,
        )
        await h.repository.create_log(
            job_id=job.id,
            step_id=step.id,
            level=ProvisionLogLevel.INFO.value,
            message="discover started",
            logged_at=_now(),
        )
        entries = await h.service.get_timeline(job.id, requesting_organization_id=None)
        assert len(entries) == 3  # step-started, step-completed, log line
        assert entries == sorted(entries, key=lambda e: e.occurred_at)


# ============================================================================
# Ad-hoc actions
# ============================================================================


class TestDiscoverDevice:
    async def test_discovers_and_heartbeats(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        result = await h.service.discover_device(
            router_id=router.id, requesting_organization_id=router.organization_id
        )
        assert result.model == "RB4011"
        assert h.router_lookup.heartbeats == [router.id]

    async def test_missing_credentials_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router(), secret=None)
        with pytest.raises(ProvisionMissingCredentialsError):
            await h.service.discover_device(
                router_id=router.id, requesting_organization_id=None
            )


class TestValidateDevice:
    async def test_valid_router_passes(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        await h.service.validate_device(
            router_id=router.id, requesting_organization_id=None
        )  # no raise

    async def test_unsupported_vendor_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        router.vendor = "opnsense"

        def _no_adapter_for(vendor: str):
            raise UnsupportedDeviceVendorError(vendor)

        h.service._get_device_adapter = _no_adapter_for
        with pytest.raises(UnsupportedDeviceVendorError):
            await h.service.validate_device(
                router_id=router.id, requesting_organization_id=None
            )


class TestGenerateConfiguration:
    async def test_seeds_variables_registers_nas_and_renders(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        config_template = h.router_provisioning.add_template(_make_config_template())
        provision_template = await h.repository.create_template(
            organization_id=None,
            name="Hotel Package",
            site_type="hotel",
            description=None,
            config_template_id=config_template.id,
            default_policy_id=None,
            settings={"ntp": {"primary": "pool.ntp.org"}},
            is_active=True,
        )

        preview = await h.service.generate_configuration(
            router_id=router.id,
            requesting_organization_id=None,
            provision_template_id=provision_template.id,
            actor_user_id=uuid.uuid4(),
        )

        assert preview.variables_used == {"dns_primary": "1.1.1.1"}
        assert {"key": "ntp_primary", "value": "pool.ntp.org"} in (
            h.router_provisioning.variables_created
        )
        assert router.id in h.nas_lookup.registered
        assert "1.1.1.1" in preview.rendered_content

    async def test_tolerates_duplicate_variable(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        config_template = h.router_provisioning.add_template(_make_config_template())
        provision_template = await h.repository.create_template(
            organization_id=None,
            name="Hotel Package",
            site_type="hotel",
            description=None,
            config_template_id=config_template.id,
            default_policy_id=None,
            settings={"ntp_primary": "pool.ntp.org"},
            is_active=True,
        )
        h.router_provisioning.duplicate_keys.add("ntp_primary")

        await h.service.generate_configuration(
            router_id=router.id,
            requesting_organization_id=None,
            provision_template_id=provision_template.id,
        )  # no raise despite the duplicate

    async def test_existing_nas_is_not_re_registered(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        h.nas_lookup.existing_nas_router_ids.add(router.id)
        config_template = h.router_provisioning.add_template(_make_config_template())
        provision_template = await h.repository.create_template(
            organization_id=None,
            name="Hotel Package",
            site_type="hotel",
            description=None,
            config_template_id=config_template.id,
            default_policy_id=None,
            settings={},
            is_active=True,
        )
        await h.service.generate_configuration(
            router_id=router.id,
            requesting_organization_id=None,
            provision_template_id=provision_template.id,
        )
        assert h.nas_lookup.registered == []


# ============================================================================
# run_provision_job: the full step-sequence orchestrator
# ============================================================================


class TestRunProvisionJob:
    async def _create_and_queue_job(
        self, h: Harness, *, is_rollback: bool = False, with_template: bool = True
    ) -> tuple[ProvisionJob, Router]:
        router = h.router_lookup.add(_make_router())
        provision_template_id = None
        if with_template:
            config_template = h.router_provisioning.add_template(
                _make_config_template()
            )
            provision_template = await h.repository.create_template(
                organization_id=None,
                name="Hotel Package",
                site_type="hotel",
                description=None,
                config_template_id=config_template.id,
                default_policy_id=None,
                settings={},
                is_active=True,
            )
            provision_template_id = provision_template.id
        job = await h.service.create_job(
            actor_user_id=uuid.uuid4(),
            router_id=router.id,
            requesting_organization_id=router.organization_id,
            provision_template_id=provision_template_id,
        )
        if is_rollback:
            version_1 = h.router_provisioning.add_version(
                _make_config_version(router_id=router.id, version_number=1)
            )
            await h.repository.update_job(
                job,
                {
                    "is_rollback": True,
                    "rollback_target_version_id": version_1.id,
                },
            )
        return job, router

    async def test_full_success_path_runs_every_step(self) -> None:
        h = make_harness()
        job, router = await self._create_and_queue_job(h)

        completed = await h.service.run_provision_job(job.id)

        assert completed.status == ProvisionJobStatus.SUCCESS.value
        assert completed.progress_percent == 100
        assert completed.applied_config_version_id is not None
        steps = await h.repository.list_steps_for_job(job.id)
        assert [s.step_type for s in steps] == [
            ProvisionStepType.DISCOVER.value,
            ProvisionStepType.VALIDATE.value,
            ProvisionStepType.GENERATE_CONFIG.value,
            ProvisionStepType.PUSH_CONFIG.value,
            ProvisionStepType.VERIFY_CONFIG.value,
            ProvisionStepType.HEALTH_CHECK.value,
            ProvisionStepType.REGISTER_MONITORING.value,
        ]
        assert all(s.status == ProvisionStepStatus.SUCCEEDED.value for s in steps)
        assert len(h.router_provisioning.health_snapshots_recorded) == 1

    async def test_device_push_failure_halts_job_as_failed(self) -> None:
        adapter = FakeDeviceAdapter(
            push_exception=ProvisionDeviceConnectionError("10.0.0.1", "refused")
        )
        h = make_harness(device_adapter=adapter)
        job, router = await self._create_and_queue_job(h)

        failed = await h.service.run_provision_job(job.id)

        assert failed.status == ProvisionJobStatus.FAILED.value
        assert failed.error_message is not None
        steps = await h.repository.list_steps_for_job(job.id)
        step_types = [s.step_type for s in steps]
        # PUSH_CONFIG failed -- VERIFY_CONFIG/HEALTH_CHECK/REGISTER_MONITORING
        # must never have been attempted.
        assert ProvisionStepType.PUSH_CONFIG.value in step_types
        assert ProvisionStepType.VERIFY_CONFIG.value not in step_types
        assert ProvisionStepType.HEALTH_CHECK.value not in step_types
        assert len(h.router_provisioning.completed_jobs) == 1
        assert h.router_provisioning.completed_jobs[0][1] is False

    async def test_rollback_job_skips_generate_config_step(self) -> None:
        h = make_harness()
        job, router = await self._create_and_queue_job(
            h, is_rollback=True, with_template=False
        )

        completed = await h.service.run_provision_job(job.id)

        assert completed.status == ProvisionJobStatus.SUCCESS.value
        steps = await h.repository.list_steps_for_job(job.id)
        generate_step = next(
            s for s in steps if s.step_type == ProvisionStepType.GENERATE_CONFIG.value
        )
        assert generate_step.output == {
            "skipped": "rollback jobs reuse an existing prior version"
        }
        assert h.router_provisioning.variables_created == []

    async def test_no_template_job_re_pushes_existing_latest_version(self) -> None:
        h = make_harness()
        job, router = await self._create_and_queue_job(h, with_template=False)
        h.router_provisioning.add_version(
            _make_config_version(router_id=router.id, version_number=1)
        )

        completed = await h.service.run_provision_job(job.id)

        assert completed.status == ProvisionJobStatus.SUCCESS.value
        steps = await h.repository.list_steps_for_job(job.id)
        generate_step = next(
            s for s in steps if s.step_type == ProvisionStepType.GENERATE_CONFIG.value
        )
        assert generate_step.output == {
            "skipped": "no provision_template_id set on this job"
        }

    async def test_no_template_and_no_existing_version_fails_push_config(self) -> None:
        h = make_harness()
        job, router = await self._create_and_queue_job(h, with_template=False)

        failed = await h.service.run_provision_job(job.id)

        assert failed.status == ProvisionJobStatus.FAILED.value
        steps = await h.repository.list_steps_for_job(job.id)
        push_step = next(
            s for s in steps if s.step_type == ProvisionStepType.PUSH_CONFIG.value
        )
        assert push_step.status == ProvisionStepStatus.FAILED.value


# ============================================================================
# RBAC -- every route requires a permission dependency
# ============================================================================


class TestEveryRouteRequiresPermission:
    def test_every_provisioning_engine_route_has_a_permission_dependency(self) -> None:
        assert len(provisioning_engine_router.routes) == 12
        for route in provisioning_engine_router.routes:
            assert (
                route.dependencies != []
            ), f"{route.path} ({route.methods}) has no permission dependency"


# ============================================================================
# Repository / queue dispatcher sanity
# ============================================================================


class TestRedisProvisionEngineQueueDispatcher:
    async def test_enqueue_lpushes_job_id(self) -> None:
        class FakeRedis:
            def __init__(self) -> None:
                self.calls: list[tuple[str, str]] = []

            async def lpush(self, key: str, value: str) -> None:
                self.calls.append((key, value))

        redis = FakeRedis()
        dispatcher = RedisProvisionEngineQueueDispatcher(redis)
        job_id = uuid.uuid4()
        await dispatcher.enqueue(job_id)
        assert redis.calls == [("cloudguest:provisioning_engine:queue", str(job_id))]


class TestProvisioningEngineRepositoryConstruction:
    def test_wires_four_generic_repositories(self) -> None:
        repository = ProvisioningEngineRepository(session=None)
        assert repository.jobs is not None
        assert repository.steps is not None
        assert repository.logs is not None
        assert repository.templates is not None
