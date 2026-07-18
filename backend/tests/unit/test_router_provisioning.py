"""Unit tests for the Router Provisioning domain: config template/variable
CRUD and resolution-order merging, config version create/diff/rollback/
apply state transitions, device-initiated enrollment submit/approve/reject
(including the serial/MAC collision race check), provisioning queue job
lifecycle, backup/restore, factory reset, router secret rotation (verifying
reuse of BE-008's existing Fernet crypto helpers, not a second encryption
mechanism), and tenant isolation.

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_router.py``); ``asyncio_mode = "auto"`` runs async tests
directly. ``RouterProvisioningService`` is exercised against a real
``RouterService`` instance (itself wired against small in-memory fakes,
exactly mirroring ``test_router.py``'s own ``make_service`` setup) rather
than a hand-rolled fake for BE-008's router lookups -- this both avoids
duplicating ``RouterService``'s own business logic in a second fake and
directly exercises the real cross-domain composition
(``RouterProvisioningService`` -> ``RouterService`` -> ``LocationService``/
``OrganizationService``) this module relies on, including the additive
``RouterService.reset_to_pending_provisioning`` method and the two new
``ROUTER_STATUS_TRANSITIONS`` edges this module contributed to BE-008.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.location.exceptions import (
    CrossOrganizationLocationAccessError,
    LocationNotFoundError,
)
from app.domains.location.models import Location
from app.domains.organization.enums import OrganizationType
from app.domains.organization.exceptions import OrganizationNotFoundError
from app.domains.organization.models import Organization
from app.domains.router.crypto import decrypt_secret
from app.domains.router.enums import RouterStatus
from app.domains.router.exceptions import (
    CrossOrganizationRouterAccessError,
    RouterDecommissionedError,
)
from app.domains.router.models import Router, RouterProvisioningToken
from app.domains.router.service import RouterService
from app.domains.router_provisioning.constants import (
    ConfigVariableScope,
    ConfigVersionStatus,
    ProvisioningJobStatus,
    ProvisioningJobType,
)
from app.domains.router_provisioning.exceptions import (
    BackupVersionExpectedError,
    ConfigTemplateNotFoundError,
    ConfigVersionRouterMismatchError,
    CrossOrganizationTemplateAccessError,
    CrossOrganizationVariableAccessError,
    DuplicateConfigVariableError,
    DuplicatePendingEnrollmentError,
    InvalidConfigVariableScopeError,
    InvalidConfigVersionStatusTransitionError,
    InvalidProvisioningJobStatusTransitionError,
    NoAppliedConfigToBackupError,
    ProvisioningJobRouterMismatchError,
    RouterAlreadyRegisteredError,
    RouterEnrollmentNotPendingError,
    RouterNotEligibleForConfigError,
    RouterNotEligibleForFactoryResetError,
    UnresolvedTemplateVariablesError,
)
from app.domains.router_provisioning.models import (
    ConfigProfile,
    ConfigTemplate,
    ConfigVariable,
    ConfigVersion,
    ProvisioningJob,
    RouterEnrollmentRequest,
    RouterEvent,
    RouterHealthSnapshot,
)
from app.domains.router_provisioning.service import (
    RouterProvisioningService,
    render_template,
)
from app.domains.router_provisioning.validators import validate_job_belongs_to_router

# ============================================================================
# Test doubles: BE-008 (Router domain) side -- mirrors test_router.py exactly
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


@dataclass
class FakeAuditLogWriter:
    entries: list[dict[str, object]] = field(default_factory=list)

    async def create_audit_log_entry(self, **fields: object) -> dict[str, object]:
        self.entries.append(fields)
        return fields


@dataclass
class FakeOrganizationLookup:
    organizations: dict[uuid.UUID, Organization] = field(default_factory=dict)

    async def get_organization(
        self, organization_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Organization:
        organization = self.organizations.get(organization_id)
        if organization is None or (organization.is_deleted and not include_deleted):
            raise OrganizationNotFoundError(organization_id)
        return organization

    def add(
        self,
        *,
        org_type: str = OrganizationType.STANDARD.value,
        parent_organization_id: uuid.UUID | None = None,
    ) -> Organization:
        organization = Organization(
            **_base_fields(
                name="Org",
                slug=f"org-{uuid.uuid4()}",
                legal_name=None,
                org_type=org_type,
                status="active",
                parent_organization_id=parent_organization_id,
                contact_email="admin@example.com",
                contact_phone=None,
                timezone="UTC",
                default_locale="en",
                settings={},
                subscription_tier=None,
            )
        )
        self.organizations[organization.id] = organization
        return organization


@dataclass
class FakeLocationLookup:
    organization_lookup: FakeOrganizationLookup
    locations: dict[uuid.UUID, Location] = field(default_factory=dict)

    async def get_location(
        self,
        location_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Location:
        location = self.locations.get(location_id)
        if location is None or (location.is_deleted and not include_deleted):
            raise LocationNotFoundError(location_id)
        await self._enforce_scope(location, requesting_organization_id)
        return location

    async def _enforce_scope(
        self, location: Location, requesting_organization_id: uuid.UUID | None
    ) -> None:
        if requesting_organization_id is None:
            return
        if location.organization_id == requesting_organization_id:
            return
        organization = await self.organization_lookup.get_organization(
            location.organization_id, include_deleted=True
        )
        if organization.parent_organization_id == requesting_organization_id:
            return
        raise CrossOrganizationLocationAccessError()

    def add(self, *, organization_id: uuid.UUID, status: str = "active") -> Location:
        location = Location(
            **_base_fields(
                organization_id=organization_id,
                name="HQ",
                slug=f"hq-{uuid.uuid4()}",
                status=status,
                address_line1="1 Main St",
                address_line2=None,
                city="Austin",
                state_province="TX",
                postal_code="78701",
                country="US",
                timezone="UTC",
                latitude=None,
                longitude=None,
                contact_name=None,
                contact_phone=None,
                contact_email=None,
                settings={},
            )
        )
        self.locations[location.id] = location
        return location


@dataclass
class FakeRouterRepository:
    routers: dict[uuid.UUID, Router] = field(default_factory=dict)
    tokens: dict[uuid.UUID, RouterProvisioningToken] = field(default_factory=dict)

    async def get_by_id(
        self, router_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Router | None:
        router = self.routers.get(router_id)
        if router is None:
            return None
        if router.is_deleted and not include_deleted:
            return None
        return router

    async def get_by_serial_number(self, serial_number: str) -> Router | None:
        return next(
            (
                r
                for r in self.routers.values()
                if r.serial_number == serial_number and not r.is_deleted
            ),
            None,
        )

    async def get_by_mac_address(self, mac_address: str) -> Router | None:
        return next(
            (
                r
                for r in self.routers.values()
                if r.mac_address == mac_address and not r.is_deleted
            ),
            None,
        )

    async def create_router(self, **fields: object) -> Router:
        defaults = {
            "routeros_version": None,
            "management_ip_address": None,
            "public_ip_address": None,
            "last_seen_at": None,
            "last_health_check_at": None,
            "health_status": None,
            "api_username": None,
            "api_credentials_encrypted": None,
            "settings": {},
        }
        router = Router(**_base_fields(**{**defaults, **fields}))
        self.routers[router.id] = router
        return router

    async def update_router(self, router: Router, data: dict[str, object]) -> Router:
        for key, value in data.items():
            if hasattr(router, key):
                setattr(router, key, value)
        router.version += 1
        return router

    async def soft_delete_router(self, router: Router) -> Router:
        router.is_deleted = True
        router.deleted_at = _now()
        return router

    async def list_routers(self, **_kwargs: object):  # pragma: no cover - unused here
        raise NotImplementedError

    async def create_provisioning_token(
        self, **fields: object
    ) -> RouterProvisioningToken:
        token = RouterProvisioningToken(**_base_fields(**fields))
        self.tokens[token.id] = token
        return token

    async def get_provisioning_token_by_hash(self, token_hash: str):
        return next(
            (t for t in self.tokens.values() if t.token_hash == token_hash), None
        )

    async def mark_provisioning_token_used(self, token, *, used_at: object):
        token.used_at = used_at
        return token


# ============================================================================
# Test doubles: Router Provisioning (this module) side
# ============================================================================


@dataclass
class FakeQueueDispatcher:
    enqueued: list[uuid.UUID] = field(default_factory=list)

    async def enqueue(self, job_id: uuid.UUID) -> None:
        self.enqueued.append(job_id)


@dataclass
class FakeRouterProvisioningRepository:
    templates: dict[uuid.UUID, ConfigTemplate] = field(default_factory=dict)
    variables: dict[uuid.UUID, ConfigVariable] = field(default_factory=dict)
    profiles: dict[uuid.UUID, ConfigProfile] = field(default_factory=dict)
    versions: dict[uuid.UUID, ConfigVersion] = field(default_factory=dict)
    enrollments: dict[uuid.UUID, RouterEnrollmentRequest] = field(default_factory=dict)
    jobs: dict[uuid.UUID, ProvisioningJob] = field(default_factory=dict)
    health_snapshots: dict[uuid.UUID, RouterHealthSnapshot] = field(
        default_factory=dict
    )
    events: dict[uuid.UUID, RouterEvent] = field(default_factory=dict)

    # -- templates -----------------------------------------------------------
    async def get_template(self, template_id, *, include_deleted: bool = False):
        template = self.templates.get(template_id)
        if template is None or (template.is_deleted and not include_deleted):
            return None
        return template

    async def create_template(self, **fields: object) -> ConfigTemplate:
        template = ConfigTemplate(**_base_fields(**fields))
        self.templates[template.id] = template
        return template

    async def update_template(self, template, data):
        for key, value in data.items():
            if hasattr(template, key):
                setattr(template, key, value)
        template.version += 1
        return template

    async def soft_delete_template(self, template):
        template.is_deleted = True
        template.deleted_at = _now()
        return template

    async def list_templates(self, *, requesting_organization_id, page, page_size):
        values = [t for t in self.templates.values() if not t.is_deleted]
        if requesting_organization_id is not None:
            values = [
                t
                for t in values
                if t.organization_id == requesting_organization_id
                or t.organization_id is None
            ]
        values.sort(key=lambda t: t.created_at, reverse=True)
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))

    # -- variables -------------------------------------------------------------
    async def get_variable(self, variable_id):
        return self.variables.get(variable_id)

    async def find_variable(
        self, *, scope_type, organization_id, location_id, router_id, key
    ):
        for v in self.variables.values():
            if v.is_deleted:
                continue
            if (
                v.scope_type == scope_type
                and v.organization_id == organization_id
                and v.location_id == location_id
                and v.router_id == router_id
                and v.key == key
            ):
                return v
        return None

    async def create_variable(self, **fields: object) -> ConfigVariable:
        variable = ConfigVariable(**_base_fields(**fields))
        self.variables[variable.id] = variable
        return variable

    async def update_variable(self, variable, data):
        for key, value in data.items():
            if hasattr(variable, key):
                setattr(variable, key, value)
        variable.version += 1
        return variable

    async def soft_delete_variable(self, variable):
        variable.is_deleted = True
        variable.deleted_at = _now()
        return variable

    async def list_global_variables(self):
        return [
            v
            for v in self.variables.values()
            if not v.is_deleted
            and v.scope_type == "organization"
            and v.organization_id is None
        ]

    async def list_organization_variables(self, organization_id):
        return [
            v
            for v in self.variables.values()
            if not v.is_deleted
            and v.scope_type == "organization"
            and v.organization_id == organization_id
        ]

    async def list_location_variables(self, location_id):
        return [
            v
            for v in self.variables.values()
            if not v.is_deleted
            and v.scope_type == "location"
            and v.location_id == location_id
        ]

    async def list_router_variables(self, router_id):
        return [
            v
            for v in self.variables.values()
            if not v.is_deleted
            and v.scope_type == "router"
            and v.router_id == router_id
        ]

    async def list_variables(self, *, scope_type, page, page_size):
        values = [v for v in self.variables.values() if not v.is_deleted]
        if scope_type:
            values = [v for v in values if v.scope_type == scope_type]
        values.sort(key=lambda v: v.created_at, reverse=True)
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))

    # -- profiles --------------------------------------------------------------
    async def get_profile(self, profile_id):
        return self.profiles.get(profile_id)

    async def get_profile_for_router(self, router_id):
        return next(
            (
                p
                for p in self.profiles.values()
                if p.router_id == router_id and not p.is_deleted
            ),
            None,
        )

    async def create_profile(self, **fields: object) -> ConfigProfile:
        profile = ConfigProfile(**_base_fields(**fields))
        self.profiles[profile.id] = profile
        return profile

    async def update_profile(self, profile, data):
        for key, value in data.items():
            if hasattr(profile, key):
                setattr(profile, key, value)
        profile.version += 1
        return profile

    # -- versions --------------------------------------------------------------
    async def get_version(self, version_id):
        return self.versions.get(version_id)

    async def create_version(self, **fields: object) -> ConfigVersion:
        version = ConfigVersion(**_base_fields(**fields))
        self.versions[version.id] = version
        return version

    async def update_version(self, version, data):
        for key, value in data.items():
            if hasattr(version, key):
                setattr(version, key, value)
        version.version += 1
        return version

    async def get_next_version_number(self, router_id) -> int:
        existing = [
            v.version_number for v in self.versions.values() if v.router_id == router_id
        ]
        return (max(existing) if existing else 0) + 1

    async def get_latest_applied_version(self, router_id, *, exclude_version_id=None):
        candidates = [
            v
            for v in self.versions.values()
            if v.router_id == router_id
            and not v.is_deleted
            and not v.is_backup
            and v.status == "applied"
            and (exclude_version_id is None or v.id != exclude_version_id)
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda v: v.version_number)

    async def get_latest_version_for_router(self, router_id):
        candidates = [
            v
            for v in self.versions.values()
            if v.router_id == router_id and not v.is_deleted
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda v: v.version_number)

    async def list_versions_for_router(self, router_id, *, page, page_size):
        values = [
            v
            for v in self.versions.values()
            if v.router_id == router_id and not v.is_deleted
        ]
        values.sort(key=lambda v: v.version_number, reverse=True)
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))

    # -- enrollment --------------------------------------------------------------
    async def get_enrollment(self, enrollment_id):
        return self.enrollments.get(enrollment_id)

    async def create_enrollment(self, **fields: object) -> RouterEnrollmentRequest:
        enrollment = RouterEnrollmentRequest(**_base_fields(**fields))
        self.enrollments[enrollment.id] = enrollment
        return enrollment

    async def update_enrollment(self, enrollment, data):
        for key, value in data.items():
            if hasattr(enrollment, key):
                setattr(enrollment, key, value)
        enrollment.version += 1
        return enrollment

    async def find_pending_enrollment(self, *, serial_number, mac_address):
        for e in self.enrollments.values():
            if e.is_deleted or e.status != "pending":
                continue
            if e.serial_number == serial_number or e.mac_address == mac_address:
                return e
        return None

    async def list_pending_enrollments(self, *, page, page_size):
        values = [
            e
            for e in self.enrollments.values()
            if not e.is_deleted and e.status == "pending"
        ]
        values.sort(key=lambda e: e.requested_at)
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))

    # -- provisioning jobs -------------------------------------------------------
    async def get_job(self, job_id):
        return self.jobs.get(job_id)

    async def create_job(self, **fields: object) -> ProvisioningJob:
        job = ProvisioningJob(**_base_fields(**fields))
        self.jobs[job.id] = job
        return job

    async def update_job(self, job, data):
        for key, value in data.items():
            if hasattr(job, key):
                setattr(job, key, value)
        job.version += 1
        return job

    async def list_jobs_for_router(self, router_id, *, page, page_size):
        values = [
            j
            for j in self.jobs.values()
            if j.router_id == router_id and not j.is_deleted
        ]
        values.sort(key=lambda j: j.scheduled_at, reverse=True)
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))

    async def list_active_jobs_for_router(self, router_id):
        return [
            j
            for j in self.jobs.values()
            if j.router_id == router_id
            and not j.is_deleted
            and j.status in ("queued", "running")
        ]

    # -- health / events ---------------------------------------------------------
    async def create_health_snapshot(self, **fields: object) -> RouterHealthSnapshot:
        snapshot = RouterHealthSnapshot(**_base_fields(**fields))
        self.health_snapshots[snapshot.id] = snapshot
        return snapshot

    async def list_health_snapshots_for_router(self, router_id, *, page, page_size):
        values = [
            s
            for s in self.health_snapshots.values()
            if s.router_id == router_id and not s.is_deleted
        ]
        values.sort(key=lambda s: s.recorded_at, reverse=True)
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))

    async def create_event(self, **fields: object) -> RouterEvent:
        event = RouterEvent(**_base_fields(**fields))
        self.events[event.id] = event
        return event

    async def list_events_for_router(self, router_id, *, page, page_size):
        values = [
            e
            for e in self.events.values()
            if e.router_id == router_id and not e.is_deleted
        ]
        values.sort(key=lambda e: e.occurred_at, reverse=True)
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))


# ============================================================================
# Fixture assembly
# ============================================================================


def make_services():
    """Builds a real ``RouterService`` (wired against small in-memory fakes,
    mirroring ``test_router.py``'s own ``make_service``) plus a
    ``RouterProvisioningService`` composed against it -- the same
    composition wiring ``app.domains.router_provisioning.dependencies``
    uses in production."""
    org_lookup = FakeOrganizationLookup()
    location_lookup = FakeLocationLookup(organization_lookup=org_lookup)
    router_repo = FakeRouterRepository()
    shared_audit = FakeAuditLogWriter()

    router_service = RouterService(
        router_repo,
        location_lookup,
        org_lookup,
        audit_writer=shared_audit,
        provisioning_token_ttl_hours=24,
    )

    provisioning_repo = FakeRouterProvisioningRepository()
    queue_dispatcher = FakeQueueDispatcher()
    provisioning_service = RouterProvisioningService(
        provisioning_repo,
        router_service,
        location_lookup,
        queue_dispatcher=queue_dispatcher,
        audit_writer=shared_audit,
    )
    return (
        provisioning_service,
        provisioning_repo,
        router_service,
        router_repo,
        location_lookup,
        org_lookup,
        queue_dispatcher,
        shared_audit,
    )


def _unique_mac() -> str:
    hex_digits = uuid.uuid4().hex[:12]
    return ":".join(hex_digits[i : i + 2] for i in range(0, 12, 2)).upper()


async def make_router(
    router_service: RouterService,
    location_lookup: FakeLocationLookup,
    organization: Organization,
    *,
    status: RouterStatus = RouterStatus.PENDING_PROVISIONING,
) -> Router:
    location = location_lookup.add(organization_id=organization.id)
    router_device = await router_service.create_router(
        actor_user_id=uuid.uuid4(),
        location_id=location.id,
        requesting_organization_id=None,
        name="Front Desk AP",
        serial_number=f"SN-{uuid.uuid4()}",
        mac_address=_unique_mac(),
        model="hAP ac2",
    )
    if status != RouterStatus.PENDING_PROVISIONING:
        # Drive through the real transition graph via check-in/heartbeat/
        # suspend so every test exercises the actual state machine, not a
        # hand-set attribute.
        if status in (
            RouterStatus.PROVISIONING,
            RouterStatus.ONLINE,
            RouterStatus.OFFLINE,
        ):
            token, plaintext = await router_service.generate_provisioning_token(
                actor_user_id=uuid.uuid4(),
                router_id=router_device.id,
                requesting_organization_id=None,
            )
            router_device = await router_service.check_in(plaintext_token=plaintext)
            if status in (RouterStatus.ONLINE, RouterStatus.OFFLINE):
                router_device = await router_service.heartbeat(
                    router_id=router_device.id
                )
        elif status == RouterStatus.SUSPENDED:
            router_device = await router_service.suspend_router(
                actor_user_id=uuid.uuid4(),
                router_id=router_device.id,
                requesting_organization_id=None,
            )
        elif status == RouterStatus.DECOMMISSIONED:
            # Deliberately bypasses ``decommission_router`` (which also
            # soft-deletes, per BE-008's own convention) -- soft-deleting
            # here would make every subsequent
            # ``RouterLookupProtocol.get_router`` call (default
            # ``include_deleted=False``, used throughout this module)
            # raise ``RouterNotFoundError`` before ever reaching the
            # decommissioned-status check this fixture exists to exercise.
            # Mirrors ``test_router.py``'s own ``make_router`` helper, which
            # sets ``status`` directly via the fake repository for this
            # exact reason.
            router_device = await router_service.repository.update_router(
                router_device, {"status": RouterStatus.DECOMMISSIONED.value}
            )
    return router_device


# ============================================================================
# Templates
# ============================================================================


class TestConfigTemplates:
    async def test_create_system_template_when_no_org_context(self) -> None:
        service, *_ = make_services()
        template = await service.create_template(
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=None,
            name="Default AP config",
            template_content="/system identity set name={{router_name}}",
        )
        assert template.is_system_template is True
        assert template.organization_id is None

    async def test_create_org_template_when_org_context_present(self) -> None:
        service, _repo, _router_service, _router_repo, _loc, org_lookup, *_ = (
            make_services()
        )
        organization = org_lookup.add()
        template = await service.create_template(
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=organization.id,
            name="Custom config",
            template_content="/system identity set name={{router_name}}",
        )
        assert template.is_system_template is False
        assert template.organization_id == organization.id

    async def test_org_scoped_caller_cannot_access_other_orgs_template(self) -> None:
        service, _repo, _rs, _rr, _loc, org_lookup, *_ = make_services()
        org_a = org_lookup.add()
        org_b = org_lookup.add()
        template = await service.create_template(
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=org_b.id,
            name="Org B template",
            template_content="content",
        )
        with pytest.raises(CrossOrganizationTemplateAccessError):
            await service.get_template(template.id, requesting_organization_id=org_a.id)

    async def test_system_template_visible_to_any_org(self) -> None:
        service, _repo, _rs, _rr, _loc, org_lookup, *_ = make_services()
        organization = org_lookup.add()
        template = await service.create_template(
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=None,
            name="System template",
            template_content="content",
        )
        fetched = await service.get_template(
            template.id, requesting_organization_id=organization.id
        )
        assert fetched.id == template.id

    async def test_update_template_ignores_scope_fields(self) -> None:
        service, *_ = make_services()
        template = await service.create_template(
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=None,
            name="Original",
            template_content="content",
        )
        updated = await service.update_template(
            actor_user_id=uuid.uuid4(),
            template_id=template.id,
            requesting_organization_id=None,
            data={"name": "Renamed", "organization_id": uuid.uuid4()},
        )
        assert updated.name == "Renamed"
        assert updated.organization_id is None

    async def test_delete_template_deactivates_and_soft_deletes(self) -> None:
        service, *_ = make_services()
        template = await service.create_template(
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=None,
            name="Original",
            template_content="content",
        )
        deleted = await service.delete_template(
            actor_user_id=uuid.uuid4(),
            template_id=template.id,
            requesting_organization_id=None,
        )
        assert deleted.is_active is False
        assert deleted.is_deleted is True

    async def test_get_missing_template_raises(self) -> None:
        service, *_ = make_services()
        with pytest.raises(ConfigTemplateNotFoundError):
            await service.get_template(uuid.uuid4())


# ============================================================================
# Variables + resolution order
# ============================================================================


class TestConfigVariables:
    async def test_create_global_variable_requires_no_org_context(self) -> None:
        service, *_ = make_services()
        variable = await service.create_variable(
            actor_user_id=uuid.uuid4(),
            scope_type=ConfigVariableScope.ORGANIZATION,
            key="ntp_server",
            value="pool.ntp.org",
            requesting_organization_id=None,
        )
        assert variable.organization_id is None

    async def test_org_scoped_caller_cannot_create_global_variable(self) -> None:
        service, _repo, _rs, _rr, _loc, org_lookup, *_ = make_services()
        organization = org_lookup.add()
        with pytest.raises(InvalidConfigVariableScopeError):
            await service.create_variable(
                actor_user_id=uuid.uuid4(),
                scope_type=ConfigVariableScope.ORGANIZATION,
                key="ntp_server",
                value="pool.ntp.org",
                requesting_organization_id=organization.id,
            )

    async def test_cross_org_variable_creation_rejected(self) -> None:
        service, _repo, _rs, _rr, _loc, org_lookup, *_ = make_services()
        org_a = org_lookup.add()
        org_b = org_lookup.add()
        with pytest.raises(CrossOrganizationVariableAccessError):
            await service.create_variable(
                actor_user_id=uuid.uuid4(),
                scope_type=ConfigVariableScope.ORGANIZATION,
                organization_id=org_b.id,
                key="ntp_server",
                value="pool.ntp.org",
                requesting_organization_id=org_a.id,
            )

    async def test_router_scope_denormalizes_location_and_org(self) -> None:
        service, _repo, router_service, router_repo, location_lookup, org_lookup, *_ = (
            make_services()
        )
        organization = org_lookup.add()
        router_device = await make_router(router_service, location_lookup, organization)
        variable = await service.create_variable(
            actor_user_id=uuid.uuid4(),
            scope_type=ConfigVariableScope.ROUTER,
            router_id=router_device.id,
            key="wifi_ssid",
            value="Guest-WiFi",
            requesting_organization_id=None,
        )
        assert variable.location_id == router_device.location_id
        assert variable.organization_id == router_device.organization_id

    async def test_duplicate_variable_same_scope_rejected(self) -> None:
        service, *_ = make_services()
        await service.create_variable(
            actor_user_id=uuid.uuid4(),
            scope_type=ConfigVariableScope.ORGANIZATION,
            key="ntp_server",
            value="pool.ntp.org",
            requesting_organization_id=None,
        )
        with pytest.raises(DuplicateConfigVariableError):
            await service.create_variable(
                actor_user_id=uuid.uuid4(),
                scope_type=ConfigVariableScope.ORGANIZATION,
                key="ntp_server",
                value="time.google.com",
                requesting_organization_id=None,
            )

    async def test_secret_variable_encrypted_and_decryptable(self) -> None:
        service, repo, *_ = make_services()
        variable = await service.create_variable(
            actor_user_id=uuid.uuid4(),
            scope_type=ConfigVariableScope.ORGANIZATION,
            key="api_password",
            value="TopSecret!",
            is_secret=True,
            requesting_organization_id=None,
        )
        stored = repo.variables[variable.id]
        assert stored.value != "TopSecret!"
        assert decrypt_secret(stored.value) == "TopSecret!"

    async def test_resolve_variables_merge_order_most_specific_wins(self) -> None:
        (
            service,
            _repo,
            router_service,
            _router_repo,
            location_lookup,
            org_lookup,
            *_,
        ) = make_services()
        organization = org_lookup.add()
        router_device = await make_router(router_service, location_lookup, organization)

        await service.create_variable(
            actor_user_id=None,
            scope_type=ConfigVariableScope.ORGANIZATION,
            key="ntp_server",
            value="global.pool.ntp.org",
            requesting_organization_id=None,
        )
        await service.create_variable(
            actor_user_id=None,
            scope_type=ConfigVariableScope.ORGANIZATION,
            organization_id=organization.id,
            key="ntp_server",
            value="org.pool.ntp.org",
            requesting_organization_id=organization.id,
        )
        await service.create_variable(
            actor_user_id=None,
            scope_type=ConfigVariableScope.LOCATION,
            location_id=router_device.location_id,
            key="ntp_server",
            value="location.pool.ntp.org",
            requesting_organization_id=None,
        )
        await service.create_variable(
            actor_user_id=None,
            scope_type=ConfigVariableScope.ROUTER,
            router_id=router_device.id,
            key="ntp_server",
            value="router.pool.ntp.org",
            requesting_organization_id=None,
        )
        # A second key only defined at the global tier, to confirm lower
        # tiers still surface when nothing more specific overrides them.
        await service.create_variable(
            actor_user_id=None,
            scope_type=ConfigVariableScope.ORGANIZATION,
            key="dns_server",
            value="1.1.1.1",
            requesting_organization_id=None,
        )

        resolved = await service.resolve_variables(router_device)
        assert resolved["ntp_server"] == "router.pool.ntp.org"
        assert resolved["dns_server"] == "1.1.1.1"

    async def test_update_variable_value_reencrypts_when_secret(self) -> None:
        service, repo, *_ = make_services()
        variable = await service.create_variable(
            actor_user_id=uuid.uuid4(),
            scope_type=ConfigVariableScope.ORGANIZATION,
            key="api_password",
            value="First",
            is_secret=True,
            requesting_organization_id=None,
        )
        updated = await service.update_variable(
            actor_user_id=uuid.uuid4(), variable_id=variable.id, value="Second"
        )
        assert decrypt_secret(updated.value) == "Second"

    async def test_delete_variable_soft_deletes(self) -> None:
        service, *_ = make_services()
        variable = await service.create_variable(
            actor_user_id=uuid.uuid4(),
            scope_type=ConfigVariableScope.ORGANIZATION,
            key="ntp_server",
            value="pool.ntp.org",
            requesting_organization_id=None,
        )
        deleted = await service.delete_variable(
            actor_user_id=uuid.uuid4(), variable_id=variable.id
        )
        assert deleted.is_deleted is True


# ============================================================================
# Template rendering
# ============================================================================


class TestTemplateRendering:
    def test_render_substitutes_placeholders(self) -> None:
        rendered = render_template(
            "/system identity set name={{router_name}}", {"router_name": "hAP-01"}
        )
        assert rendered == "/system identity set name=hAP-01"

    def test_render_raises_on_unresolved_placeholder(self) -> None:
        with pytest.raises(UnresolvedTemplateVariablesError):
            render_template("set name={{missing_var}}", {})


# ============================================================================
# Config profile assignment + version creation
# ============================================================================


class TestConfigProfileAndVersions:
    async def test_assign_profile_creates_draft_version_one(self) -> None:
        (
            service,
            _repo,
            router_service,
            _router_repo,
            location_lookup,
            org_lookup,
            *_,
        ) = make_services()
        organization = org_lookup.add()
        router_device = await make_router(router_service, location_lookup, organization)
        template = await service.create_template(
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=None,
            name="Basic",
            template_content="/system identity set name={{router_name}}",
        )
        await service.create_variable(
            actor_user_id=None,
            scope_type=ConfigVariableScope.ROUTER,
            router_id=router_device.id,
            key="router_name",
            value="hAP-01",
            requesting_organization_id=None,
        )

        profile, version = await service.assign_profile(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            template_id=template.id,
            requesting_organization_id=None,
        )
        assert profile.template_id == template.id
        assert version.version_number == 1
        assert version.status == ConfigVersionStatus.DRAFT.value
        assert version.rendered_content == "/system identity set name=hAP-01"

    async def test_assign_profile_requires_all_placeholders_resolved(self) -> None:
        (
            service,
            _repo,
            router_service,
            _router_repo,
            location_lookup,
            org_lookup,
            *_,
        ) = make_services()
        organization = org_lookup.add()
        router_device = await make_router(router_service, location_lookup, organization)
        template = await service.create_template(
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=None,
            name="Broken",
            template_content="set name={{unresolvable}}",
        )
        with pytest.raises(UnresolvedTemplateVariablesError):
            await service.assign_profile(
                actor_user_id=uuid.uuid4(),
                router_id=router_device.id,
                template_id=template.id,
                requesting_organization_id=None,
            )

    async def test_assign_profile_on_decommissioned_router_raises(self) -> None:
        (
            service,
            _repo,
            router_service,
            _router_repo,
            location_lookup,
            org_lookup,
            *_,
        ) = make_services()
        organization = org_lookup.add()
        router_device = await make_router(
            router_service,
            location_lookup,
            organization,
            status=RouterStatus.DECOMMISSIONED,
        )
        template = await service.create_template(
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=None,
            name="Basic",
            template_content="no placeholders",
        )
        with pytest.raises(RouterNotEligibleForConfigError):
            await service.assign_profile(
                actor_user_id=uuid.uuid4(),
                router_id=router_device.id,
                template_id=template.id,
                requesting_organization_id=None,
            )

    async def _setup_draft_version(
        self, *, router_status: RouterStatus = RouterStatus.ONLINE
    ):
        (
            service,
            repo,
            router_service,
            router_repo,
            location_lookup,
            org_lookup,
            queue_dispatcher,
            audit,
        ) = make_services()
        organization = org_lookup.add()
        router_device = await make_router(
            router_service, location_lookup, organization, status=router_status
        )
        template = await service.create_template(
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=None,
            name="Basic",
            template_content="no placeholders here",
        )
        _profile, version = await service.assign_profile(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            template_id=template.id,
            requesting_organization_id=None,
        )
        return service, repo, router_device, version, queue_dispatcher, audit

    async def test_apply_version_transitions_to_pending_apply_and_enqueues(
        self,
    ) -> None:
        (
            service,
            repo,
            router_device,
            version,
            queue_dispatcher,
            _audit,
        ) = await self._setup_draft_version()
        updated_version, job = await service.apply_version(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            version_id=version.id,
            requesting_organization_id=None,
        )
        assert updated_version.status == ConfigVersionStatus.PENDING_APPLY.value
        assert job.status == ProvisioningJobStatus.QUEUED.value
        assert job.job_type == ProvisioningJobType.INITIAL_CONFIG.value
        assert job.id in queue_dispatcher.enqueued

    async def test_apply_on_non_draft_version_raises(self) -> None:
        (
            service,
            repo,
            router_device,
            version,
            _qd,
            _audit,
        ) = await self._setup_draft_version()
        await service.apply_version(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            version_id=version.id,
            requesting_organization_id=None,
        )
        with pytest.raises(InvalidConfigVersionStatusTransitionError):
            await service.apply_version(
                actor_user_id=uuid.uuid4(),
                router_id=router_device.id,
                version_id=version.id,
                requesting_organization_id=None,
            )

    async def test_complete_job_success_applies_version(self) -> None:
        (
            service,
            repo,
            router_device,
            version,
            _qd,
            audit,
        ) = await self._setup_draft_version()
        _updated, job = await service.apply_version(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            version_id=version.id,
            requesting_organization_id=None,
        )
        await service.start_provisioning_job(job.id)
        completed_job = await service.complete_provisioning_job(job.id, success=True)

        assert completed_job.status == ProvisioningJobStatus.SUCCEEDED.value
        applied_version = repo.versions[version.id]
        assert applied_version.status == ConfigVersionStatus.APPLIED.value
        assert applied_version.applied_at is not None
        assert any(
            e["action"] == "router_config_version_applied" for e in audit.entries
        )

    async def test_complete_job_failure_marks_version_failed(self) -> None:
        (
            service,
            repo,
            router_device,
            version,
            _qd,
            _audit,
        ) = await self._setup_draft_version()
        _updated, job = await service.apply_version(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            version_id=version.id,
            requesting_organization_id=None,
        )
        await service.start_provisioning_job(job.id)
        await service.complete_provisioning_job(
            job.id, success=False, error_message="device unreachable"
        )
        failed_version = repo.versions[version.id]
        assert failed_version.status == ConfigVersionStatus.FAILED.value

    async def test_second_version_is_config_push_not_initial(self) -> None:
        (
            service,
            repo,
            router_device,
            version,
            _qd,
            _audit,
        ) = await self._setup_draft_version()
        _updated, job = await service.apply_version(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            version_id=version.id,
            requesting_organization_id=None,
        )
        await service.start_provisioning_job(job.id)
        await service.complete_provisioning_job(job.id, success=True)

        template = await service.create_template(
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=None,
            name="Second",
            template_content="v2 content",
        )
        _profile, version_2 = await service.assign_profile(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            template_id=template.id,
            requesting_organization_id=None,
        )
        assert version_2.version_number == 2
        _updated_2, job_2 = await service.apply_version(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            version_id=version_2.id,
            requesting_organization_id=None,
        )
        assert job_2.job_type == ProvisioningJobType.CONFIG_PUSH.value

    async def test_rollback_creates_new_draft_tagged_with_target(self) -> None:
        (
            service,
            repo,
            router_device,
            version,
            _qd,
            _audit,
        ) = await self._setup_draft_version()
        _updated, job = await service.apply_version(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            version_id=version.id,
            requesting_organization_id=None,
        )
        await service.start_provisioning_job(job.id)
        await service.complete_provisioning_job(job.id, success=True)

        rollback_version = await service.rollback_to_version(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            target_version_id=version.id,
            requesting_organization_id=None,
        )
        assert rollback_version.status == ConfigVersionStatus.DRAFT.value
        assert rollback_version.rollback_of_version_id == version.id
        assert rollback_version.rendered_content == version.rendered_content
        assert rollback_version.version_number == 2

    async def test_applying_rollback_marks_previous_version_rolled_back(self) -> None:
        (
            service,
            repo,
            router_device,
            version,
            _qd,
            audit,
        ) = await self._setup_draft_version()
        _updated, job = await service.apply_version(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            version_id=version.id,
            requesting_organization_id=None,
        )
        await service.start_provisioning_job(job.id)
        await service.complete_provisioning_job(job.id, success=True)

        rollback_version = await service.rollback_to_version(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            target_version_id=version.id,
            requesting_organization_id=None,
        )
        _updated_rb, rollback_job = await service.apply_version(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            version_id=rollback_version.id,
            requesting_organization_id=None,
        )
        await service.start_provisioning_job(rollback_job.id)
        await service.complete_provisioning_job(rollback_job.id, success=True)

        original = repo.versions[version.id]
        assert original.status == ConfigVersionStatus.ROLLED_BACK.value
        assert any(
            e["action"] == "router_config_version_rolled_back" for e in audit.entries
        )

    async def test_rollback_to_version_from_different_router_raises(self) -> None:
        (
            service,
            repo,
            router_service,
            _router_repo,
            location_lookup,
            org_lookup,
            *_,
        ) = make_services()
        organization = org_lookup.add()
        router_a = await make_router(router_service, location_lookup, organization)
        router_b = await make_router(router_service, location_lookup, organization)
        template = await service.create_template(
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=None,
            name="Basic",
            template_content="content",
        )
        _profile, version_a = await service.assign_profile(
            actor_user_id=uuid.uuid4(),
            router_id=router_a.id,
            template_id=template.id,
            requesting_organization_id=None,
        )
        with pytest.raises(ConfigVersionRouterMismatchError):
            await service.rollback_to_version(
                actor_user_id=uuid.uuid4(),
                router_id=router_b.id,
                target_version_id=version_a.id,
                requesting_organization_id=None,
            )

    async def test_diff_versions_reports_line_changes(self) -> None:
        (
            service,
            _repo,
            router_service,
            _router_repo,
            location_lookup,
            org_lookup,
            *_,
        ) = make_services()
        organization = org_lookup.add()
        router_device = await make_router(router_service, location_lookup, organization)
        template_v1 = await service.create_template(
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=None,
            name="V1",
            template_content="line one\nline two",
        )
        _profile, version_1 = await service.assign_profile(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            template_id=template_v1.id,
            requesting_organization_id=None,
        )
        template_v2 = await service.create_template(
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=None,
            name="V2",
            template_content="line one\nline three",
        )
        _profile2, version_2 = await service.assign_profile(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            template_id=template_v2.id,
            requesting_organization_id=None,
        )
        _v1, _v2, diff_lines = await service.diff_versions(
            router_id=router_device.id,
            version_id=version_1.id,
            other_version_id=version_2.id,
            requesting_organization_id=None,
        )
        assert any("line two" in line for line in diff_lines)
        assert any("line three" in line for line in diff_lines)


# ============================================================================
# Backup / restore
# ============================================================================


class TestBackupRestore:
    async def test_create_backup_without_applied_config_raises(self) -> None:
        (
            service,
            _repo,
            router_service,
            _router_repo,
            location_lookup,
            org_lookup,
            *_,
        ) = make_services()
        organization = org_lookup.add()
        router_device = await make_router(router_service, location_lookup, organization)
        with pytest.raises(NoAppliedConfigToBackupError):
            await service.create_backup(
                actor_user_id=uuid.uuid4(),
                router_id=router_device.id,
                requesting_organization_id=None,
            )

    async def _apply_first_version(self, service, router_device):
        template = await service.create_template(
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=None,
            name="Basic",
            template_content="applied content v1",
        )
        _profile, version = await service.assign_profile(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            template_id=template.id,
            requesting_organization_id=None,
        )
        _updated, job = await service.apply_version(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            version_id=version.id,
            requesting_organization_id=None,
        )
        await service.start_provisioning_job(job.id)
        await service.complete_provisioning_job(job.id, success=True)
        return version

    async def test_create_backup_enqueues_job_and_completion_creates_backup_version(
        self,
    ) -> None:
        (
            service,
            repo,
            router_service,
            _router_repo,
            location_lookup,
            org_lookup,
            queue_dispatcher,
            audit,
        ) = make_services()
        organization = org_lookup.add()
        router_device = await make_router(
            router_service, location_lookup, organization, status=RouterStatus.ONLINE
        )
        await self._apply_first_version(service, router_device)

        job = await service.create_backup(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )
        assert job.job_type == ProvisioningJobType.BACKUP.value
        assert job.id in queue_dispatcher.enqueued

        await service.start_provisioning_job(job.id)
        await service.complete_provisioning_job(job.id, success=True)

        backup_versions = [v for v in repo.versions.values() if v.is_backup]
        assert len(backup_versions) == 1
        assert backup_versions[0].status == ConfigVersionStatus.APPLIED.value
        assert any(e["action"] == "router_backup_created" for e in audit.entries)

    async def test_restore_requires_a_backup_tagged_version(self) -> None:
        (
            service,
            repo,
            router_service,
            _router_repo,
            location_lookup,
            org_lookup,
            *_,
        ) = make_services()
        organization = org_lookup.add()
        router_device = await make_router(
            router_service, location_lookup, organization, status=RouterStatus.ONLINE
        )
        version = await self._apply_first_version(service, router_device)

        with pytest.raises(BackupVersionExpectedError):
            await service.restore_backup(
                actor_user_id=uuid.uuid4(),
                router_id=router_device.id,
                backup_version_id=version.id,
                requesting_organization_id=None,
            )

    async def test_restore_completion_creates_new_applied_version(self) -> None:
        (
            service,
            repo,
            router_service,
            _router_repo,
            location_lookup,
            org_lookup,
            *_,
        ) = make_services()
        organization = org_lookup.add()
        router_device = await make_router(
            router_service, location_lookup, organization, status=RouterStatus.ONLINE
        )
        await self._apply_first_version(service, router_device)

        backup_job = await service.create_backup(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )
        await service.start_provisioning_job(backup_job.id)
        await service.complete_provisioning_job(backup_job.id, success=True)
        backup_version = next(v for v in repo.versions.values() if v.is_backup)

        restore_job = await service.restore_backup(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            backup_version_id=backup_version.id,
            requesting_organization_id=None,
        )
        assert restore_job.job_type == ProvisioningJobType.RESTORE.value
        await service.start_provisioning_job(restore_job.id)
        await service.complete_provisioning_job(restore_job.id, success=True)

        current = await repo.get_latest_applied_version(router_device.id)
        assert current is not None
        assert current.rollback_of_version_id == backup_version.id


# ============================================================================
# Factory reset
# ============================================================================


class TestFactoryReset:
    async def test_factory_reset_rejected_for_pending_provisioning_router(self) -> None:
        (
            service,
            _repo,
            router_service,
            _router_repo,
            location_lookup,
            org_lookup,
            *_,
        ) = make_services()
        organization = org_lookup.add()
        router_device = await make_router(router_service, location_lookup, organization)
        with pytest.raises(RouterNotEligibleForFactoryResetError):
            await service.factory_reset(
                actor_user_id=uuid.uuid4(),
                router_id=router_device.id,
                requesting_organization_id=None,
            )

    async def test_factory_reset_queues_job_for_online_router(self) -> None:
        (
            service,
            _repo,
            router_service,
            _router_repo,
            location_lookup,
            org_lookup,
            queue_dispatcher,
            _audit,
        ) = make_services()
        organization = org_lookup.add()
        router_device = await make_router(
            router_service, location_lookup, organization, status=RouterStatus.ONLINE
        )
        job = await service.factory_reset(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )
        assert job.job_type == ProvisioningJobType.FACTORY_RESET.value
        assert job.id in queue_dispatcher.enqueued

    async def test_factory_reset_completion_resets_router_status(self) -> None:
        (
            service,
            repo,
            router_service,
            router_repo,
            location_lookup,
            org_lookup,
            _qd,
            audit,
        ) = make_services()
        organization = org_lookup.add()
        router_device = await make_router(
            router_service, location_lookup, organization, status=RouterStatus.ONLINE
        )
        job = await service.factory_reset(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )
        await service.start_provisioning_job(job.id)
        await service.complete_provisioning_job(job.id, success=True)

        reset_router = router_repo.routers[router_device.id]
        assert reset_router.status == RouterStatus.PENDING_PROVISIONING.value
        # BE-008's own RouterService._set_status already writes the
        # audit_log_entries row for this transition -- confirm it did, and
        # that this module did not write a second, duplicate one.
        factory_reset_entries = [
            e for e in audit.entries if e["action"] == "router_factory_reset"
        ]
        assert len(factory_reset_entries) == 1


# ============================================================================
# Secret rotation
# ============================================================================


class TestSecretRotation:
    async def test_rotate_secret_returns_new_plaintext_and_encrypts_via_be008_crypto(
        self,
    ) -> None:
        (
            service,
            _repo,
            router_service,
            router_repo,
            location_lookup,
            org_lookup,
            _qd,
            audit,
        ) = make_services()
        organization = org_lookup.add()
        router_device = await make_router(router_service, location_lookup, organization)

        updated_router, new_secret = await service.rotate_secret(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )
        assert len(new_secret) > 10
        assert updated_router.api_credentials_encrypted != new_secret
        # Decryptable via the exact same BE-008 helper, confirming reuse
        # rather than a second encryption mechanism.
        assert (
            router_service.get_decrypted_api_secret(
                router_repo.routers[router_device.id]
            )
            == new_secret
        )
        assert any(e["action"] == "router_secret_rotated" for e in audit.entries)

    async def test_rotate_secret_on_decommissioned_router_raises(self) -> None:
        (
            service,
            _repo,
            router_service,
            _router_repo,
            location_lookup,
            org_lookup,
            *_,
        ) = make_services()
        organization = org_lookup.add()
        router_device = await make_router(
            router_service,
            location_lookup,
            organization,
            status=RouterStatus.DECOMMISSIONED,
        )
        with pytest.raises(RouterDecommissionedError):
            await service.rotate_secret(
                actor_user_id=uuid.uuid4(),
                router_id=router_device.id,
                requesting_organization_id=None,
            )


# ============================================================================
# Device-initiated enrollment
# ============================================================================


class TestEnrollment:
    async def test_submit_enrollment_creates_pending_request(self) -> None:
        service, *_ = make_services()
        enrollment = await service.submit_enrollment(
            serial_number="HB31090ABCD",
            mac_address="aa:bb:cc:dd:ee:ff",
            model="hAP ac2",
        )
        assert enrollment.status == "pending"
        assert enrollment.mac_address == "AA:BB:CC:DD:EE:FF"

    async def test_submit_enrollment_rejects_existing_active_router_serial(
        self,
    ) -> None:
        (
            service,
            _repo,
            router_service,
            _router_repo,
            location_lookup,
            org_lookup,
            *_,
        ) = make_services()
        organization = org_lookup.add()
        router_device = await make_router(router_service, location_lookup, organization)
        with pytest.raises(RouterAlreadyRegisteredError):
            await service.submit_enrollment(
                serial_number=router_device.serial_number,
                mac_address="11:22:33:44:55:66",
                model="hAP ac2",
            )

    async def test_submit_duplicate_pending_enrollment_rejected(self) -> None:
        service, *_ = make_services()
        await service.submit_enrollment(
            serial_number="SN-123", mac_address="AA:BB:CC:DD:EE:FF", model="hAP ac2"
        )
        with pytest.raises(DuplicatePendingEnrollmentError):
            await service.submit_enrollment(
                serial_number="SN-123", mac_address="11:22:33:44:55:66", model="hAP ac2"
            )

    async def test_approve_enrollment_creates_router_pending_provisioning(self) -> None:
        (
            service,
            _repo,
            _router_service,
            router_repo,
            location_lookup,
            org_lookup,
            _qd,
            audit,
        ) = make_services()
        organization = org_lookup.add()
        location = location_lookup.add(organization_id=organization.id)
        enrollment = await service.submit_enrollment(
            serial_number="SN-456", mac_address="AA:BB:CC:DD:EE:FF", model="hAP ac2"
        )
        updated_enrollment, router_device = await service.approve_enrollment(
            actor_user_id=uuid.uuid4(),
            enrollment_id=enrollment.id,
            requesting_organization_id=None,
            location_id=location.id,
            name="New Front Desk AP",
        )
        assert updated_enrollment.status == "approved"
        assert updated_enrollment.approved_router_id == router_device.id
        assert router_device.status == RouterStatus.PENDING_PROVISIONING.value
        assert router_repo.routers[router_device.id].serial_number == "SN-456"
        assert any(e["action"] == "router_enrollment_approved" for e in audit.entries)

    async def test_approve_enrollment_race_condition_conflict(self) -> None:
        """Another registration claims the same serial number between
        submission and approval -- approval must reject, not silently
        create a duplicate Router."""
        (
            service,
            _repo,
            router_service,
            _router_repo,
            location_lookup,
            org_lookup,
            *_,
        ) = make_services()
        organization = org_lookup.add()
        location = location_lookup.add(organization_id=organization.id)
        enrollment = await service.submit_enrollment(
            serial_number="SN-RACE", mac_address="AA:BB:CC:DD:EE:FF", model="hAP ac2"
        )
        # A directly-registered router claims the same serial number before
        # the enrollment is approved.
        await router_service.create_router(
            actor_user_id=uuid.uuid4(),
            location_id=location.id,
            requesting_organization_id=None,
            name="Directly registered",
            serial_number="SN-RACE",
            mac_address="11:22:33:44:55:66",
            model="hAP ac2",
        )
        with pytest.raises(RouterAlreadyRegisteredError):
            await service.approve_enrollment(
                actor_user_id=uuid.uuid4(),
                enrollment_id=enrollment.id,
                requesting_organization_id=None,
                location_id=location.id,
                name="New Front Desk AP",
            )

    async def test_approve_already_approved_enrollment_raises(self) -> None:
        (
            service,
            _repo,
            _router_service,
            _router_repo,
            location_lookup,
            org_lookup,
            *_,
        ) = make_services()
        organization = org_lookup.add()
        location = location_lookup.add(organization_id=organization.id)
        enrollment = await service.submit_enrollment(
            serial_number="SN-789", mac_address="AA:BB:CC:DD:EE:FF", model="hAP ac2"
        )
        await service.approve_enrollment(
            actor_user_id=uuid.uuid4(),
            enrollment_id=enrollment.id,
            requesting_organization_id=None,
            location_id=location.id,
            name="AP",
        )
        with pytest.raises(RouterEnrollmentNotPendingError):
            await service.approve_enrollment(
                actor_user_id=uuid.uuid4(),
                enrollment_id=enrollment.id,
                requesting_organization_id=None,
                location_id=location.id,
                name="AP",
            )

    async def test_reject_enrollment_records_reason(self) -> None:
        service, *_ = make_services()
        enrollment = await service.submit_enrollment(
            serial_number="SN-999", mac_address="AA:BB:CC:DD:EE:FF", model="hAP ac2"
        )
        rejected = await service.reject_enrollment(
            actor_user_id=uuid.uuid4(),
            enrollment_id=enrollment.id,
            rejection_reason="Unknown device",
        )
        assert rejected.status == "rejected"
        assert rejected.rejection_reason == "Unknown device"

    async def test_list_pending_enrollments_excludes_reviewed(self) -> None:
        service, *_ = make_services()
        await service.submit_enrollment(
            serial_number="SN-A", mac_address="AA:AA:AA:AA:AA:AA", model="hAP ac2"
        )
        pending_b = await service.submit_enrollment(
            serial_number="SN-B", mac_address="BB:BB:BB:BB:BB:BB", model="hAP ac2"
        )
        await service.reject_enrollment(
            actor_user_id=uuid.uuid4(),
            enrollment_id=pending_b.id,
            rejection_reason="no",
        )
        enrollments, meta = await service.list_pending_enrollments()
        assert meta.total_items == 1
        assert enrollments[0].serial_number == "SN-A"


# ============================================================================
# Provisioning queue job lifecycle
# ============================================================================


class TestProvisioningJobLifecycle:
    async def test_job_lifecycle_queued_running_succeeded(self) -> None:
        (
            service,
            repo,
            router_service,
            _router_repo,
            location_lookup,
            org_lookup,
            queue_dispatcher,
            _audit,
        ) = make_services()
        organization = org_lookup.add()
        router_device = await make_router(
            router_service, location_lookup, organization, status=RouterStatus.ONLINE
        )
        job = await service.factory_reset(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )
        assert job.status == ProvisioningJobStatus.QUEUED.value
        assert job.attempts == 0

        started = await service.start_provisioning_job(job.id)
        assert started.status == ProvisioningJobStatus.RUNNING.value
        assert started.attempts == 1

        completed = await service.complete_provisioning_job(job.id, success=True)
        assert completed.status == ProvisioningJobStatus.SUCCEEDED.value
        assert completed.completed_at is not None

    async def test_job_cannot_complete_without_starting(self) -> None:
        (
            service,
            _repo,
            router_service,
            _router_repo,
            location_lookup,
            org_lookup,
            *_,
        ) = make_services()
        organization = org_lookup.add()
        router_device = await make_router(
            router_service, location_lookup, organization, status=RouterStatus.ONLINE
        )
        job = await service.factory_reset(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )

        with pytest.raises(InvalidProvisioningJobStatusTransitionError):
            await service.complete_provisioning_job(job.id, success=True)

    async def test_provisioning_status_reports_active_jobs_and_latest_version(
        self,
    ) -> None:
        (
            service,
            repo,
            router_service,
            _router_repo,
            location_lookup,
            org_lookup,
            *_,
        ) = make_services()
        organization = org_lookup.add()
        router_device = await make_router(
            router_service, location_lookup, organization, status=RouterStatus.ONLINE
        )
        template = await service.create_template(
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=None,
            name="Basic",
            template_content="content",
        )
        _profile, version = await service.assign_profile(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            template_id=template.id,
            requesting_organization_id=None,
        )
        _updated, job = await service.apply_version(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            version_id=version.id,
            requesting_organization_id=None,
        )

        result = await service.get_provisioning_status(
            router_id=router_device.id, requesting_organization_id=None
        )
        assert result.router.id == router_device.id
        assert result.latest_version.id == version.id
        assert any(j.id == job.id for j in result.active_jobs)


# ============================================================================
# Tenant isolation
# ============================================================================


class TestTenantIsolation:
    async def test_org_scoped_caller_cannot_reach_other_orgs_router(self) -> None:
        (
            service,
            _repo,
            router_service,
            _router_repo,
            location_lookup,
            org_lookup,
            *_,
        ) = make_services()
        org_a = org_lookup.add()
        org_b = org_lookup.add()
        router_device = await make_router(router_service, location_lookup, org_b)

        with pytest.raises(CrossOrganizationRouterAccessError):
            await service.get_provisioning_status(
                router_id=router_device.id, requesting_organization_id=org_a.id
            )

    async def test_org_scoped_caller_cannot_rotate_secret_outside_scope(self) -> None:
        (
            service,
            _repo,
            router_service,
            _router_repo,
            location_lookup,
            org_lookup,
            *_,
        ) = make_services()
        org_a = org_lookup.add()
        org_b = org_lookup.add()
        router_device = await make_router(router_service, location_lookup, org_b)

        with pytest.raises(CrossOrganizationRouterAccessError):
            await service.rotate_secret(
                actor_user_id=uuid.uuid4(),
                router_id=router_device.id,
                requesting_organization_id=org_a.id,
            )

    async def test_provisioning_job_router_mismatch_validator(self) -> None:
        (
            service,
            repo,
            router_service,
            _router_repo,
            location_lookup,
            org_lookup,
            *_,
        ) = make_services()
        organization = org_lookup.add()
        router_a = await make_router(router_service, location_lookup, organization)
        router_b = await make_router(router_service, location_lookup, organization)
        job = await repo.create_job(
            router_id=router_a.id,
            job_type=ProvisioningJobType.FACTORY_RESET.value,
            status=ProvisioningJobStatus.QUEUED.value,
            payload={},
            attempts=0,
            max_attempts=3,
            scheduled_at=_now(),
            started_at=None,
            completed_at=None,
            error_message=None,
            requested_by_user_id=None,
        )
        with pytest.raises(ProvisioningJobRouterMismatchError):
            validate_job_belongs_to_router(job, router_b.id)
